package idp

import (
	"errors"
	"net/http"
	"time"

	"github.com/crewjam/saml"

	"github.com/kc9wwh/symbiont-sso/internal/config"
)

// AuthnRequest is a validated SP-initiated authentication request.
type AuthnRequest struct {
	// SP is the requesting service provider.
	SP *config.ServiceProvider
	// RelayState is the opaque value to echo back to the SP.
	RelayState string
	// RawXML is the decoded AuthnRequest, kept so the request can be
	// replayed after the upstream OIDC login.
	RawXML []byte
	// ReceivedAt is when the request was first received; validity
	// (IssueInstant freshness) is judged at this time.
	ReceivedAt time.Time
	// Replayed is set by the HTTP layer when this request is the bridge's
	// own replay after an upstream login (verified via a signed token).
	Replayed bool
	// IDPInitiated marks an unsolicited (IdP-initiated) response.
	IDPInitiated bool

	req *saml.IdpAuthnRequest
}

// ID is the AuthnRequest ID (echoed as InResponseTo).
func (a *AuthnRequest) ID() string { return a.req.Request.ID }

// ACSURL is the resolved Assertion Consumer Service URL.
func (a *AuthnRequest) ACSURL() string { return a.req.ACSEndpoint.Location }

// ForceAuthn reports whether the SP demanded fresh authentication.
func (a *AuthnRequest) ForceAuthn() bool {
	return a.req.Request.ForceAuthn != nil && *a.req.Request.ForceAuthn
}

// ParseRequest decodes and validates an SP-initiated request received via
// the HTTP-Redirect (GET) or HTTP-POST binding. For POST, r.Body must
// already be limited (http.MaxBytesReader). All failures are *RequestError.
func (p *IdP) ParseRequest(r *http.Request) (*AuthnRequest, error) {
	xmlBuf, relayState, err := DecodeRequest(r)
	if err != nil {
		return nil, err
	}
	return p.ParseXML(r, xmlBuf, relayState, p.now())
}

// Now returns the IdP's current time (used to stamp ReceivedAt).
func (p *IdP) Now() time.Time { return p.now() }

// ParseXML validates a decoded AuthnRequest as if received at receivedAt.
// It is used directly when replaying a stored request after OIDC login.
func (p *IdP) ParseXML(r *http.Request, xmlBuf []byte, relayState string, receivedAt time.Time) (*AuthnRequest, error) {
	if len(xmlBuf) > MaxRequestBytes {
		return nil, errorf(CategoryTooLarge, "", "AuthnRequest exceeds %d bytes", MaxRequestBytes)
	}
	if !ValidRelayState(relayState) {
		return nil, errorf(CategoryRelayState, "", "RelayState must be at most %d bytes of printable ASCII", MaxRelayStateBytes)
	}
	ar, err := p.preflight(xmlBuf)
	if err != nil {
		return nil, err
	}
	sp, _ := p.sps.ByEntityID(ar.Issuer.Value) // preflight guarantees presence

	req := &saml.IdpAuthnRequest{
		IDP:           p.crew,
		HTTPRequest:   r,
		RequestBuffer: xmlBuf,
		RelayState:    relayState,
		Now:           receivedAt,
	}
	// crewjam checks: XML round-trip safety, version, IssueInstant
	// freshness, Destination, SP lookup, and that the ACS is listed.
	if err := req.Validate(); err != nil {
		return nil, &RequestError{Category: CategoryInvalid, EntityID: sp.EntityID, Err: err}
	}
	if req.ACSEndpoint == nil || req.ACSEndpoint.Binding != saml.HTTPPostBinding {
		return nil, errorf(CategoryACSNotAllowed, sp.EntityID, "no HTTP-POST assertion consumer service resolved")
	}
	return &AuthnRequest{
		SP:         sp,
		RelayState: relayState,
		RawXML:     xmlBuf,
		ReceivedAt: receivedAt,
		req:        req,
	}, nil
}

// PostForm is the HTTP-POST binding payload to deliver to the SP.
type PostForm struct {
	// Action is the ACS URL the form must be posted to.
	Action       string
	SAMLResponse string
	RelayState   string
}

// IdPInitiated builds an unsolicited request for sp. It is addressed to
// sp.IDPInitiatedACSURL explicitly (crewjam's ServeIDPInitiated would pick
// the first POST ACS in metadata, and runs its session hook before the SP
// lookup). The response carries no InResponseTo.
func (p *IdP) IdPInitiated(r *http.Request, sp *config.ServiceProvider, relayState string) (*AuthnRequest, error) {
	if !sp.IDPInitiatedEnabled || sp.IDPInitiatedACSURL == "" {
		return nil, errorf(CategoryInvalid, sp.EntityID, "IdP-initiated login is disabled for %q", sp.ID)
	}
	if !ValidRelayState(relayState) {
		return nil, errorf(CategoryRelayState, sp.EntityID, "RelayState must be at most %d bytes of printable ASCII", MaxRelayStateBytes)
	}
	md, err := p.sps.GetServiceProvider(r, sp.EntityID)
	if err != nil {
		return nil, errorf(CategoryUnknownSP, sp.EntityID, "service provider %q has no metadata", sp.ID)
	}
	var acs *saml.IndexedEndpoint
	for i, e := range md.SPSSODescriptors[0].AssertionConsumerServices {
		if e.Location == sp.IDPInitiatedACSURL && e.Binding == saml.HTTPPostBinding {
			acs = &md.SPSSODescriptors[0].AssertionConsumerServices[i]
			break
		}
	}
	if acs == nil {
		return nil, errorf(CategoryACSNotAllowed, sp.EntityID, "idp_initiated.acs_url is not an HTTP-POST ACS of %q", sp.ID)
	}
	now := p.now()
	return &AuthnRequest{
		SP:           sp,
		RelayState:   relayState,
		ReceivedAt:   now,
		IDPInitiated: true,
		req: &saml.IdpAuthnRequest{
			IDP:                     p.crew,
			HTTPRequest:             r,
			RelayState:              relayState,
			Now:                     now,
			ServiceProviderMetadata: md,
			SPSSODescriptor:         &md.SPSSODescriptors[0],
			ACSEndpoint:             acs,
		},
	}, nil
}

// Respond issues a signed Response (with a signed Assertion) for id to the
// request's service provider, carrying email, name, and attrs. attrs must
// come from the access decision for a.SP; Respond does no authorization.
func (p *IdP) Respond(a *AuthnRequest, id *Identity, attrs []Attribute) (*PostForm, error) {
	if a == nil || a.req == nil {
		return nil, errors.New("idp: nil request")
	}
	// Validity was judged at ReceivedAt; the assertion itself is timed now.
	a.req.Now = p.now()
	a.req.Assertion, a.req.AssertionEl, a.req.ResponseEl = nil, nil, nil
	if err := p.maker.Make(a.req, a.SP, id, attrs); err != nil {
		return nil, err
	}
	form, err := a.req.PostBinding()
	if err != nil {
		return nil, err
	}
	return &PostForm{Action: form.URL, SAMLResponse: form.SAMLResponse, RelayState: form.RelayState}, nil
}
