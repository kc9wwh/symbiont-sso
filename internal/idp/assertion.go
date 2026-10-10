package idp

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/crewjam/saml"

	"github.com/kc9wwh/symbiont-sso/internal/config"
)

// SAML constants used in assertions.
const (
	AttrNameFormatUnspecified = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
	AttrValueTypeString       = "xs:string"
	AttrEmail                 = "email"
	AttrName                  = "name"
	authnContextClassUnspec   = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
	nameIDFormatEntity        = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
	subjectConfirmationBearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer" //nolint:gosec // G101: SAML URN ("bearer"), not a credential
)

// Identity is the authenticated user an assertion is issued for. It carries
// identity only; access and attribute decisions are made per service
// provider at issue time.
type Identity struct {
	// SessionID is the bridge session ID (used as SAML SessionIndex).
	SessionID string
	Subject   string
	Email     string
	Name      string
	Groups    []string
	// Claims holds additional OIDC claims needed by claim rules and
	// passthrough attributes.
	Claims   map[string]any
	AuthTime time.Time
}

// Attribute is a single-valued SAML attribute to add to an assertion.
type Attribute struct {
	Name  string
	Value string
}

// ErrNoEmail is returned when an identity has no email to use as NameID.
var ErrNoEmail = errors.New("identity has no email address")

// AssertionMaker builds Fleet-compatible assertions, replacing crewjam's
// DefaultAssertionMaker (transient NameID, OID-named attributes, client IP
// in SubjectConfirmationData). It performs no authorization or mapping:
// callers pass the attributes already decided for the target SP.
type AssertionMaker struct {
	SPs *ServiceProviders
}

var _ saml.AssertionMaker = (*AssertionMaker)(nil)

// Make builds req.Assertion for id, addressed to sp only, carrying email,
// name, and mapped.
func (m *AssertionMaker) Make(req *saml.IdpAuthnRequest, sp *config.ServiceProvider, id *Identity, mapped []Attribute) error {
	if id == nil || id.Email == "" {
		return ErrNoEmail
	}
	if req.ACSEndpoint == nil {
		return errors.New("request has no resolved ACS endpoint")
	}

	attrs := make([]saml.Attribute, 0, 2+len(mapped))
	attrs = append(attrs, stringAttribute(AttrEmail, id.Email))
	if id.Name != "" {
		attrs = append(attrs, stringAttribute(AttrName, id.Name))
	}
	for _, a := range mapped {
		if a.Name == AttrEmail || a.Name == AttrName {
			return fmt.Errorf("attribute source produced reserved attribute %q", a.Name)
		}
		attrs = append(attrs, stringAttribute(a.Name, a.Value))
	}

	// Timing uses crewjam's package defaults (read, never assigned):
	// NotBefore = now - MaxClockSkew (180s), NotOnOrAfter = now +
	// MaxIssueDelay (90s). Unlike crewjam's DefaultAssertionMaker we do NOT
	// anchor the window to the AuthnRequest's IssueInstant: replayed requests
	// (after the upstream login) may be minutes old, which would yield an
	// already-expired assertion.
	now := req.Now
	notOnOrAfter := now.Add(saml.MaxIssueDelay)
	authnInstant := id.AuthTime
	if authnInstant.IsZero() {
		authnInstant = now
	}

	req.Assertion = &saml.Assertion{
		ID:           newID(),
		IssueInstant: now,
		Version:      "2.0",
		Issuer:       saml.Issuer{Format: nameIDFormatEntity, Value: req.IDP.MetadataURL.String()},
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Format: string(saml.EmailAddressNameIDFormat),
				Value:  id.Email,
			},
			SubjectConfirmations: []saml.SubjectConfirmation{{
				Method: subjectConfirmationBearer,
				SubjectConfirmationData: &saml.SubjectConfirmationData{
					InResponseTo: req.Request.ID, // empty for IdP-initiated
					NotOnOrAfter: notOnOrAfter,
					Recipient:    req.ACSEndpoint.Location,
				},
			}},
		},
		Conditions: &saml.Conditions{
			NotBefore:    now.Add(-saml.MaxClockSkew),
			NotOnOrAfter: notOnOrAfter,
			AudienceRestrictions: []saml.AudienceRestriction{{
				Audience: saml.Audience{Value: sp.EntityID},
			}},
		},
		AuthnStatements: []saml.AuthnStatement{{
			AuthnInstant: authnInstant,
			SessionIndex: id.SessionID,
			AuthnContext: saml.AuthnContext{
				AuthnContextClassRef: &saml.AuthnContextClassRef{Value: authnContextClassUnspec},
			},
		}},
		AttributeStatements: []saml.AttributeStatement{{Attributes: attrs}},
	}
	return nil
}

// ErrNotSupported is returned by MakeAssertion: crewjam's own SSO handlers
// are never used, because they bypass symbiont's access policy.
var ErrNotSupported = errors.New("idp: crewjam session-driven assertions are disabled; use IdP.Respond")

// MakeAssertion implements saml.AssertionMaker so a crewjam IdentityProvider
// configured with this maker never falls back to DefaultAssertionMaker. It
// fails closed: every assertion must go through access.Decide.
func (m *AssertionMaker) MakeAssertion(*saml.IdpAuthnRequest, *saml.Session) error {
	return ErrNotSupported
}

func stringAttribute(name, value string) saml.Attribute {
	return saml.Attribute{
		Name:       name,
		NameFormat: AttrNameFormatUnspecified,
		Values:     []saml.AttributeValue{{Type: AttrValueTypeString, Value: value}},
	}
}

// newID returns a random XML ID (which must not start with a digit).
func newID() string {
	var b [20]byte
	_, _ = rand.Read(b[:])
	return "id-" + hex.EncodeToString(b[:])
}
