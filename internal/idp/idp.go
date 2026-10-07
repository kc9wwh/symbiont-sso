package idp

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
)

// Endpoint paths, relative to the public base URL.
const (
	MetadataPath = "/metadata"
	SSOPath      = "/sso"
)

// SignatureMethodRSASHA256 is the XML-DSig algorithm used for both the
// Response and Assertion signatures (crewjam defaults to RSA-SHA1).
const SignatureMethodRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

// Options configures an IdP.
type Options struct {
	BaseURL     *url.URL
	Certificate *x509.Certificate
	Key         *rsa.PrivateKey
	SPs         *ServiceProviders
	Attributes  AttributeSource
	Logger      *slog.Logger
	// Now overrides the clock (tests).
	Now func() time.Time
}

// IdP is symbiont's SAML identity provider. It validates AuthnRequests and
// produces signed responses; it does not render HTML.
type IdP struct {
	crew  *saml.IdentityProvider
	sps   *ServiceProviders
	maker *AssertionMaker
	now   func() time.Time
}

// New builds an IdP.
func New(o Options) (*IdP, error) {
	if o.BaseURL == nil || o.Certificate == nil || o.Key == nil || o.SPs == nil {
		return nil, errors.New("idp: BaseURL, Certificate, Key and SPs are required")
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	maker := &AssertionMaker{SPs: o.SPs, Attributes: o.Attributes}
	p := &IdP{sps: o.SPs, maker: maker, now: o.Now}
	p.crew = &saml.IdentityProvider{
		Key:                     o.Key,
		Certificate:             o.Certificate,
		Logger:                  slog.NewLogLogger(o.Logger.Handler(), slog.LevelWarn),
		MetadataURL:             withPath(o.BaseURL, MetadataPath),
		SSOURL:                  withPath(o.BaseURL, SSOPath),
		ServiceProviderProvider: o.SPs,
		SessionProvider:         noSessions{},
		AssertionMaker:          maker,
		SignatureMethod:         SignatureMethodRSASHA256,
	}
	return p, nil
}

func withPath(base *url.URL, path string) url.URL {
	u := *base
	u.Path = path
	return u
}

// EntityID is the IdP entity ID (its metadata URL, as crewjam requires).
func (p *IdP) EntityID() string { return p.crew.MetadataURL.String() }

// SSOURL is the absolute SSO endpoint URL.
func (p *IdP) SSOURL() string { return p.crew.SSOURL.String() }

// SPs returns the service provider registry.
func (p *IdP) SPs() *ServiceProviders { return p.sps }

// Metadata returns IdP metadata. Compared with crewjam's default it omits
// the "encryption" KeyDescriptor (symbiont never decrypts anything) and
// advertises the emailAddress NameID format it actually emits.
func (p *IdP) Metadata() *saml.EntityDescriptor {
	md := p.crew.Metadata()
	d := &md.IDPSSODescriptors[0]
	var keys []saml.KeyDescriptor
	for _, k := range d.KeyDescriptors {
		if k.Use == "signing" {
			keys = append(keys, k)
		}
	}
	d.KeyDescriptors = keys
	d.NameIDFormats = []saml.NameIDFormat{saml.EmailAddressNameIDFormat}
	return md
}

// MetadataXML renders Metadata as an XML document.
func (p *IdP) MetadataXML() ([]byte, error) {
	b, err := xml.MarshalIndent(p.Metadata(), "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), b...), nil
}

// noSessions satisfies crewjam's required SessionProvider. symbiont never
// calls IdentityProvider.ServeSSO/ServeIDPInitiated, so it is unreachable;
// if it is ever reached it fails closed.
type noSessions struct{}

func (noSessions) GetSession(w http.ResponseWriter, _ *http.Request, _ *saml.IdpAuthnRequest) *saml.Session {
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	return nil
}

// errorf is a small helper for wrapping crewjam errors with a category.
func errorf(category, entityID string, format string, args ...any) *RequestError {
	return &RequestError{Category: category, EntityID: entityID, Err: fmt.Errorf(format, args...)}
}
