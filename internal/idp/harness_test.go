package idp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crewjam/saml"

	"github.com/kc9wwh/symbiont-sso/internal/config"
)

const (
	testBase       = "https://saml.example.com"
	adminEntityID  = "fleet.example.com"
	adminACS       = "https://fleet.example.com/api/v1/fleet/sso/callback"
	adminACS2      = "https://fleet.example.com/alt/callback"
	mdmEntityID    = "fleet.example.com/mdm"
	mdmACS         = "https://fleet.example.com/api/v1/fleet/mdm/sso/callback"
	testUserEmail  = "alice@example.com"
	testUserName   = "Alice Example"
	testSessionIdx = "sess-123"
)

var (
	keyOnce sync.Once
	idpKey  *rsa.PrivateKey
	idpCert *x509.Certificate
)

func testKeyPair(t testing.TB) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "saml.example.com"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		if err != nil {
			panic(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			panic(err)
		}
		idpKey, idpCert = k, c
	})
	return idpKey, idpCert
}

// testSPConfigs mirrors the amendment's two-SP example, with a second admin
// ACS so ACS selection is observable.
func testSPConfigs() []config.ServiceProvider {
	return []config.ServiceProvider{
		{
			ID: "fleet-admin", DisplayName: "Fleet", EntityID: adminEntityID,
			ACSURLs:             []string{adminACS2, adminACS},
			IDPInitiatedEnabled: true, IDPInitiatedACSURL: adminACS,
			Access:              config.AccessPolicy{AllowGroups: []string{"fleet-admins"}},
			FleetRoleValidation: true,
		},
		{
			ID: "fleet-enduser", DisplayName: "Fleet device enrollment", EntityID: mdmEntityID,
			ACSURLs: []string{mdmACS},
			Access:  config.AccessPolicy{AllowGroups: []string{"employees"}},
		},
	}
}

func newTestIdP(t testing.TB) *IdP {
	t.Helper()
	key, cert := testKeyPair(t)
	sps, err := NewServiceProviders(testSPConfigs())
	if err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse(testBase)
	p, err := New(Options{BaseURL: base, Certificate: cert, Key: key, SPs: sps})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// testSP returns a crewjam ServiceProvider (the same library Fleet uses)
// that trusts p via p's published metadata XML.
func testSP(t *testing.T, p *IdP, entityID, acs string) *saml.ServiceProvider {
	t.Helper()
	raw, err := p.MetadataXML()
	if err != nil {
		t.Fatal(err)
	}
	var md saml.EntityDescriptor
	if err := xml.Unmarshal(raw, &md); err != nil {
		t.Fatalf("parse IdP metadata: %v", err)
	}
	acsURL, _ := url.Parse(acs)
	return &saml.ServiceProvider{
		EntityID:          entityID,
		AcsURL:            *acsURL,
		IDPMetadata:       &md,
		AuthnNameIDFormat: saml.EmailAddressNameIDFormat,
	}
}

func testIdentity() *Identity {
	return &Identity{
		SessionID: testSessionIdx,
		Subject:   "sub-1",
		Email:     testUserEmail,
		Name:      testUserName,
		AuthTime:  time.Now().Add(-10 * time.Second),
	}
}

// redirectRequest builds a GET /sso request exactly as Fleet does
// (HTTP-Redirect binding, response via HTTP-POST).
func redirectRequest(t *testing.T, sp *saml.ServiceProvider, relayState string) (*http.Request, string) {
	t.Helper()
	ar, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		t.Fatal(err)
	}
	u, err := ar.Redirect(relayState, sp)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewRequest(http.MethodGet, u.String(), nil), ar.ID
}

// postRequest builds a POST /sso request (HTTP-POST binding).
func postRequest(t *testing.T, sp *saml.ServiceProvider, relayState string) (*http.Request, string) {
	t.Helper()
	ar, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPPostBinding),
		saml.HTTPPostBinding, saml.HTTPPostBinding)
	if err != nil {
		t.Fatal(err)
	}
	buf, err := xml.Marshal(ar)
	if err != nil {
		t.Fatal(err)
	}
	return rawPostRequest(base64.StdEncoding.EncodeToString(buf), relayState), ar.ID
}

func rawPostRequest(samlRequest, relayState string) *http.Request {
	form := url.Values{"SAMLRequest": {samlRequest}}
	if relayState != "" {
		form.Set("RelayState", relayState)
	}
	r := httptest.NewRequest(http.MethodPost, testBase+SSOPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// acsPost turns a PostForm into the request the browser would POST to the
// SP's ACS.
func acsPost(f *PostForm) *http.Request {
	form := url.Values{"SAMLResponse": {f.SAMLResponse}, "RelayState": {f.RelayState}}
	r := httptest.NewRequest(http.MethodPost, f.Action, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r.ParseForm()
	return r
}
