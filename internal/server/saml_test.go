package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crewjam/saml"

	"github.com/kc9wwh/symbiont-sso/internal/config"
	"github.com/kc9wwh/symbiont-sso/internal/idp"
)

const (
	base       = "https://saml.example.com"
	adminID    = "fleet.example.com"
	adminACS   = "https://fleet.example.com/api/v1/fleet/sso/callback"
	unknownACS = "https://evil.example.com/acs"
)

var (
	srvKeyOnce sync.Once
	srvKey     *rsa.PrivateKey
	srvCert    *x509.Certificate
)

func serverKeyPair(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	srvKeyOnce.Do(func() {
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		srvCert, _ = x509.ParseCertificate(der)
		srvKey = k
	})
	return srvKey, srvCert
}

// fixedSessions is the phase 2 test-only session provider: every request
// belongs to the same user.
type fixedSessions struct{ id *idp.Identity }

func (f fixedSessions) Identity(http.ResponseWriter, *http.Request, *idp.AuthnRequest) *idp.Identity {
	return f.id
}

type samlFixture struct {
	srv  *Server
	idp  *idp.IdP
	logs *syncBuffer
}

func newSAMLFixture(t *testing.T, sessions Sessions) *samlFixture {
	t.Helper()
	key, cert := serverKeyPair(t)
	sps, err := idp.NewServiceProviders([]config.ServiceProvider{{
		ID: "fleet-admin", DisplayName: "Fleet", EntityID: adminID, ACSURLs: []string{adminACS},
		Access: config.AccessPolicy{AllowAll: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(base)
	p, err := idp.New(idp.Options{BaseURL: u, Certificate: cert, Key: key, SPs: sps})
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return &samlFixture{srv: New(Options{Logger: logger, IdP: p, Sessions: sessions}), idp: p, logs: logs}
}

func (f *samlFixture) do(r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(rec, r)
	return rec
}

func (f *samlFixture) sp(t *testing.T, acs string) *saml.ServiceProvider {
	t.Helper()
	raw, _ := f.idp.MetadataXML()
	var md saml.EntityDescriptor
	if err := xml.Unmarshal(raw, &md); err != nil {
		t.Fatal(err)
	}
	a, _ := url.Parse(acs)
	return &saml.ServiceProvider{EntityID: adminID, AcsURL: *a, IDPMetadata: &md}
}

func fleetRedirect(t *testing.T, sp *saml.ServiceProvider, relay string) (*http.Request, string) {
	t.Helper()
	ar, err := sp.MakeAuthenticationRequest(base+idp.SSOPath, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		t.Fatal(err)
	}
	u, err := ar.Redirect(relay, sp)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewRequest(http.MethodGet, u.String(), nil), ar.ID
}

var (
	scriptRE = regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	styleRE  = regexp.MustCompile(`(?s)<style>(.*?)</style>`)
	actionRE = regexp.MustCompile(`<form id="f" method="post" action="([^"]+)">`)
	inputRE  = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)
)

// cspDirectives parses a CSP header into directive -> sources.
func cspDirectives(csp string) map[string][]string {
	out := map[string][]string{}
	for _, d := range strings.Split(csp, ";") {
		f := strings.Fields(d)
		if len(f) > 0 {
			out[f[0]] = f[1:]
		}
	}
	return out
}

func testUser() *idp.Identity {
	return &idp.Identity{SessionID: "s1", Email: "alice@example.com", Name: "Alice"}
}
