package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/oauth2-proxy/mockoidc"

	"github.com/kc9wwh/symbiont-sso/internal/config"
	"github.com/kc9wwh/symbiont-sso/internal/idp"
	"github.com/kc9wwh/symbiont-sso/internal/oidcrp"
	"github.com/kc9wwh/symbiont-sso/internal/oidcrp/oidctest"
	"github.com/kc9wwh/symbiont-sso/internal/session"
)

const (
	e2eAdminEntity = "fleet.example.com"
	e2eAdminACS    = "https://fleet.example.com/api/v1/fleet/sso/callback"
	e2eMDMEntity   = "fleet.example.com/mdm"
	e2eMDMACS      = "https://fleet.example.com/api/v1/fleet/mdm/sso/callback"
)

// clock is a settable time source shared by the bridge components.
type clock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return time.Now().Add(c.off) }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.off += d
}

// e2e is a running bridge (httptest, http://127.0.0.1) wired to a mock OIDC
// provider, plus a browser with a cookie jar.
type e2e struct {
	t        *testing.T
	oidc     *mockoidc.MockOIDC
	bridge   *httptest.Server
	idp      *idp.IdP
	login    *Login
	pending  *session.MemoryPendingStore
	sessions *session.MemorySessionStore
	clk      *clock
	logs     *syncBuffer
	browser  *http.Client
}

type e2eOpts struct {
	policy        oidcrp.Policy
	fetchUserinfo bool
	sessionTTL    time.Duration
	maxSessions   int
}

func newE2E(t *testing.T, o e2eOpts) *e2e {
	t.Helper()
	if o.sessionTTL == 0 {
		o.sessionTTL = time.Minute
	}
	e := &e2e{t: t, oidc: oidctest.Start(t), clk: &clock{}, logs: &syncBuffer{}}
	// The handler is installed after the server starts so its URL is known.
	var h http.Handler
	e.bridge = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(e.bridge.Close)
	base, _ := url.Parse(e.bridge.URL)

	key, cert := serverKeyPair(t)
	sps, err := idp.NewServiceProviders([]config.ServiceProvider{
		{ID: "fleet-admin", DisplayName: "Fleet", EntityID: e2eAdminEntity, ACSURLs: []string{e2eAdminACS},
			IDPInitiatedEnabled: true, IDPInitiatedACSURL: e2eAdminACS,
			Access: config.AccessPolicy{AllowGroups: []string{"fleet-admins"}}},
		{ID: "fleet-enduser", DisplayName: "Fleet device enrollment", EntityID: e2eMDMEntity, ACSURLs: []string{e2eMDMACS},
			Access: config.AccessPolicy{AllowGroups: []string{"employees"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.idp, err = idp.New(idp.Options{BaseURL: base, Certificate: cert, Key: key, SPs: sps, Now: e.clk.now}); err != nil {
		t.Fatal(err)
	}
	oc, err := oidcrp.New(context.Background(), oidcrp.Options{
		Issuer: e.oidc.Issuer(), ClientID: e.oidc.ClientID, ClientSecret: e.oidc.ClientSecret,
		RedirectURL: e.bridge.URL + CallbackPath, Scopes: []string{"openid", "email", "profile", "groups"},
		FetchUserinfo: o.fetchUserinfo,
	})
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := session.NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	e.pending = session.NewMemoryPendingStore(session.MemoryOptions{TTL: 10 * time.Minute, Now: e.clk.now})
	e.sessions = session.NewMemorySessionStore(session.MemoryOptions{Now: e.clk.now, MaxEntries: o.maxSessions})
	e.login = &Login{
		OIDC: oc, Pending: e.pending, Sessions: e.sessions, Signer: signer,
		Cookies:    session.NewCookies(false),
		Claims:     oidcrp.ClaimNames{Email: "email", Name: "name", Groups: "groups"},
		Policy:     o.policy,
		SessionTTL: o.sessionTTL, PendingTTL: 10 * time.Minute, Now: e.clk.now,
	}
	logger := slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h = New(Options{Logger: logger, IdP: e.idp, Login: e.login}).Handler()

	jar, _ := cookiejar.New(nil)
	e.browser = &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return e
}

// sp returns a crewjam ServiceProvider (as Fleet uses) trusting the bridge.
func (e *e2e) sp(entityID, acs string) *saml.ServiceProvider {
	raw, err := e.idp.MetadataXML()
	if err != nil {
		e.t.Fatal(err)
	}
	md, err := samlParseMetadata(raw)
	if err != nil {
		e.t.Fatal(err)
	}
	a, _ := url.Parse(acs)
	return &saml.ServiceProvider{EntityID: entityID, AcsURL: *a, IDPMetadata: md, AuthnNameIDFormat: saml.EmailAddressNameIDFormat}
}
