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

// Test users (groups in the ID token). The harness's SPs mirror the
// amendment: fleet-admin allows fleet-admins/fleet-maintainers and maps
// FLEET_JIT_USER_ROLE_GLOBAL; fleet-enduser allows employees, no roles.
var (
	adminUser    = oidctest.Member("admin", []string{"fleet-admins", "employees"}, nil)
	employeeUser = oidctest.Member("emp", []string{"employees"}, nil)
)

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
	// sps overrides the default service providers (parsed from YAML).
	sps []config.ServiceProvider
	// anyUser keeps mockoidc's default user instead of queueing adminUser.
	anyUser bool
}

// defaultE2ESPs is the amendment's two-SP setup, loaded through the real
// config parser so tests exercise the shipped validation.
func defaultE2ESPs(t *testing.T) []config.ServiceProvider {
	t.Helper()
	sps, _, err := config.ParseServiceProviders([]byte(`
service_providers:
  - id: fleet-admin
    display_name: Fleet
    entity_id: ` + e2eAdminEntity + `
    acs_urls: [` + e2eAdminACS + `]
    idp_initiated: {enabled: true}
    access: {allow_groups: [fleet-admins, fleet-maintainers]}
    fleet_role_validation: true
    attributes:
      - name: FLEET_JIT_USER_ROLE_GLOBAL
        rules:
          - {group: fleet-admins, value: admin}
          - {group: fleet-maintainers, value: maintainer}
  - id: fleet-enduser
    display_name: Fleet device enrollment
    entity_id: ` + e2eMDMEntity + `
    acs_urls: [` + e2eMDMACS + `]
    idp_initiated: {enabled: false}
    access: {allow_groups: [employees]}
    fleet_role_validation: false
    attributes: []
`))
	if err != nil {
		t.Fatal(err)
	}
	return sps
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
	spCfgs := o.sps
	if spCfgs == nil {
		spCfgs = defaultE2ESPs(t)
	}
	sps, err := idp.NewServiceProviders(spCfgs)
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
	if !o.anyUser {
		// mockoidc pops one queued user per authorization and otherwise
		// falls back to its built-in user (in no groups). Default to an
		// allowed admin; tests pick other users with queueFirst.
		for range 32 {
			e.oidc.QueueUser(adminUser)
		}
	}
	return e
}

// queueFirst makes u the user for the next upstream login.
func (e *e2e) queueFirst(u mockoidc.User) {
	q := e.oidc.UserQueue
	q.Lock()
	defer q.Unlock()
	q.Queue = append([]mockoidc.User{u}, q.Queue...)
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
