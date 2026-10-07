package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kc9wwh/symbiont-sso/internal/oidcrp/oidctest"
)

// TestE2ESPInitiated is the phase 3 acceptance test: mockoidc upstream,
// bridge in the middle, crewjam SP (as Fleet) downstream.
func TestE2ESPInitiated(t *testing.T) {
	e := newE2E(t, e2eOpts{fetchUserinfo: true})
	e.oidc.QueueUser(oidctest.Alice("fleet-admins"))
	sp := e.sp(e2eAdminEntity, e2eAdminACS)

	ssoURL, reqID := e.startSSO(sp, "fleet-relay")
	authURL := e.toIdP(ssoURL)
	for _, want := range []string{"code_challenge_method=S256", "nonce=", "state="} {
		if !strings.Contains(authURL, want) {
			t.Errorf("authorize URL missing %s", want)
		}
	}
	a, fields := e.deliver(e.replay(e.callback(authURL)), sp, reqID)

	if a.Subject.NameID.Value != "alice@example.com" {
		t.Errorf("NameID = %q", a.Subject.NameID.Value)
	}
	if fields.Get("RelayState") != "fleet-relay" {
		t.Errorf("RelayState = %q, want it echoed through the upstream login", fields.Get("RelayState"))
	}
	attrs := map[string]string{}
	for _, at := range a.AttributeStatements[0].Attributes {
		attrs[at.Name] = at.Values[0].Value
	}
	if attrs["email"] != "alice@example.com" || attrs["name"] != "Alice Example" {
		t.Errorf("attributes = %v", attrs)
	}
	if e.sessions.Len() != 1 || e.pending.Len() != 0 {
		t.Errorf("sessions=%d pending=%d", e.sessions.Len(), e.pending.Len())
	}
	logs := e.logs.String()
	for _, want := range []string{`"msg":"upstream login succeeded"`, `"msg":"sso success"`, `"sp_id":"fleet-admin"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs missing %s", want)
		}
	}
	for _, secret := range []string{"code=", e.oidc.ClientSecret, "SAMLResponse", "id_token"} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs leaked %q", secret)
		}
	}
}

// After login, a second SP-initiated request within the session TTL is
// answered directly (true SSO), without a round-trip to the IdP.
func TestE2ESessionReuse(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	sp := e.sp(e2eAdminEntity, e2eAdminACS)
	e.fullLogin(sp, "")

	ssoURL, reqID := e.startSSO(sp, "")
	resp := e.do(http.MethodGet, ssoURL, nil)
	a, _ := e.deliver(resp, sp, reqID)
	if a.Subject.NameID.Value != "jane.doe@example.com" {
		t.Errorf("NameID = %q", a.Subject.NameID.Value)
	}

	// Server-side expiry: after the TTL the session no longer counts.
	e.clk.advance(61 * time.Second)
	ssoURL, _ = e.startSSO(sp, "")
	if loc := e.toIdP(ssoURL); !strings.HasPrefix(loc, e.oidc.AuthorizationEndpoint()) {
		t.Errorf("expired session should redirect to IdP, got %q", loc)
	}
}

// A slow upstream login (well past crewjam's 90s IssueInstant limit) still
// succeeds because the replay is judged at the original receipt time.
func TestE2ESlowLoginReplay(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	sp := e.sp(e2eAdminEntity, e2eAdminACS)
	ssoURL, reqID := e.startSSO(sp, "")
	authURL := e.toIdP(ssoURL)
	e.clk.advance(4 * time.Minute) // user dawdles at the passkey prompt
	a, _ := e.deliver(e.replay(e.callback(authURL)), sp, reqID)
	if a == nil {
		t.Fatal("no assertion")
	}
}
