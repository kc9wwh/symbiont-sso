package server

import (
	"net/http"
	"strings"
	"testing"
)

// Enduser-only user with an existing session at /login/fleet-admin: 403,
// no assertion, session kept, no IdP redirect.
func TestE2EIdPInitiatedDenied(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	e.queueFirst(employeeUser)
	e.fullLogin(e.sp(e2eMDMEntity, e2eMDMACS), "")
	before := e.sessionCookie().Value

	e.expectDenied(e.do(http.MethodGet, e.loginURL("fleet-admin", ""), nil), "Fleet")
	if e.sessionCookie().Value != before || e.sessions.Len() != 1 {
		t.Error("session not kept")
	}
	want := `"flow":"idp","sp_id":"fleet-admin","sp_entity_id":"fleet.example.com","email":"emp@example.com","reason":"no_matching_group"`
	if !strings.Contains(e.logs.String(), want) {
		t.Errorf("denial not logged as expected:\n%s", e.logs.String())
	}
	if n := strings.Count(e.logs.String(), `"msg":"redirecting to identity provider"`); n != 1 {
		t.Errorf("IdP redirects = %d, want 1 (the initial login)", n)
	}
}

// Disabled and unknown SPs return the same 404 (no hint which).
func TestE2EIdPInitiatedNotFound(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	var bodies []string
	for _, id := range []string{"fleet-enduser", "nope", "FLEET-ADMIN"} {
		resp := e.do(http.MethodGet, e.loginURL(id, ""), nil)
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("/login/%s = %d, want 404", id, resp.StatusCode)
		}
		bodies = append(bodies, stripReference(body))
	}
	if bodies[0] != bodies[1] {
		t.Error("disabled and unknown SP responses differ")
	}
	if e.pending.Len() != 0 {
		t.Error("404 started a login")
	}
	for _, p := range []string{"/login", "/login/"} {
		if resp := e.do(http.MethodGet, e.bridge.URL+p, nil); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", p, resp.StatusCode)
		}
	}
}

func TestE2EIdPInitiatedReturnTokenAndRelayState(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	// Callback return without a session cookie: error, no second login.
	body := e.expectFail(e.do(http.MethodGet, e.bridge.URL+e.loginReturnPath("fleet-admin"), nil),
		http.StatusBadRequest, "session_cookie_missing")
	if !strings.Contains(body, "cookies are enabled") {
		t.Errorf("page = %s", body)
	}
	if e.pending.Len() != 0 {
		t.Error("dropped cookie started another login")
	}
	// Forged return token.
	e.expectFail(e.do(http.MethodGet, e.loginURL("fleet-admin", "")+"?return=AQ.bogus", nil),
		http.StatusBadRequest, "replay_token_invalid")
	// A token minted for another SP is not accepted.
	other := strings.Replace(e.loginReturnPath("other"), "/login/other", "/login/fleet-admin", 1)
	e.expectFail(e.do(http.MethodGet, e.bridge.URL+other, nil), http.StatusBadRequest, "replay_token_invalid")
	// RelayState over 80 bytes rejected.
	e.expectFail(e.do(http.MethodGet, e.loginURL("fleet-admin", strings.Repeat("x", 81)), nil),
		http.StatusBadRequest, "invalid_relay_state")
}
