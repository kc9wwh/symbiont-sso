package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"

	"github.com/kc9wwh/symbiont-sso/internal/session"
)

// startForcedSSO is startSSO for an AuthnRequest with ForceAuthn="true".
func (e *e2e) startForcedSSO(sp *saml.ServiceProvider) (string, string) {
	e.t.Helper()
	ar, err := sp.MakeAuthenticationRequest(e.idp.SSOURL(), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		e.t.Fatal(err)
	}
	force := true
	ar.ForceAuthn = &force
	u, err := ar.Redirect("", sp)
	if err != nil {
		e.t.Fatal(err)
	}
	return u.String(), ar.ID
}

// A live bridge session must not satisfy an SP that sent ForceAuthn: the
// user goes back to the provider with prompt=login, and the replay after
// that fresh login is answered without looping.
func TestE2EForceAuthnReauthenticates(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	sp := e.sp(e2eAdminEntity, e2eAdminACS)
	e.fullLogin(sp, "")

	// Control: without ForceAuthn the session is reused (no redirect).
	ssoURL, _ := e.startSSO(sp, "")
	if resp := e.do(http.MethodGet, ssoURL, nil); resp.StatusCode == http.StatusFound {
		t.Fatalf("plain request redirected to %q despite a live session", resp.Header.Get("Location"))
	}

	ssoURL, reqID := e.startForcedSSO(sp)
	authURL := e.toIdP(ssoURL)
	if !strings.Contains(authURL, "prompt=login") {
		t.Fatalf("ForceAuthn did not force provider re-login: %s", authURL)
	}
	a, _ := e.deliver(e.replay(e.callback(authURL)), sp, reqID)
	if a == nil {
		t.Fatal("no assertion after forced re-authentication")
	}
}

// With no auth_time claim, AuthnInstant is the session's creation time, not
// the moment the assertion is issued.
func TestIdentityFromSessionAuthTimeFallback(t *testing.T) {
	s := session.Session{ID: "s", Email: "a@example.com", IssuedAt: time.Unix(1_700_000_000, 0).UTC()}
	if got := identityFromSession(&s).AuthTime; !got.Equal(s.IssuedAt) {
		t.Errorf("AuthTime = %v, want session IssuedAt %v", got, s.IssuedAt)
	}
	s.AuthTime = s.IssuedAt.Add(-time.Hour)
	if got := identityFromSession(&s).AuthTime; !got.Equal(s.AuthTime) {
		t.Errorf("AuthTime = %v, want the provider's auth_time %v", got, s.AuthTime)
	}
}
