package server

import (
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"

	"github.com/kc9wwh/symbiont-sso/internal/oidcrp/oidctest"
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
	if !strings.Contains(authURL, "prompt=login") || !strings.Contains(authURL, "max_age=0") {
		t.Fatalf("ForceAuthn did not force provider re-login: %s", authURL)
	}
	e.queueFirst(adminWithAuthTime(e.clk.now()))
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

func adminWithAuthTime(at time.Time) *oidctest.User {
	return oidctest.Member("admin", []string{"fleet-admins", "employees"}, map[string]any{"auth_time": at.Unix()})
}

// A forced login is only honoured if the provider proves it re-authenticated
// the user: auth_time must be present and not older than the login request.
func TestE2EForceAuthnRequiresFreshAuthTime(t *testing.T) {
	tests := []struct {
		name string
		user func(now time.Time) *oidctest.User
		ok   bool
	}{
		{"fresh auth_time", func(now time.Time) *oidctest.User { return adminWithAuthTime(now) }, true},
		{"auth_time within skew", func(now time.Time) *oidctest.User { return adminWithAuthTime(now.Add(-30 * time.Second)) }, true},
		{"stale auth_time", func(now time.Time) *oidctest.User { return adminWithAuthTime(now.Add(-time.Hour)) }, false},
		{"missing auth_time", func(time.Time) *oidctest.User { return adminUser }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newE2E(t, e2eOpts{anyUser: true})
			sp := e.sp(e2eAdminEntity, e2eAdminACS)
			e.queueFirst(tc.user(e.clk.now()))
			ssoURL, _ := e.startForcedSSO(sp)
			resp := e.callback(e.toIdP(ssoURL))
			if tc.ok {
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status = %d, want the replay page\n%s", resp.StatusCode, e.logs.String())
				}
				return
			}
			e.expectFail(resp, http.StatusForbidden, catReauthNotPerformed)
			if e.sessions.Len() != 0 {
				t.Error("a session was created for a refused login")
			}
		})
	}
}

// Without ForceAuthn a missing auth_time is fine.
func TestE2EPlainLoginIgnoresAuthTime(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	if a, _ := e.fullLogin(e.sp(e2eAdminEntity, e2eAdminACS), ""); a == nil {
		t.Fatal("plain login failed without auth_time")
	}
}

// The limiter charges when a login is started, not for the bridge's own
// replay POST: a complete login costs one token, and a login answered from a
// live session costs none.
func TestE2ERateLimitChargesLoginStartsOnly(t *testing.T) {
	e := newE2E(t, e2eOpts{rateLimit: 1})
	sp := e.sp(e2eAdminEntity, e2eAdminACS)
	if a, _ := e.fullLogin(sp, ""); a == nil {
		t.Fatal("login with a budget of one failed (replay charged?)")
	}
	ssoURL, _ := e.startSSO(sp, "")
	if resp := e.do(http.MethodGet, ssoURL, nil); resp.StatusCode == http.StatusTooManyRequests {
		t.Fatal("request answered from a live session was rate limited")
	}

	jar, _ := cookiejar.New(nil)
	e.browser.Jar = jar // a new browser from the same address
	ssoURL, _ = e.startSSO(sp, "")
	e.expectFail(e.do(http.MethodGet, ssoURL, nil), http.StatusTooManyRequests, "rate_limited")
}
