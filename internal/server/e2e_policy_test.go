package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kc9wwh/symbiont-sso/internal/oidcrp"
	"github.com/kc9wwh/symbiont-sso/internal/oidcrp/oidctest"
	"github.com/kc9wwh/symbiont-sso/internal/session"
)

func TestE2EGlobalEmailPolicy(t *testing.T) {
	tests := []struct {
		name   string
		user   *oidctest.User
		policy oidcrp.Policy
		cat    string
		msg    string
	}{
		{"unverified email", &oidctest.User{Sub: "s", IDToken: map[string]any{"email": "a@example.com", "email_verified": false}},
			oidcrp.Policy{RequireEmailVerified: true}, oidcrp.CategoryEmailUnverified, "has not been verified"},
		{"disallowed domain", oidctest.Alice(), oidcrp.Policy{AllowedDomains: []string{"corp.example.org"}},
			oidcrp.CategoryDomainNotAllowed, "email domain are not allowed"},
		{"missing email", &oidctest.User{Sub: "s", IDToken: map[string]any{"name": "No Mail"}},
			oidcrp.Policy{}, oidcrp.CategoryMissingEmail, "no email address"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newE2E(t, e2eOpts{policy: tc.policy})
			e.queueFirst(tc.user)
			ssoURL, _ := e.startSSO(e.sp(e2eAdminEntity, e2eAdminACS), "")
			body := e.expectFail(e.callback(e.toIdP(ssoURL)), http.StatusForbidden, tc.cat)
			if !strings.Contains(body, tc.msg) {
				t.Errorf("page = %s", body)
			}
			if e.sessions.Len() != 0 {
				t.Error("session created for rejected identity")
			}
			if strings.Contains(e.logs.String(), "upstream login succeeded") {
				t.Error("rejected login logged as success")
			}
		})
	}
}

// sessionCookie returns the browser's bridge session cookie.
func (e *e2e) sessionCookie() *http.Cookie {
	u, _ := url.Parse(e.bridge.URL)
	for _, c := range e.browser.Jar.Cookies(u) {
		if c.Name == e.login.Cookies.SessionName() {
			return c
		}
	}
	return nil
}

func (e *e2e) setSessionCookie(v string) {
	u, _ := url.Parse(e.bridge.URL)
	e.browser.Jar.SetCookies(u, []*http.Cookie{{Name: e.login.Cookies.SessionName(), Value: v, Path: "/"}})
}

// TestE2ESessionCookieFailures: anything but a valid, current, signed
// session cookie leads back to the IdP (never to an assertion).
func TestE2ESessionCookieFailures(t *testing.T) {
	setup := func(t *testing.T, o e2eOpts) (*e2e, string) {
		e := newE2E(t, o)
		e.fullLogin(e.sp(e2eAdminEntity, e2eAdminACS), "")
		c := e.sessionCookie()
		if c == nil {
			t.Fatal("no session cookie after login")
		}
		if !c.HttpOnly && c.Value == "" {
			t.Fatal("bad cookie")
		}
		return e, c.Value
	}
	expectIdPRedirect := func(e *e2e, reason string) {
		e.t.Helper()
		ssoURL, _ := e.startSSO(e.sp(e2eAdminEntity, e2eAdminACS), "")
		if loc := e.toIdP(ssoURL); !strings.HasPrefix(loc, e.oidc.AuthorizationEndpoint()) {
			e.t.Errorf("want IdP redirect, got %q", loc)
		}
		if reason != "" && !strings.Contains(e.logs.String(), `"reason":"`+reason+`"`) {
			e.t.Errorf("logs missing reason %s", reason)
		}
	}

	t.Run("tampered cookie", func(t *testing.T) {
		e, v := setup(t, e2eOpts{})
		b := []byte(v)
		b[5] ^= 1
		e.setSessionCookie(string(b))
		expectIdPRedirect(e, sessionInvalid)
	})
	t.Run("cookie signed by another key", func(t *testing.T) {
		e, _ := setup(t, e2eOpts{})
		other, _ := session.NewSigner([]byte("ffffffffffffffffffffffffffffffff"))
		sess, _ := e.sessions.Get(t.Context(), firstSessionID(t, e))
		e.setSessionCookie(other.Sign(session.PurposeSession, sess.ID, time.Now().Add(time.Hour)))
		expectIdPRedirect(e, sessionInvalid)
	})
	t.Run("state token reused as session cookie", func(t *testing.T) {
		e, _ := setup(t, e2eOpts{})
		e.setSessionCookie(e.login.Signer.Sign(session.PurposeState, firstSessionID(t, e), time.Now().Add(time.Hour)))
		expectIdPRedirect(e, sessionInvalid)
	})
	t.Run("expired cookie", func(t *testing.T) {
		// Correctly signed, for a live server-side session, but past the
		// token's own expiry: rejected on the signed expiry alone.
		e, _ := setup(t, e2eOpts{sessionTTL: time.Hour})
		id := firstSessionID(t, e)
		e.setSessionCookie(e.login.Signer.Sign(session.PurposeSession, id, e.clk.now().Add(-time.Second)))
		expectIdPRedirect(e, sessionExpired)
	})
	t.Run("expired server-side session", func(t *testing.T) {
		// Cookie still valid but the store entry has expired.
		e, _ := setup(t, e2eOpts{sessionTTL: time.Minute})
		id := firstSessionID(t, e)
		e.setSessionCookie(e.login.Signer.Sign(session.PurposeSession, id, e.clk.now().Add(time.Hour)))
		_ = e.sessions.Delete(t.Context(), id)
		_ = e.sessions.Create(t.Context(), session.Session{ID: id, ExpiresAt: e.clk.now().Add(-time.Second)})
		expectIdPRedirect(e, sessionNotFound)
	})
	t.Run("evicted session", func(t *testing.T) {
		e, v := setup(t, e2eOpts{maxSessions: 1})
		// A second user's login evicts the first session from the bounded store.
		_ = e.sessions.Create(t.Context(), session.Session{ID: "other", ExpiresAt: time.Now().Add(time.Hour)})
		e.setSessionCookie(v)
		expectIdPRedirect(e, sessionNotFound)
	})
	t.Run("no cookie", func(t *testing.T) {
		e := newE2E(t, e2eOpts{})
		expectIdPRedirect(e, "")
	})
}

func firstSessionID(t *testing.T, e *e2e) string {
	t.Helper()
	c := e.sessionCookie()
	id, err := e.login.Signer.Verify(session.PurposeSession, c.Value, e.clk.now())
	if err != nil {
		t.Fatal(err)
	}
	return id
}
