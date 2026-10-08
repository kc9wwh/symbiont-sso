package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kc9wwh/symbiont-sso/internal/web"
)

// callbackPage completes the upstream login and returns the replay page
// (status, headers, body) without submitting it.
func (e *e2e) callbackPage() (*http.Response, string) {
	e.t.Helper()
	ssoURL, _ := e.startSSO(e.sp(e2eAdminEntity, e2eAdminACS), "rs-1")
	resp := e.callback(e.toIdP(ssoURL))
	return resp, readBody(e.t, resp)
}

// TestReplayPageCSP: the post-login replay page must auto-submit only to
// the bridge itself ('self') and allow only its own script.
func TestReplayPageCSP(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	resp, body := e.callbackPage()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	csp := cspDirectives(resp.Header.Get(web.CSPHeader))
	scripts := scriptRE.FindAllStringSubmatch(body, -1)
	if len(scripts) != 1 || csp["script-src"][0] != web.ScriptHash(scripts[0][1]) || len(csp["script-src"]) != 1 {
		t.Errorf("script-src = %v", csp["script-src"])
	}
	if len(csp["form-action"]) != 1 || csp["form-action"][0] != "'self'" {
		t.Errorf("form-action = %v, want 'self'", csp["form-action"])
	}
	action, fields := formFields(t, body)
	if action != "/sso" {
		t.Errorf("replay action = %q", action)
	}
	if fields.Get("SAMLRequest") == "" || fields.Get(replayField) == "" || fields.Get("RelayState") != "rs-1" {
		t.Errorf("replay fields = %v", fields)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("replay page cacheable")
	}
}

func TestReplayTokenAbuse(t *testing.T) {
	t.Run("token bound to request bytes", func(t *testing.T) {
		e := newE2E(t, e2eOpts{})
		_, body := e.callbackPage()
		_, fields := formFields(t, body)
		// Swap in a different (fresh) AuthnRequest with the same token.
		other, _ := e.startSSO(e.sp(e2eAdminEntity, e2eAdminACS), "")
		u, _ := url.Parse(other)
		fields.Set("SAMLRequest", deflatedToRaw(t, u.Query().Get("SAMLRequest")))
		e.expectFail(e.do(http.MethodPost, e.bridge.URL+"/sso", fields), http.StatusBadRequest, "replay_token_invalid")
	})
	t.Run("forged token", func(t *testing.T) {
		e := newE2E(t, e2eOpts{})
		_, body := e.callbackPage()
		_, fields := formFields(t, body)
		fields.Set(replayField, "AQ.forged")
		e.expectFail(e.do(http.MethodPost, e.bridge.URL+"/sso", fields), http.StatusBadRequest, "replay_token_invalid")
	})
	t.Run("expired token", func(t *testing.T) {
		e := newE2E(t, e2eOpts{sessionTTL: time.Hour})
		_, body := e.callbackPage()
		_, fields := formFields(t, body)
		e.clk.advance(replayTokenTTL + time.Second)
		e.expectFail(e.do(http.MethodPost, e.bridge.URL+"/sso", fields), http.StatusBadRequest, "replay_token_invalid")
	})
	t.Run("replay without session cookie does not loop", func(t *testing.T) {
		e := newE2E(t, e2eOpts{})
		_, body := e.callbackPage()
		_, fields := formFields(t, body)
		e.setSessionCookie("") // browser dropped the cookie
		u, _ := url.Parse(e.bridge.URL)
		e.browser.Jar.SetCookies(u, []*http.Cookie{{Name: e.login.Cookies.SessionName(), MaxAge: -1, Path: "/"}})
		resp := e.do(http.MethodPost, e.bridge.URL+"/sso", fields)
		page := e.expectFail(resp, http.StatusBadRequest, "session_cookie_missing")
		if !strings.Contains(page, "cookies are enabled") {
			t.Errorf("page = %s", page)
		}
	})
}
