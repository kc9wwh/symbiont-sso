package server

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kc9wwh/symbiont-sso/internal/oidcrp/oidctest"
	"github.com/kc9wwh/symbiont-sso/internal/session"
)

// expectFail asserts a generic error page and a logged category.
func (e *e2e) expectFail(resp *http.Response, status int, category string) string {
	e.t.Helper()
	body := readBody(e.t, resp)
	if resp.StatusCode != status {
		e.t.Fatalf("status = %d, want %d\n%s\nlogs:\n%s", resp.StatusCode, status, body, e.logs.String())
	}
	if !strings.Contains(e.logs.String(), `"error_category":"`+category+`"`) {
		e.t.Errorf("logs missing category %s:\n%s", category, e.logs.String())
	}
	if strings.Contains(body, "SAMLResponse") {
		e.t.Error("error response contains a SAML response")
	}
	return body
}

func (e *e2e) callbackURL(q url.Values) string { return e.bridge.URL + CallbackPath + "?" + q.Encode() }

func TestE2ECallbackStateFailures(t *testing.T) {
	t.Run("missing state", func(t *testing.T) {
		e := newE2E(t, e2eOpts{})
		e.expectFail(e.do(http.MethodGet, e.callbackURL(url.Values{"code": {"x"}}), nil), http.StatusBadRequest, catMissingParams)
	})
	t.Run("unknown state without binding cookie", func(t *testing.T) {
		e := newE2E(t, e2eOpts{})
		e.expectFail(e.do(http.MethodGet, e.callbackURL(url.Values{"code": {"x"}, "state": {"forged"}}), nil),
			http.StatusBadRequest, catStateCookie)
		if strings.Contains(e.logs.String(), `"hint"`) {
			t.Error("hostname hint logged although the host matches")
		}
	})
	t.Run("callback on a different hostname logs a hint", func(t *testing.T) {
		e := newE2E(t, e2eOpts{})
		req, _ := http.NewRequest(http.MethodGet, e.callbackURL(url.Values{"code": {"x"}, "state": {"s"}}), nil)
		req.Host = "other.example.com"
		resp, err := e.browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		e.expectFail(resp, http.StatusBadRequest, catStateCookie)
		if !strings.Contains(e.logs.String(), "different hostname than SYMBIONT_BASE_URL") {
			t.Errorf("no hostname hint in logs:\n%s", e.logs.String())
		}
	})
	t.Run("bad state: valid login state from another browser", func(t *testing.T) {
		e := newE2E(t, e2eOpts{})
		ssoURL, _ := e.startSSO(e.sp(e2eAdminEntity, e2eAdminACS), "")
		back := oidctestAuthorize(t, e.toIdP(ssoURL))
		// Attacker's browser (fresh jar) replays the victim's callback URL.
		jar, _ := cookiejar.New(nil)
		e.browser.Jar = jar
		e.expectFail(e.do(http.MethodGet, back.String(), nil), http.StatusBadRequest, catStateCookie)
		if e.pending.Len() != 1 {
			t.Error("a forged callback must not consume the real user's pending login")
		}
	})
	t.Run("replayed callback (state is single-use)", func(t *testing.T) {
		e := newE2E(t, e2eOpts{})
		ssoURL, _ := e.startSSO(e.sp(e2eAdminEntity, e2eAdminACS), "")
		authURL := e.toIdP(ssoURL)
		back := oidctestAuthorize(t, authURL)
		// Capture the binding cookie before the first callback clears it.
		u, _ := url.Parse(e.bridge.URL)
		saved := e.browser.Jar.Cookies(u)
		resp := e.do(http.MethodGet, back.String(), nil)
		_ = readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("first callback = %d", resp.StatusCode)
		}
		e.browser.Jar.SetCookies(u, saved) // attacker restores the cookie too
		e.expectFail(e.do(http.MethodGet, back.String(), nil), http.StatusBadRequest, catStateUnknown)
	})
	t.Run("expired login (state cookie and pending entry past TTL)", func(t *testing.T) {
		e := newE2E(t, e2eOpts{})
		ssoURL, _ := e.startSSO(e.sp(e2eAdminEntity, e2eAdminACS), "")
		back := oidctestAuthorize(t, e.toIdP(ssoURL))
		// The cookie jar keeps the cookie (wall clock), but its signed
		// expiry and the pending entry are both past PendingTTL.
		e.clk.advance(11 * time.Minute)
		e.expectFail(e.do(http.MethodGet, back.String(), nil), http.StatusBadRequest, catStateCookie)
		if _, err := e.pending.Take(t.Context(), back.Query().Get("state")); err == nil {
			t.Error("expired pending entry still redeemable")
		}
	})
	t.Run("expired pending entry with valid cookie", func(t *testing.T) {
		e := newE2E(t, e2eOpts{})
		ssoURL, _ := e.startSSO(e.sp(e2eAdminEntity, e2eAdminACS), "")
		back := oidctestAuthorize(t, e.toIdP(ssoURL))
		state := back.Query().Get("state")
		if _, err := e.pending.Take(t.Context(), state); err != nil { // simulate expiry/eviction
			t.Fatal(err)
		}
		e.expectFail(e.do(http.MethodGet, back.String(), nil), http.StatusBadRequest, catStateUnknown)
	})
	t.Run("idp error param", func(t *testing.T) {
		e := newE2E(t, e2eOpts{})
		ssoURL, _ := e.startSSO(e.sp(e2eAdminEntity, e2eAdminACS), "")
		back := oidctestAuthorize(t, e.toIdP(ssoURL))
		q := url.Values{"state": {back.Query().Get("state")}, "error": {"access_denied"}, "error_description": {"user cancelled"}}
		body := e.expectFail(e.do(http.MethodGet, e.callbackURL(q), nil), http.StatusForbidden, catIdPError)
		if strings.Contains(body, "user cancelled") || strings.Contains(body, "access_denied") {
			t.Error("IdP error details shown to user")
		}
		if e.pending.Len() != 0 {
			t.Error("state not consumed on IdP error")
		}
	})
	t.Run("missing code", func(t *testing.T) {
		e := newE2E(t, e2eOpts{})
		ssoURL, _ := e.startSSO(e.sp(e2eAdminEntity, e2eAdminACS), "")
		back := oidctestAuthorize(t, e.toIdP(ssoURL))
		q := url.Values{"state": {back.Query().Get("state")}}
		e.expectFail(e.do(http.MethodGet, e.callbackURL(q), nil), http.StatusBadRequest, catMissingParams)
	})
}

func TestE2EUpstreamFailures(t *testing.T) {
	t.Run("nonce mismatch", func(t *testing.T) {
		e := newE2E(t, e2eOpts{})
		ssoURL, _ := e.startSSO(e.sp(e2eAdminEntity, e2eAdminACS), "")
		authURL := e.toIdP(ssoURL)
		u, _ := url.Parse(authURL)
		q := u.Query()
		q.Set("nonce", "attacker-nonce") // IdP issues a token for another nonce
		u.RawQuery = q.Encode()
		e.expectFail(e.callback(u.String()), http.StatusBadGateway, "nonce_mismatch")
		if e.sessions.Len() != 0 {
			t.Error("session created despite nonce mismatch")
		}
	})
	t.Run("userinfo sub mismatch", func(t *testing.T) {
		e := newE2E(t, e2eOpts{fetchUserinfo: true})
		u := oidctest.Alice("fleet-admins")
		u.UserinfoClaims["sub"] = "someone-else"
		e.queueFirst(u)
		ssoURL, _ := e.startSSO(e.sp(e2eAdminEntity, e2eAdminACS), "")
		e.expectFail(e.callback(e.toIdP(ssoURL)), http.StatusBadGateway, "userinfo_sub_mismatch")
	})
}

// A full pending store is load, not a fault: 503 and a Warn with its own
// category, not a "store pending login" Error per rejected request. (The
// access log still records the 503 at ERROR, like every 5xx.)
func TestE2EPendingStoreFull(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	for i := range session.DefaultPendingMaxEntries {
		if err := e.pending.Put(t.Context(), strconv.Itoa(i), session.Pending{}); err != nil {
			t.Fatal(err)
		}
	}
	ssoURL, _ := e.startSSO(e.sp(e2eAdminEntity, e2eAdminACS), "")
	e.expectFail(e.do(http.MethodGet, ssoURL, nil), http.StatusServiceUnavailable, catPendingFull)
	if strings.Contains(e.logs.String(), `"msg":"store pending login"`) {
		t.Errorf("store-full logged at ERROR:\n%s", e.logs.String())
	}
}
