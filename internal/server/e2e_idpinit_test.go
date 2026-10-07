package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/crewjam/saml"

	"github.com/kc9wwh/symbiont-sso/internal/web"
)

func (e *e2e) loginURL(spID, relay string) string {
	u := e.bridge.URL + LoginPathPrefix + spID
	if relay != "" {
		u += "?" + url.Values{"RelayState": {relay}}.Encode()
	}
	return u
}

// deliverUnsolicited validates an IdP-initiated response page at sp.
func (e *e2e) deliverUnsolicited(resp *http.Response, sp *saml.ServiceProvider) (*saml.Assertion, url.Values, error) {
	e.t.Helper()
	body := readBody(e.t, resp)
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("status = %d\n%s\nlogs:\n%s", resp.StatusCode, body, e.logs.String())
	}
	action, fields := formFields(e.t, body)
	if action != e2eAdminACS {
		e.t.Fatalf("posted to %q, want idp_initiated.acs_url %q", action, e2eAdminACS)
	}
	csp := cspDirectives(resp.Header.Get(web.CSPHeader))
	scripts := scriptRE.FindAllStringSubmatch(body, -1)
	if len(scripts) != 1 || len(csp["script-src"]) != 1 || csp["script-src"][0] != web.ScriptHash(scripts[0][1]) ||
		len(csp["form-action"]) != 1 || csp["form-action"][0] != "https://fleet.example.com" {
		e.t.Errorf("CSP = %v", csp)
	}
	r, _ := http.NewRequest(http.MethodPost, action, nil)
	r.PostForm, r.Form = fields, fields
	a, err := sp.ParseResponse(r, nil)
	return a, fields, err
}

func idpSP(e *e2e, allow bool) *saml.ServiceProvider {
	sp := e.sp(e2eAdminEntity, e2eAdminACS)
	sp.AllowIDPInitiated = allow
	return sp
}

// Allowed user with an existing session: the unsolicited Response
// validates at an SP that allows IdP-initiated login, and is rejected by one
// that does not (Fleet's enable_sso_idp_login gate).
func TestE2EIdPInitiatedWithSession(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	spAssertion, _ := e.fullLogin(e.sp(e2eAdminEntity, e2eAdminACS), "") // establishes the session

	resp := e.do(http.MethodGet, e.loginURL("fleet-admin", "dash"), nil)
	if resp.StatusCode == http.StatusFound {
		t.Fatal("existing session should not redirect to the IdP")
	}
	a, fields, err := e.deliverUnsolicited(resp, idpSP(e, true))
	if err != nil {
		t.Fatalf("AllowIDPInitiated SP rejected: %v", privateErr(err))
	}
	if fields.Get("RelayState") != "dash" {
		t.Errorf("RelayState = %q", fields.Get("RelayState"))
	}
	sc := a.Subject.SubjectConfirmations[0].SubjectConfirmationData
	if sc.InResponseTo != "" || sc.Recipient != e2eAdminACS {
		t.Errorf("SubjectConfirmationData = %+v", sc)
	}
	if aud := a.Conditions.AudienceRestrictions; len(aud) != 1 || aud[0].Audience.Value != e2eAdminEntity {
		t.Errorf("audience = %+v", aud)
	}
	if d := sc.NotOnOrAfter.Sub(a.IssueInstant); d != saml.MaxIssueDelay {
		t.Errorf("validity = %v", d)
	}
	// Role attributes identical to the SP-initiated assertion.
	idpAttrs, spAttrs := attrMap(a), attrMap(spAssertion)
	if len(idpAttrs) != len(spAttrs) || len(idpAttrs["FLEET_JIT_USER_ROLE_GLOBAL"]) != 1 ||
		idpAttrs["FLEET_JIT_USER_ROLE_GLOBAL"][0] != "admin" || spAttrs["FLEET_JIT_USER_ROLE_GLOBAL"][0] != "admin" {
		t.Errorf("IdP-initiated attrs %v != SP-initiated attrs %v", idpAttrs, spAttrs)
	}
	if !strings.Contains(e.logs.String(), `"flow":"idp"`) {
		t.Error("flow=idp not logged")
	}

	// Same flow, SP with AllowIDPInitiated=false: rejected.
	resp = e.do(http.MethodGet, e.loginURL("fleet-admin", ""), nil)
	if _, _, err := e.deliverUnsolicited(resp, idpSP(e, false)); err == nil {
		t.Fatal("SP without AllowIDPInitiated accepted an unsolicited response")
	}
}

// Allowed user without a session: /login -> IdP -> callback -> back to
// /login/{sp_id} (not /sso) -> unsolicited Response.
func TestE2EIdPInitiatedNoSession(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	resp := e.do(http.MethodGet, e.loginURL("fleet-admin", "rs-1"), nil)
	_ = readBody(t, resp)
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), e.oidc.AuthorizationEndpoint()) {
		t.Fatalf("want IdP redirect, got %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	cb := e.callback(resp.Header.Get("Location"))
	_ = readBody(t, cb)
	loc := cb.Header.Get("Location")
	if cb.StatusCode != http.StatusFound || !strings.HasPrefix(loc, "/login/fleet-admin?") || strings.Contains(loc, "/sso") {
		t.Fatalf("callback = %d %q, want redirect to /login/fleet-admin", cb.StatusCode, loc)
	}
	a, fields, err := e.deliverUnsolicited(e.do(http.MethodGet, e.abs(loc), nil), idpSP(e, true))
	if err != nil {
		t.Fatalf("unsolicited response rejected: %v", privateErr(err))
	}
	if a.Subject.NameID.Value != "admin@example.com" || fields.Get("RelayState") != "rs-1" {
		t.Errorf("NameID=%q RelayState=%q", a.Subject.NameID.Value, fields.Get("RelayState"))
	}
	if n := strings.Count(e.logs.String(), `"msg":"redirecting to identity provider"`); n != 1 {
		t.Errorf("IdP redirects = %d, want 1", n)
	}
}
