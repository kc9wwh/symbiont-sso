package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/crewjam/saml"

	"github.com/kc9wwh/symbiont-sso/internal/config"
)

func attrMap(a *saml.Assertion) map[string][]string {
	m := map[string][]string{}
	for _, st := range a.AttributeStatements {
		for _, at := range st.Attributes {
			for _, v := range at.Values {
				m[at.Name] = append(m[at.Name], v.Value)
			}
		}
	}
	return m
}

// expectDenied checks a 403 access-denied page with no SAML response.
func (e *e2e) expectDenied(resp *http.Response, displayName string) {
	e.t.Helper()
	body := readBody(e.t, resp)
	if resp.StatusCode != http.StatusForbidden {
		e.t.Fatalf("status = %d, want 403\n%s\nlogs:\n%s", resp.StatusCode, body, e.logs.String())
	}
	if !strings.Contains(body, "have access to "+displayName) || strings.Contains(body, "SAMLResponse") {
		e.t.Errorf("page = %s", body)
	}
}

// MANDATORY: an employee who signed in to fleet-enduser must NOT get a
// fleet-admin assertion by reusing that bridge session, and the denial
// must not destroy the session or bounce to the IdP.
func TestE2ECrossSPSessionReuseDenied(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	e.queueFirst(employeeUser)
	enduser := e.sp(e2eMDMEntity, e2eMDMACS)
	a, _ := e.fullLogin(enduser, "")
	if a.Subject.NameID.Value != "emp@example.com" {
		t.Fatalf("NameID = %q", a.Subject.NameID.Value)
	}
	sessionBefore := e.sessionCookie().Value

	ssoURL, _ := e.startSSO(e.sp(e2eAdminEntity, e2eAdminACS), "")
	e.expectDenied(e.do(http.MethodGet, ssoURL, nil), "Fleet")
	logs := e.logs.String()
	for _, want := range []string{`"msg":"access denied"`, `"level":"WARN"`, `"sp_id":"fleet-admin"`,
		`"email":"emp@example.com"`, `"reason":"no_matching_group"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs missing %s", want)
		}
	}

	// Session kept: still valid for fleet-enduser, without the IdP.
	if c := e.sessionCookie(); c == nil || c.Value != sessionBefore || e.sessions.Len() != 1 {
		t.Fatal("denial cleared or replaced the bridge session")
	}
	ssoURL, reqID := e.startSSO(enduser, "")
	resp := e.do(http.MethodGet, ssoURL, nil)
	if resp.StatusCode == http.StatusFound {
		t.Fatal("session reuse for an allowed SP redirected to the IdP")
	}
	if b, _ := e.deliver(resp, enduser, reqID); b.Subject.NameID.Value != "emp@example.com" {
		t.Errorf("NameID = %q", b.Subject.NameID.Value)
	}

	// Repeating the denied request is still a 403 from the session, never
	// a redirect to the IdP (no loop).
	ssoURL, _ = e.startSSO(e.sp(e2eAdminEntity, e2eAdminACS), "")
	e.expectDenied(e.do(http.MethodGet, ssoURL, nil), "Fleet")
	if n := strings.Count(e.logs.String(), `"msg":"redirecting to identity provider"`); n != 1 {
		t.Errorf("IdP redirects = %d, want 1 (initial login only)", n)
	}
}

// A fresh login straight to a denied SP: the upstream login succeeds, the
// replay is denied, and no assertion is issued.
func TestE2EDeniedAfterFreshLogin(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	e.queueFirst(employeeUser)
	ssoURL, _ := e.startSSO(e.sp(e2eAdminEntity, e2eAdminACS), "")
	e.expectDenied(e.replay(e.callback(e.toIdP(ssoURL))), "Fleet")
	if e.sessions.Len() != 1 {
		t.Error("session not kept after denial")
	}
}

// An admin's fleet-admin assertion carries the mapped role; the same
// session's fleet-enduser assertion carries no role attributes.
func TestE2EPerSPMapping(t *testing.T) {
	e := newE2E(t, e2eOpts{})
	admin := e.sp(e2eAdminEntity, e2eAdminACS)
	a, _ := e.fullLogin(admin, "")
	attrs := attrMap(a)
	if got := attrs["FLEET_JIT_USER_ROLE_GLOBAL"]; len(got) != 1 || got[0] != "admin" {
		t.Errorf("admin role = %v, want single value admin", got)
	}
	for _, at := range a.AttributeStatements[0].Attributes {
		if at.Name == "FLEET_JIT_USER_ROLE_GLOBAL" && at.NameFormat != "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" {
			t.Errorf("NameFormat = %q", at.NameFormat)
		}
	}
	if !strings.Contains(e.logs.String(), `"fleet_role_attributes":["FLEET_JIT_USER_ROLE_GLOBAL"]`) {
		t.Error("role attribute names not logged")
	}
	if strings.Contains(e.logs.String(), `"admin"`) && strings.Contains(e.logs.String(), `"FLEET_JIT_USER_ROLE_GLOBAL":"admin"`) {
		t.Error("role values logged at info")
	}

	enduser := e.sp(e2eMDMEntity, e2eMDMACS)
	ssoURL, reqID := e.startSSO(enduser, "")
	b, _ := e.deliver(e.do(http.MethodGet, ssoURL, nil), enduser, reqID)
	for name := range attrMap(b) {
		if name != "email" && name != "name" {
			t.Errorf("fleet-enduser assertion carries %q", name)
		}
	}
	for _, aud := range b.Conditions.AudienceRestrictions {
		if aud.Audience.Value != e2eMDMEntity {
			t.Errorf("enduser assertion audience includes %q", aud.Audience.Value)
		}
	}
}

func TestE2ERoleConflictRejected(t *testing.T) {
	sps := defaultE2ESPs(t)
	sps[0].Access.AllowGroups = append(sps[0].Access.AllowGroups, "workstations-maint")
	sps[0].Attributes = append(sps[0].Attributes, roleRule("FLEET_JIT_USER_ROLE_FLEET_2", "workstations-maint", "maintainer"))
	e := newE2E(t, e2eOpts{sps: sps})
	e.queueFirst(memberOf("both", "fleet-admins", "workstations-maint"))
	ssoURL, _ := e.startSSO(e.sp(e2eAdminEntity, e2eAdminACS), "")
	resp := e.replay(e.callback(e.toIdP(ssoURL)))
	body := e.expectFail(resp, http.StatusForbidden, "fleet_role_conflict")
	if !strings.Contains(body, "conflicting Fleet roles: user matched both global and fleet-level role rules") {
		t.Errorf("page = %s", body)
	}
}

// An invalid role arriving via a passthrough claim rejects the login; the
// log names the claim/attribute but never the value.
func TestE2EInvalidPassthroughRoleLogsNameOnly(t *testing.T) {
	sps := defaultE2ESPs(t)
	sps[0].PassthroughPrefixes = []string{"FLEET_JIT_USER_ROLE_FLEET_"}
	e := newE2E(t, e2eOpts{sps: sps})
	e.queueFirst(oidctestMember("pt", []string{"fleet-maintainers"},
		map[string]any{"FLEET_JIT_USER_ROLE_FLEET_4": "s3cret-bogus-role"}))
	ssoURL, _ := e.startSSO(e.sp(e2eAdminEntity, e2eAdminACS), "")
	body := e.expectFail(e.replay(e.callback(e.toIdP(ssoURL))), http.StatusForbidden, "invalid_fleet_role")
	logs := e.logs.String()
	for _, want := range []string{`"attribute":"FLEET_JIT_USER_ROLE_FLEET_4"`, `"claim":"FLEET_JIT_USER_ROLE_FLEET_4"`, `"attribute_source":"passthrough"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs missing %s:\n%s", want, logs)
		}
	}
	if strings.Contains(logs, "s3cret-bogus-role") || strings.Contains(body, "s3cret-bogus-role") {
		t.Error("claim value leaked to logs or page")
	}
}

func TestE2EAllowEmailsAndAllowAll(t *testing.T) {
	sps := defaultE2ESPs(t)
	sps[0].Access = config.AccessPolicy{AllowEmails: []string{"breakglass@example.com"}}
	sps[1].Access = config.AccessPolicy{AllowAll: true}
	e := newE2E(t, e2eOpts{sps: sps})

	e.queueFirst(memberOf("breakglass")) // in no groups at all
	if a, _ := e.fullLogin(e.sp(e2eAdminEntity, e2eAdminACS), ""); a.Subject.NameID.Value != "breakglass@example.com" {
		t.Errorf("allow_emails: NameID = %q", a.Subject.NameID.Value)
	}

	e2 := newE2E(t, e2eOpts{sps: sps})
	e2.queueFirst(memberOf("nobody"))
	if a, _ := e2.fullLogin(e2.sp(e2eMDMEntity, e2eMDMACS), ""); a.Subject.NameID.Value != "nobody@example.com" {
		t.Errorf("allow_all: NameID = %q", a.Subject.NameID.Value)
	}
	ssoURL, _ := e2.startSSO(e2.sp(e2eAdminEntity, e2eAdminACS), "")
	e2.expectDenied(e2.do(http.MethodGet, ssoURL, nil), "Fleet")
	if !strings.Contains(e2.logs.String(), `"reason":"email_not_allowed"`) {
		t.Error("missing email_not_allowed reason")
	}
}
