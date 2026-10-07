package idp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crewjam/saml"
)

// unsolicited issues an IdP-initiated response to fleet-admin.
func unsolicited(t *testing.T, p *IdP, relay string, attrs ...Attribute) *PostForm {
	t.Helper()
	sp, _ := p.SPs().ByID("fleet-admin")
	req, err := p.IdPInitiated(httptest.NewRequest(http.MethodGet, "/login/fleet-admin", nil), sp, relay)
	if err != nil {
		t.Fatal(err)
	}
	form, err := p.Respond(req, testIdentity(), attrs)
	if err != nil {
		t.Fatal(err)
	}
	return form
}

func TestIdPInitiatedResponse(t *testing.T) {
	p := newTestIdP(t)
	form := unsolicited(t, p, "rs", Attribute{Name: "FLEET_JIT_USER_ROLE_GLOBAL", Value: "admin"})

	// Posted to idp_initiated.acs_url, NOT the first-configured ACS
	// (harness lists adminACS2 first).
	if form.Action != adminACS {
		t.Fatalf("action = %q, want idp_initiated.acs_url %q", form.Action, adminACS)
	}
	if form.RelayState != "rs" {
		t.Errorf("RelayState = %q", form.RelayState)
	}

	sp := testSP(t, p, adminEntityID, adminACS)
	sp.AllowIDPInitiated = true
	a, err := sp.ParseResponse(acsPost(form), nil)
	if err != nil {
		var ire *saml.InvalidResponseError
		errors.As(err, &ire)
		t.Fatalf("AllowIDPInitiated SP rejected: %v", ire.PrivateErr)
	}
	if got := a.Conditions.AudienceRestrictions; len(got) != 1 || got[0].Audience.Value != adminEntityID {
		t.Errorf("audience = %+v", got)
	}
	sc := a.Subject.SubjectConfirmations[0].SubjectConfirmationData
	if sc.InResponseTo != "" || sc.Recipient != adminACS {
		t.Errorf("SubjectConfirmationData = %+v (want no InResponseTo)", sc)
	}
	if d := sc.NotOnOrAfter.Sub(a.IssueInstant); d != saml.MaxIssueDelay {
		t.Errorf("validity = %v, want %v", d, saml.MaxIssueDelay)
	}
	if strings.Contains(string(mustB64(t, form.SAMLResponse)), "InResponseTo") {
		t.Error("unsolicited Response carries InResponseTo")
	}

	// The same Response is rejected by an SP that does not allow
	// IdP-initiated logins (Fleet with enable_sso_idp_login: false).
	strict := testSP(t, p, adminEntityID, adminACS)
	if _, err := strict.ParseResponse(acsPost(form), []string{"id-some-request"}); err == nil {
		t.Fatal("SP without AllowIDPInitiated accepted an unsolicited response")
	}
}

func TestIdPInitiatedRequestValidation(t *testing.T) {
	p := newTestIdP(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	admin, _ := p.SPs().ByID("fleet-admin")
	mdm, _ := p.SPs().ByID("fleet-enduser")
	if _, err := p.IdPInitiated(r, mdm, ""); err == nil {
		t.Error("disabled SP accepted")
	}
	_, err := p.IdPInitiated(r, admin, strings.Repeat("x", 81))
	_ = requireCategory(t, err, CategoryRelayState)
}
