package server

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/crewjam/saml"

	"github.com/kc9wwh/symbiont-sso/internal/web"
)

var (
	inlineHandlerRE      = regexp.MustCompile(`\son[a-z]+\s*=`)
	crewjamSAMLRequestRE = regexp.MustCompile(`name="SAMLRequest" value="([^"]*)"`)
)

// TestSSOResponsePageCSP is the required phase 2 CSP test: the per-response
// CSP on the SSO page must allow exactly the page's inline script (by hash)
// and only the ACS origin as form-action, overriding the strict default.
func TestSSOResponsePageCSP(t *testing.T) {
	f := newSAMLFixture(t, fixedSessions{testUser()})
	r, _ := fleetRedirect(t, f.sp(t, adminACS), "")
	rec := f.do(r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	cspValues := rec.Header().Values(web.CSPHeader)
	if len(cspValues) != 1 {
		t.Fatalf("want exactly one CSP header, got %q", cspValues)
	}
	csp := cspDirectives(cspValues[0])

	scripts := scriptRE.FindAllStringSubmatch(body, -1)
	if len(scripts) != 1 {
		t.Fatalf("want exactly one inline script, got %d", len(scripts))
	}
	if got, want := csp["script-src"], web.ScriptHash(scripts[0][1]); !slices.Equal(got, []string{want}) {
		t.Errorf("script-src = %v, want only %s (hash of the rendered script)", got, want)
	}
	styles := styleRE.FindAllStringSubmatch(body, -1)
	if len(styles) != 1 || !slices.Equal(csp["style-src"], []string{web.ScriptHash(styles[0][1])}) {
		t.Errorf("style-src = %v does not match rendered style", csp["style-src"])
	}
	if got := csp["form-action"]; !slices.Equal(got, []string{"https://fleet.example.com"}) {
		t.Errorf("form-action = %v, want ACS origin only", got)
	}
	for d, want := range map[string]string{"default-src": "'none'", "frame-ancestors": "'none'", "base-uri": "'none'"} {
		if !slices.Equal(csp[d], []string{want}) {
			t.Errorf("%s = %v, want %s", d, csp[d], want)
		}
	}
	if strings.Contains(cspValues[0], "unsafe-") {
		t.Errorf("CSP must not use unsafe-*: %s", cspValues[0])
	}
	if inlineHandlerRE.MatchString(body) {
		t.Errorf("page contains inline event handlers, which the CSP would block")
	}
	if m := actionRE.FindStringSubmatch(body); m == nil || html.UnescapeString(m[1]) != adminACS {
		t.Errorf("form action = %v, want %s", m, adminACS)
	}
	if !strings.Contains(body, "<noscript>") {
		t.Errorf("missing <noscript> fallback")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("baseline security headers missing")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("SAML response page must not be cached")
	}
}

// postFields extracts the hidden inputs from a rendered POST-binding page.
func postFields(body string) map[string]string {
	fields := map[string]string{}
	for _, m := range inputRE.FindAllStringSubmatch(body, -1) {
		fields[m[1]] = html.UnescapeString(m[2])
	}
	return fields
}

// deliver posts the rendered form to the SP's ACS as a browser would and
// returns the validated assertion.
func deliver(t *testing.T, rec *httptest.ResponseRecorder, sp *saml.ServiceProvider, reqID, wantRelay string) *saml.Assertion {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	m := actionRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no form in page: %s", body)
	}
	fields := postFields(body)
	if fields["RelayState"] != wantRelay {
		t.Errorf("RelayState = %q, want %q", fields["RelayState"], wantRelay)
	}
	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}
	r := httptest.NewRequest(http.MethodPost, html.UnescapeString(m[1]), strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r.ParseForm()
	a, err := sp.ParseResponse(r, []string{reqID})
	if err != nil {
		if ire, ok := err.(*saml.InvalidResponseError); ok {
			t.Fatalf("SP rejected response: %v", ire.PrivateErr)
		}
		t.Fatalf("SP rejected response: %v", err)
	}
	return a
}

// TestSSOEndToEnd delivers the rendered page to a crewjam SP for both
// request bindings.
func TestSSOEndToEnd(t *testing.T) {
	f := newSAMLFixture(t, fixedSessions{testUser()})
	sp := f.sp(t, adminACS)

	t.Run("redirect binding", func(t *testing.T) {
		r, reqID := fleetRedirect(t, sp, "relay-123")
		a := deliver(t, f.do(r), sp, reqID, "relay-123")
		if a.Subject.NameID.Value != "alice@example.com" {
			t.Errorf("NameID = %q", a.Subject.NameID.Value)
		}
	})
	t.Run("post binding", func(t *testing.T) {
		ar, err := sp.MakeAuthenticationRequest(base+"/sso", saml.HTTPPostBinding, saml.HTTPPostBinding)
		if err != nil {
			t.Fatal(err)
		}
		// crewjam's SP-side AuthnRequest.Post renders `<input ... />`, which
		// differs from our page markup, so extract the field directly.
		m := crewjamSAMLRequestRE.FindStringSubmatch(string(ar.Post("")))
		if m == nil {
			t.Fatal("no SAMLRequest in crewjam POST form")
		}
		form := url.Values{"SAMLRequest": {html.UnescapeString(m[1])}}
		r := httptest.NewRequest(http.MethodPost, base+"/sso", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		deliver(t, f.do(r), sp, ar.ID, "")
	})
	if !strings.Contains(f.logs.String(), `"msg":"sso success"`) || !strings.Contains(f.logs.String(), `"sp_id":"fleet-admin"`) {
		t.Errorf("success not logged with sp_id: %s", f.logs.String())
	}
}
