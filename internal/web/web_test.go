package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScriptHashKnownVector(t *testing.T) {
	// echo -n 'alert(1)' | openssl dgst -sha256 -binary | base64
	if got := ScriptHash("alert(1)"); got != "'sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI='" {
		t.Errorf("ScriptHash = %s", got)
	}
}

func TestOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://fleet.example.com/api/v1/fleet/sso/callback": "https://fleet.example.com",
		"https://fleet.example.com:8443/x?y=1":                "https://fleet.example.com:8443",
		"http://localhost:8080/acs":                           "http://localhost:8080",
	} {
		if got, err := Origin(in); err != nil || got != want {
			t.Errorf("Origin(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"/relative", "", "not a url", "%zz"} {
		if _, err := Origin(bad); err == nil {
			t.Errorf("Origin(%q) accepted", bad)
		}
	}
}

func TestWritePostFormEscapesValues(t *testing.T) {
	rec := httptest.NewRecorder()
	err := WritePostForm(rec, PostFormPage{
		Action:     `https://sp.example.com/acs?a=1&b="2"`,
		FormAction: "https://sp.example.com",
		Fields:     []Field{{"RelayState", `"><script>alert(1)</script>`}},
		Title:      "<b>x</b>",
	})
	if err != nil {
		t.Fatal(err)
	}
	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(1)") || strings.Contains(body, "<b>x</b>") {
		t.Fatalf("unescaped content in page: %s", body)
	}
	if strings.Count(body, "<script>") != 1 {
		t.Errorf("want exactly one script element")
	}
	if !strings.Contains(rec.Header().Get(CSPHeader), "script-src "+AutoSubmitScriptHash()) {
		t.Errorf("CSP = %s", rec.Header().Get(CSPHeader))
	}
	if !strings.Contains(rec.Header().Get(CSPHeader), "form-action https://sp.example.com") {
		t.Errorf("CSP = %s", rec.Header().Get(CSPHeader))
	}
}

func TestWritePostFormSelf(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := WritePostForm(rec, PostFormPage{Action: "/sso", FormAction: "'self'"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.Header().Get(CSPHeader), "form-action 'self'") {
		t.Errorf("CSP = %s", rec.Header().Get(CSPHeader))
	}
	if !strings.Contains(rec.Body.String(), "Signing you in") {
		t.Errorf("default title missing")
	}
}

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set(CSPHeader, DefaultCSP)
	WriteError(rec, ErrorPage{Status: http.StatusForbidden, Message: "<nope>", RequestID: "abc"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "<nope>") || !strings.Contains(body, "&lt;nope&gt;") {
		t.Errorf("message not escaped: %s", body)
	}
	if !strings.Contains(body, "<title>Forbidden</title>") || !strings.Contains(body, "Reference: abc") {
		t.Errorf("body = %s", body)
	}
	csp := rec.Header().Get(CSPHeader)
	if strings.Contains(csp, "script-src") || !strings.Contains(csp, "form-action 'none'") || !strings.Contains(csp, "style-src 'sha256-") {
		t.Errorf("error CSP = %s", csp)
	}
	if len(rec.Header().Values(CSPHeader)) != 1 {
		t.Errorf("CSP header duplicated")
	}
	rec = httptest.NewRecorder()
	WriteError(rec, ErrorPage{})
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("default status = %d", rec.Code)
	}
}
