package server

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/crewjam/saml"

	"github.com/kc9wwh/symbiont-sso/internal/oidcrp/oidctest"
)

func oidctestAuthorize(t *testing.T, authURL string) *url.URL { return oidctest.Authorize(t, authURL) }

// deflatedToRaw converts an HTTP-Redirect SAMLRequest (deflate+base64) into
// the HTTP-POST encoding (base64 of the raw XML).
func deflatedToRaw(t *testing.T, redirectValue string) string {
	t.Helper()
	compressed, err := base64.StdEncoding.DecodeString(redirectValue)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(flate.NewReader(bytes.NewReader(compressed)))
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// startSSO builds a Fleet-style HTTP-Redirect AuthnRequest and returns the
// /sso URL and request ID.
func (e *e2e) startSSO(sp *saml.ServiceProvider, relay string) (string, string) {
	ar, err := sp.MakeAuthenticationRequest(e.idp.SSOURL(), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		e.t.Fatal(err)
	}
	u, err := ar.Redirect(relay, sp)
	if err != nil {
		e.t.Fatal(err)
	}
	return u.String(), ar.ID
}

// do sends a request with the browser's cookie jar.
func (e *e2e) do(method, target string, form url.Values) *http.Response {
	e.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := e.browser.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// formFields parses an auto-submit page's action and hidden inputs.
func formFields(t *testing.T, body string) (string, url.Values) {
	t.Helper()
	m := actionRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no form in page:\n%s", body)
	}
	v := url.Values{}
	for _, f := range inputRE.FindAllStringSubmatch(body, -1) {
		v.Set(f[1], html.UnescapeString(f[2]))
	}
	return html.UnescapeString(m[1]), v
}

func (e *e2e) abs(target string) string {
	if strings.HasPrefix(target, "/") {
		return e.bridge.URL + target
	}
	return target
}
