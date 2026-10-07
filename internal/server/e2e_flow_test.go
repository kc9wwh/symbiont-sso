package server

import (
	"encoding/xml"
	"net/http"
	"net/url"

	"github.com/crewjam/saml"
)

func samlParseMetadata(raw []byte) (*saml.EntityDescriptor, error) {
	var md saml.EntityDescriptor
	return &md, xml.Unmarshal(raw, &md)
}

// toIdP follows /sso to the identity provider and returns the authorize URL.
func (e *e2e) toIdP(ssoURL string) string {
	e.t.Helper()
	resp := e.do(http.MethodGet, ssoURL, nil)
	_ = readBody(e.t, resp)
	if resp.StatusCode != http.StatusFound {
		e.t.Fatalf("/sso status = %d, want redirect to IdP\nlogs:\n%s", resp.StatusCode, e.logs.String())
	}
	return resp.Header.Get("Location")
}

// callback lets the mock IdP authenticate and returns the callback response.
func (e *e2e) callback(authURL string) *http.Response {
	e.t.Helper()
	back := oidctestAuthorize(e.t, authURL)
	return e.do(http.MethodGet, back.String(), nil)
}

// replay submits the post-login replay page and returns the /sso response.
func (e *e2e) replay(resp *http.Response) *http.Response {
	e.t.Helper()
	body := readBody(e.t, resp)
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("callback status = %d\n%s\nlogs:\n%s", resp.StatusCode, body, e.logs.String())
	}
	action, fields := formFields(e.t, body)
	return e.do(http.MethodPost, e.abs(action), fields)
}

// deliver posts the SAML response page to the SP and returns the assertion.
func (e *e2e) deliver(resp *http.Response, sp *saml.ServiceProvider, reqID string) (*saml.Assertion, url.Values) {
	e.t.Helper()
	body := readBody(e.t, resp)
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("/sso status = %d\n%s\nlogs:\n%s", resp.StatusCode, body, e.logs.String())
	}
	action, fields := formFields(e.t, body)
	if action != sp.AcsURL.String() {
		e.t.Fatalf("form posts to %q, want %q", action, sp.AcsURL.String())
	}
	r, _ := http.NewRequest(http.MethodPost, action, nil)
	r.PostForm = fields
	r.Form = fields
	a, err := sp.ParseResponse(r, []string{reqID})
	if err != nil {
		if ire, ok := err.(*saml.InvalidResponseError); ok {
			e.t.Fatalf("SP rejected response: %v", ire.PrivateErr)
		}
		e.t.Fatal(err)
	}
	return a, fields
}

// fullLogin runs SP-initiated SSO from scratch through the replay.
func (e *e2e) fullLogin(sp *saml.ServiceProvider, relay string) (*saml.Assertion, url.Values) {
	e.t.Helper()
	ssoURL, reqID := e.startSSO(sp, relay)
	return e.deliver(e.replay(e.callback(e.toIdP(ssoURL))), sp, reqID)
}
