package idp

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func requireCategory(t *testing.T, err error, category string) *RequestError {
	t.Helper()
	var re *RequestError
	if !errors.As(err, &re) {
		t.Fatalf("err = %v (%T), want *RequestError %s", err, err, category)
	}
	if re.Category != category {
		t.Fatalf("category = %s (%v), want %s", re.Category, re.Err, category)
	}
	return re
}

func mustFail(_ *AuthnRequest, err error) error { return err }

func authnXML(issuer, acs, extra string) string {
	now := time.Now().UTC().Format(time.RFC3339)
	iss := ""
	if issuer != "" {
		iss = `<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` + issuer + `</saml:Issuer>`
	}
	acsAttr := ""
	if acs != "" {
		acsAttr = ` AssertionConsumerServiceURL="` + acs + `"`
	}
	return `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id-1" Version="2.0" IssueInstant="` +
		now + `"` + acsAttr + extra + `>` + iss + `</samlp:AuthnRequest>`
}

func postXML(x string) *http.Request {
	return rawPostRequest(base64.StdEncoding.EncodeToString([]byte(x)), "")
}

func TestUnknownEntityIDRejected(t *testing.T) {
	p := newTestIdP(t)
	sp := testSP(t, p, "https://unknown.example.com", adminACS)
	r, _ := redirectRequest(t, sp, "")
	re := requireCategory(t, mustFail(p.ParseRequest(r)), CategoryUnknownSP)
	if re.EntityID != "https://unknown.example.com" {
		t.Errorf("EntityID = %q", re.EntityID)
	}
}

func TestUnlistedACSRejected(t *testing.T) {
	p := newTestIdP(t)
	sp := testSP(t, p, adminEntityID, "https://evil.example.com/acs")
	r, _ := redirectRequest(t, sp, "")
	_ = requireCategory(t, mustFail(p.ParseRequest(r)), CategoryACSNotAllowed)
}

// An ACS URL belonging to SP A, requested by SP B, must be rejected.
func TestCrossSPACSRejected(t *testing.T) {
	p := newTestIdP(t)
	spB := testSP(t, p, mdmEntityID, adminACS)
	r, _ := redirectRequest(t, spB, "")
	re := requireCategory(t, mustFail(p.ParseRequest(r)), CategoryACSNotAllowed)
	if re.EntityID != mdmEntityID {
		t.Errorf("EntityID = %q", re.EntityID)
	}
}

func TestACSIndexHandling(t *testing.T) {
	p := newTestIdP(t)
	// Index 0 in metadata order is the IdP-initiated ACS (adminACS).
	req, err := p.ParseRequest(postXML(authnXML(adminEntityID, "", ` AssertionConsumerServiceIndex="0"`)))
	if err != nil {
		t.Fatal(err)
	}
	if req.ACSURL() != adminACS {
		t.Errorf("index 0 resolved to %q", req.ACSURL())
	}
	bad := postXML(authnXML(adminEntityID, "", ` AssertionConsumerServiceIndex="7"`))
	_ = requireCategory(t, mustFail(p.ParseRequest(bad)), CategoryACSNotAllowed)
}

func TestNoACSInRequestUsesDefault(t *testing.T) {
	p := newTestIdP(t)
	req, err := p.ParseRequest(postXML(authnXML(mdmEntityID, "", "")))
	if err != nil {
		t.Fatal(err)
	}
	if req.ACSURL() != mdmACS {
		t.Errorf("ACS = %q", req.ACSURL())
	}
}

func TestMalformedRequests(t *testing.T) {
	p := newTestIdP(t)
	valid := base64.StdEncoding.EncodeToString([]byte(authnXML(adminEntityID, adminACS, "")))
	plainB64 := url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("plain")))
	tests := []struct {
		name     string
		req      *http.Request
		category string
	}{
		{"missing issuer (crewjam would panic)", postXML(authnXML("", adminACS, "")), CategoryMalformed},
		{"missing SAMLRequest", rawPostRequest("", ""), CategoryMalformed},
		{"bad base64", rawPostRequest("!!!", ""), CategoryMalformed},
		{"not xml", postXML("hello"), CategoryMalformed},
		{"bad deflate", httptest.NewRequest(http.MethodGet, testBase+"/sso?SAMLRequest="+plainB64, nil), CategoryMalformed},
		{"wrong version", postXML(strings.Replace(authnXML(adminEntityID, adminACS, ""), `Version="2.0"`, `Version="1.1"`, 1)), CategoryInvalid},
		{"wrong destination", postXML(authnXML(adminEntityID, adminACS, ` Destination="https://other.example.com/sso"`)), CategoryInvalid},
		{"relay state too long", rawPostRequest(valid, strings.Repeat("a", 81)), CategoryRelayState},
		{"relay state control char", rawPostRequest(valid, "a\nb"), CategoryRelayState},
		{"method", httptest.NewRequest(http.MethodPut, testBase+"/sso", nil), CategoryMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_ = requireCategory(t, mustFail(p.ParseRequest(tc.req)), tc.category)
		})
	}
}

func TestStaleRequestRejectedButReplayableAtReceivedTime(t *testing.T) {
	p := newTestIdP(t)
	sp := testSP(t, p, adminEntityID, adminACS)
	r, _ := redirectRequest(t, sp, "")
	req, err := p.ParseRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	// Judged at its original receive time, a replay is accepted (phase 3
	// replays the request after the upstream OIDC login).
	if _, err := p.ParseXML(r, req.RawXML, "", req.ReceivedAt); err != nil {
		t.Errorf("replay at ReceivedAt rejected: %v", err)
	}
	// Judged later, crewjam's IssueInstant freshness check rejects it.
	_, err = p.ParseXML(r, req.RawXML, "", req.ReceivedAt.Add(5*time.Minute))
	re := requireCategory(t, err, CategoryInvalid)
	if !strings.Contains(re.Err.Error(), "expired") {
		t.Errorf("err = %v", re.Err)
	}
}
