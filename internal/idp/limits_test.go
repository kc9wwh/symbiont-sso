package idp

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/crewjam/saml"
)

func TestDeflateBombBounded(t *testing.T) {
	p := newTestIdP(t, nil)
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = fw.Write(bytes.Repeat([]byte("A"), 10<<20)) // 10 MB from ~10 KB
	_ = fw.Close()
	q := url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
	r := httptest.NewRequest(http.MethodGet, testBase+"/sso?SAMLRequest="+q, nil)
	_ = requireCategory(t, mustFail(p.ParseRequest(r)), CategoryTooLarge)
}

func TestOversizedQueryRejected(t *testing.T) {
	p := newTestIdP(t, nil)
	r := httptest.NewRequest(http.MethodGet, testBase+"/sso?SAMLRequest="+strings.Repeat("A", MaxRequestBytes+1), nil)
	_ = requireCategory(t, mustFail(p.ParseRequest(r)), CategoryTooLarge)
}

func TestOversizedPostRejected(t *testing.T) {
	p := newTestIdP(t, nil)
	r := rawPostRequest(strings.Repeat("A", MaxRequestBytes+1), "")
	r.Body = http.MaxBytesReader(httptest.NewRecorder(), r.Body, MaxRequestBytes)
	_ = requireCategory(t, mustFail(p.ParseRequest(r)), CategoryTooLarge)
}

func TestOversizedDecodedXMLRejected(t *testing.T) {
	p := newTestIdP(t, nil)
	big := make([]byte, MaxRequestBytes+1)
	if _, err := p.ParseXML(httptest.NewRequest(http.MethodGet, "/", nil), big, "", p.now()); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidRelayState(t *testing.T) {
	for s, want := range map[string]bool{
		"":                          true,
		"fleet":                     true,
		strings.Repeat("x", 80):     true,
		strings.Repeat("x", 81):     false,
		"tab\there":                 false,
		"caf\u00e9":                 false,
		"/path?q=1&r=https://x.y/z": true,
	} {
		if got := ValidRelayState(s); got != want {
			t.Errorf("ValidRelayState(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestMetadata(t *testing.T) {
	p := newTestIdP(t, nil)
	md := p.Metadata()
	if md.EntityID != testBase+MetadataPath || p.EntityID() != md.EntityID {
		t.Errorf("EntityID = %q", md.EntityID)
	}
	d := md.IDPSSODescriptors[0]
	if len(d.KeyDescriptors) != 1 || d.KeyDescriptors[0].Use != "signing" {
		t.Errorf("KeyDescriptors = %+v, want only signing", d.KeyDescriptors)
	}
	if len(d.NameIDFormats) != 1 || d.NameIDFormats[0] != saml.EmailAddressNameIDFormat {
		t.Errorf("NameIDFormats = %v", d.NameIDFormats)
	}
	bindings := map[string]string{}
	for _, s := range d.SingleSignOnServices {
		bindings[s.Binding] = s.Location
	}
	if bindings[saml.HTTPRedirectBinding] != p.SSOURL() || bindings[saml.HTTPPostBinding] != p.SSOURL() {
		t.Errorf("SSO services = %v", bindings)
	}
	if len(d.SingleLogoutServices) != 0 {
		t.Errorf("SLO must not be advertised")
	}
	raw, err := p.MetadataXML()
	if err != nil || !bytes.HasPrefix(raw, []byte("<?xml")) {
		t.Errorf("MetadataXML: %v", err)
	}
}

func TestNewServiceProvidersRejectsDuplicates(t *testing.T) {
	sps := testSPConfigs()
	sps[1].EntityID = sps[0].EntityID
	if _, err := NewServiceProviders(sps); err == nil {
		t.Error("duplicate entity ID accepted")
	}
	sps = testSPConfigs()
	sps[1].ID = sps[0].ID
	if _, err := NewServiceProviders(sps); err == nil {
		t.Error("duplicate ID accepted")
	}
}

// The saml.AssertionMaker adapter (used only if crewjam's own handlers are
// ever invoked) must also produce our Fleet-compatible assertion.
func TestMakeAssertionAdapter(t *testing.T) {
	p := newTestIdP(t, nil)
	sp := testSP(t, p, adminEntityID, adminACS)
	r, _ := redirectRequest(t, sp, "")
	req, err := p.ParseRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.maker.MakeAssertion(req.req, &saml.Session{UserEmail: testUserEmail, Index: "i"}); err != nil {
		t.Fatal(err)
	}
	if f := req.req.Assertion.Subject.NameID.Format; f != string(saml.EmailAddressNameIDFormat) {
		t.Errorf("format = %q", f)
	}
	req.req.ServiceProviderMetadata = &saml.EntityDescriptor{EntityID: "nope"}
	if err := p.maker.MakeAssertion(req.req, &saml.Session{UserEmail: testUserEmail}); err == nil {
		t.Error("unknown SP accepted")
	}
}
