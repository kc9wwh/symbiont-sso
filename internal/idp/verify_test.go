package idp

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
)

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

// Minimal XML views for inspecting signatures. encoding/xml matches named
// fields against direct children only, which is exactly what "enveloped
// signature on this element" means.
type xmlSig struct {
	SignedInfo struct {
		SignatureMethod struct {
			Algorithm string `xml:"Algorithm,attr"`
		} `xml:"SignatureMethod"`
		Reference struct {
			URI string `xml:"URI,attr"`
		} `xml:"Reference"`
	} `xml:"SignedInfo"`
}

type xmlSigned struct {
	ID        string  `xml:"ID,attr"`
	Signature *xmlSig `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
}

type xmlResponse struct {
	XMLName xml.Name
	xmlSigned
	Assertion *xmlSigned `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
}

// responseDoc decodes the SAMLResponse XML from a PostForm.
func responseDoc(t *testing.T, f *PostForm) *xmlResponse {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(f.SAMLResponse)
	if err != nil {
		t.Fatal(err)
	}
	var r xmlResponse
	if err := xml.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

func issue(t *testing.T, p *IdP, entityID, acs string) *PostForm {
	t.Helper()
	sp := testSP(t, p, entityID, acs)
	r, _ := redirectRequest(t, sp, "")
	req, err := p.ParseRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	form, err := p.Respond(req, testIdentity(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return form
}

// VERIFY: crewjam's DefaultAssertionMaker emits a transient NameID (which
// Fleet cannot use as a user ID). Pins the reason our AssertionMaker exists.
func TestVerifyCrewjamDefaultNameIDIsTransient(t *testing.T) {
	p := newTestIdP(t)
	sp := testSP(t, p, adminEntityID, adminACS)
	r, _ := redirectRequest(t, sp, "")
	req, err := p.ParseRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	err = saml.DefaultAssertionMaker{}.MakeAssertion(req.req, &saml.Session{NameID: "x", UserEmail: testUserEmail})
	if err != nil {
		t.Fatal(err)
	}
	if got := req.req.Assertion.Subject.NameID.Format; got != string(saml.TransientNameIDFormat) {
		t.Fatalf("crewjam default NameID format = %q; re-check AssertionMaker assumptions", got)
	}
}

// VERIFY: both the Response and the Assertion carry an enveloped
// RSA-SHA256 signature (crewjam would default to RSA-SHA1).
func TestVerifyResponseAndAssertionSignedRSASHA256(t *testing.T) {
	p := newTestIdP(t)
	root := responseDoc(t, issue(t, p, adminEntityID, adminACS))

	if root.XMLName.Local != "Response" || root.XMLName.Space != "urn:oasis:names:tc:SAML:2.0:protocol" {
		t.Fatalf("root = %v", root.XMLName)
	}
	check := func(name string, el *xmlSigned) {
		if el.Signature == nil {
			t.Fatalf("%s is not signed", name)
		}
		if got := el.Signature.SignedInfo.SignatureMethod.Algorithm; got != SignatureMethodRSASHA256 {
			t.Errorf("%s signature method = %q, want RSA-SHA256", name, got)
		}
		if el.ID == "" || el.Signature.SignedInfo.Reference.URI != "#"+el.ID {
			t.Errorf("%s signature references %q, want #%s", name, el.Signature.SignedInfo.Reference.URI, el.ID)
		}
	}
	check("Response", &root.xmlSigned)
	if root.Assertion == nil {
		t.Fatal("no plaintext Assertion (encrypted assertions are out of scope)")
	}
	check("Assertion", root.Assertion)
}

// VERIFY: timing follows crewjam's package defaults (MaxIssueDelay 90s,
// MaxClockSkew 180s), which symbiont reads but never assigns, and the
// window is anchored at issue time even for an old (replayed) request.
func TestVerifyAssertionTimingUsesCrewjamDefaults(t *testing.T) {
	if saml.MaxIssueDelay != 90*time.Second || saml.MaxClockSkew != 180*time.Second {
		t.Fatalf("crewjam defaults changed: MaxIssueDelay=%v MaxClockSkew=%v", saml.MaxIssueDelay, saml.MaxClockSkew)
	}
	p := newTestIdP(t)
	sp := testSP(t, p, adminEntityID, adminACS)
	r, _ := redirectRequest(t, sp, "")
	req, err := p.ParseRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Now().UTC().Add(4 * time.Minute) // e.g. replay after a slow passkey prompt
	p.now = func() time.Time { return issued }
	if _, err := p.Respond(req, testIdentity(), nil); err != nil {
		t.Fatal(err)
	}
	a := req.req.Assertion
	if !a.IssueInstant.Equal(issued) {
		t.Errorf("IssueInstant = %v, want %v", a.IssueInstant, issued)
	}
	if got := a.Conditions.NotBefore; !got.Equal(issued.Add(-180 * time.Second)) {
		t.Errorf("NotBefore = %v", got)
	}
	if got := a.Conditions.NotOnOrAfter; !got.Equal(issued.Add(90 * time.Second)) {
		t.Errorf("NotOnOrAfter = %v", got)
	}
	if got := a.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter; !got.Equal(issued.Add(90 * time.Second)) {
		t.Errorf("SubjectConfirmationData.NotOnOrAfter = %v", got)
	}
}

// VERIFY: attribute statement contains exactly email, name, then mapped
// attributes; NameFormat unspecified, xs:string, single-valued.
func TestVerifyAttributeShape(t *testing.T) {
	p := newTestIdP(t)
	sp := testSP(t, p, adminEntityID, adminACS)
	a, _ := roundTrip(t, p, sp, saml.HTTPRedirectBinding, Attribute{Name: "FLEET_JIT_USER_ROLE_GLOBAL", Value: "admin"})

	want := []struct{ name, value string }{
		{"email", testUserEmail}, {"name", testUserName}, {"FLEET_JIT_USER_ROLE_GLOBAL", "admin"},
	}
	got := a.AttributeStatements[0].Attributes
	if len(got) != len(want) {
		t.Fatalf("got %d attributes: %+v", len(got), got)
	}
	for i, w := range want {
		g := got[i]
		if g.Name != w.name || g.NameFormat != AttrNameFormatUnspecified || g.FriendlyName != "" {
			t.Errorf("attr %d = %+v", i, g)
		}
		if len(g.Values) != 1 || g.Values[0].Value != w.value || g.Values[0].Type != AttrValueTypeString {
			t.Errorf("attr %s values = %+v", g.Name, g.Values)
		}
	}
}

func TestReservedAttributeFromSourceRejected(t *testing.T) {
	p := newTestIdP(t)
	sp := testSP(t, p, adminEntityID, adminACS)
	r, _ := redirectRequest(t, sp, "")
	req, _ := p.ParseRequest(r)
	evil := []Attribute{{Name: "email", Value: "evil@example.com"}}
	if _, err := p.Respond(req, testIdentity(), evil); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("err = %v", err)
	}
}

func TestNameAttributeOmittedWhenEmptyAndEmailRequired(t *testing.T) {
	p := newTestIdP(t)
	sp := testSP(t, p, adminEntityID, adminACS)
	r, reqID := redirectRequest(t, sp, "")
	req, _ := p.ParseRequest(r)
	id := testIdentity()
	id.Name = ""
	form, err := p.Respond(req, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err := sp.ParseResponse(acsPost(form), []string{reqID})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(a.AttributeStatements[0].Attributes); n != 1 {
		t.Errorf("want only email attribute, got %d", n)
	}
	if _, err := p.Respond(req, &Identity{}, nil); !errors.Is(err, ErrNoEmail) {
		t.Errorf("empty email: err = %v, want ErrNoEmail", err)
	}
}

// VERIFY: crewjam's ServeIDPInitiated picks the FIRST HTTP-POST ACS in SP
// metadata order. Our metadata puts the IdP-initiated ACS first (and marks
// it isDefault) even though config lists adminACS2 first.
func TestVerifyIDPInitiatedACSIsFirstInMetadata(t *testing.T) {
	p := newTestIdP(t)
	md, err := p.SPs().GetServiceProvider(nil, adminEntityID)
	if err != nil {
		t.Fatal(err)
	}
	acs := md.SPSSODescriptors[0].AssertionConsumerServices
	if acs[0].Location != adminACS || acs[0].IsDefault == nil || !*acs[0].IsDefault {
		t.Errorf("first ACS = %+v, want IdP-initiated ACS %q marked default", acs[0], adminACS)
	}
	if acs[1].Location != adminACS2 || *acs[1].IsDefault {
		t.Errorf("second ACS = %+v", acs[1])
	}
	for _, e := range acs {
		if e.Binding != saml.HTTPPostBinding {
			t.Errorf("ACS %s binding = %s", e.Location, e.Binding)
		}
	}
}
