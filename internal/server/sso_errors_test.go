package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/kc9wwh/symbiont-sso/internal/idp"
	"github.com/kc9wwh/symbiont-sso/internal/web"
)

func TestSSORejections(t *testing.T) {
	f := newSAMLFixture(t, fixedSessions{testUser()})

	unknownSP := f.sp(t, adminACS)
	unknownSP.EntityID = "https://not-configured.example.com"
	rUnknown, _ := fleetRedirect(t, unknownSP, "")
	rBadACS, _ := fleetRedirect(t, f.sp(t, unknownACS), "")

	big := url.Values{"SAMLRequest": {strings.Repeat("A", idp.MaxRequestBytes+10)}}
	rBig := httptest.NewRequest(http.MethodPost, base+"/sso", strings.NewReader(big.Encode()))
	rBig.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tests := []struct {
		name     string
		req      *http.Request
		status   int
		category string
		page     string
	}{
		{"unknown entity id", rUnknown, http.StatusBadRequest, idp.CategoryUnknownSP, "not configured for sign-in"},
		{"unlisted acs", rBadACS, http.StatusBadRequest, idp.CategoryACSNotAllowed, "address that is not configured"},
		{"oversized post", rBig, http.StatusRequestEntityTooLarge, idp.CategoryTooLarge, "invalid"},
		{"missing request", httptest.NewRequest(http.MethodGet, base+"/sso", nil), http.StatusBadRequest, idp.CategoryMalformed, "invalid"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.do(tc.req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			if !strings.Contains(rec.Body.String(), tc.page) {
				t.Errorf("page = %s", rec.Body)
			}
			if !strings.Contains(f.logs.String(), `"error_category":"`+tc.category+`"`) {
				t.Errorf("log missing category %s: %s", tc.category, f.logs.String())
			}
			csp := cspDirectives(rec.Header().Get(web.CSPHeader))
			if _, ok := csp["script-src"]; ok || csp["form-action"][0] != "'none'" {
				t.Errorf("error page CSP allows scripts or forms: %v", csp)
			}
		})
	}
}

func TestSSOMethodNotAllowed(t *testing.T) {
	f := newSAMLFixture(t, fixedSessions{testUser()})
	if rec := f.do(httptest.NewRequest(http.MethodPut, base+"/sso", nil)); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT /sso = %d", rec.Code)
	}
}

func TestSSOWithoutSessionBackend(t *testing.T) {
	f := newSAMLFixture(t, nil)
	r, _ := fleetRedirect(t, f.sp(t, adminACS), "")
	if rec := f.do(r); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

type handledSessions struct{}

func (handledSessions) Identity(w http.ResponseWriter, _ *http.Request, _ *idp.AuthnRequest) *idp.Identity {
	http.Redirect(w, &http.Request{}, "https://id.example.com/authorize", http.StatusFound)
	return nil
}

func TestSSOSessionProviderHandlesResponse(t *testing.T) {
	f := newSAMLFixture(t, handledSessions{})
	r, _ := fleetRedirect(t, f.sp(t, adminACS), "")
	rec := f.do(r)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://id.example.com/authorize" {
		t.Errorf("status=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestSSOMissingEmail(t *testing.T) {
	f := newSAMLFixture(t, fixedSessions{&idp.Identity{SessionID: "s"}})
	r, _ := fleetRedirect(t, f.sp(t, adminACS), "")
	rec := f.do(r)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "no email address") {
		t.Errorf("status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestMetadataEndpoint(t *testing.T) {
	f := newSAMLFixture(t, nil)
	rec := f.do(httptest.NewRequest(http.MethodGet, base+"/metadata", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/samlmetadata+xml" {
		t.Errorf("Content-Type = %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{`entityID="https://saml.example.com/metadata"`, `Location="https://saml.example.com/sso"`, "X509Certificate"} {
		if !strings.Contains(body, want) {
			t.Errorf("metadata missing %s", want)
		}
	}
}

func TestSAMLRoutesAbsentWithoutIdP(t *testing.T) {
	s, _ := newTestServer(t, 0)
	for _, p := range []string{"/metadata", "/sso"} {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s = %d", p, rec.Code)
		}
	}
}
