package config

import (
	"slices"
	"strings"
	"testing"
)

const placeholderMsg = "uses a placeholder domain; did you point SYMBIONT_SP_CONFIG_FILE at the example file?"

// otherWarnings drops placeholder-domain warnings, for tests whose fixtures
// use example.com but which are about other warnings.
func otherWarnings(ws []string) []string {
	return slices.DeleteFunc(slices.Clone(ws), func(w string) bool { return strings.Contains(w, placeholderMsg) })
}

func TestIsPlaceholderHost(t *testing.T) {
	for host, want := range map[string]bool{
		"example.com":         true,
		"fleet.example.com":   true,
		"FLEET.EXAMPLE.ORG.":  true,
		"a.b.example.net":     true,
		"example":             true,
		"saml.corp.example":   true,
		"notexample.com":      false,
		"example.com.evil.io": false,
		"example.co":          false,
		"proto.kc9wwh.net":    false,
		"fleet.test":          false,
		"localhost":           false,
		"":                    false,
	} {
		if got := isPlaceholderHost(host); got != want {
			t.Errorf("isPlaceholderHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestEntityIDHost(t *testing.T) {
	for id, want := range map[string]string{
		"fleet.example.com":              "fleet.example.com",
		"fleet.example.com/mdm":          "fleet.example.com",
		"fleet.example.com:8443/mdm":     "fleet.example.com",
		"https://fleet.example.com/saml": "fleet.example.com",
		"https://fleet.example.com:8443": "fleet.example.com",
		"urn:example.com:fleet":          "",
		"URN:amazon:webservices":         "",
	} {
		if got := entityIDHost(id); got != want {
			t.Errorf("entityIDHost(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestPlaceholderDomainWarning(t *testing.T) {
	tests := []struct {
		name, entityID, acs string
		warn                bool
	}{
		{"entity id placeholder", "fleet.example.com", "https://fleet.acme.internal/acs", true},
		{"acs placeholder", "fleet.acme.internal", "https://fleet.example.org/acs", true},
		{"*.example TLD", "https://sp.corp.example/metadata", "https://sp.acme.internal/acs", true},
		{"real domains", "proto.kc9wwh.net", "https://proto.kc9wwh.net/api/v1/fleet/sso/callback", false},
		{"urn entity id, real acs", "urn:example.com:sp", "https://sp.acme.internal/acs", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, warnings := parseSPs(t, "service_providers:\n  - id: my-sp\n    entity_id: \""+tc.entityID+
				"\"\n    acs_urls: [\""+tc.acs+"\"]\n    access: {allow_groups: [g]}\n")
			want := []string(nil)
			if tc.warn {
				want = []string{"service provider my-sp " + placeholderMsg}
			}
			if !slices.Equal(warnings, want) {
				t.Errorf("warnings = %q, want %q", warnings, want)
			}
		})
	}
}

// One warning per SP, even when several of its URLs are placeholders.
func TestPlaceholderWarningOncePerSP(t *testing.T) {
	_, warnings := parseSPs(t, `
service_providers:
  - id: a
    entity_id: a.example.com
    acs_urls: [https://a.example.com/1, https://a.example.com/2]
    access: {allow_all: true}
  - id: b
    entity_id: b.acme.internal
    acs_urls: [https://b.acme.internal/acs]
    access: {allow_all: true}
`)
	if !slices.Equal(warnings, []string{"service provider a " + placeholderMsg}) {
		t.Errorf("warnings = %q", warnings)
	}
}
