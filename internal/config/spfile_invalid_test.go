package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// spYAML builds a one-SP file around a body fragment (indented 4 spaces).
func spYAML(body string) string {
	return "service_providers:\n  - id: app\n    entity_id: urn:app\n" + body
}

const okACS = "    acs_urls: [https://app.example.com/acs]\n"
const okAccess = "    access: {allow_groups: [g]}\n"

func TestParseServiceProvidersInvalid(t *testing.T) {
	tests := []struct {
		name, yaml, want string
	}{
		{"empty file", "", "file is empty"},
		{"no providers", "service_providers: []\n", "at least one entry"},
		{"bad yaml", "service_providers: [\n", "invalid YAML"},
		{"unknown key typo", spYAML(okACS + okAccess + "    acces: {}\n"), "field acces not found"},
		{"multiple documents", spYAML(okACS+okAccess) + "---\nfoo: bar\n", "single YAML document"},
		{"missing access is default deny", spYAML(okACS), "access block is required (access is denied by default)"},
		{"empty access block", spYAML(okACS + "    access: {}\n"), "access must set at least one of"},
		{"allow_all false alone", spYAML(okACS + "    access: {allow_all: false}\n"), "access must set at least one of"},
		{"allow_all combined", spYAML(okACS + "    access: {allow_all: true, allow_groups: [g]}\n"), "cannot be combined"},
		{"allow_all with emails", spYAML(okACS + "    access: {allow_all: true, allow_emails: [a@b.c]}\n"), "cannot be combined"},
		{"bad email", spYAML(okACS + "    access: {allow_emails: [nope]}\n"), "allow_emails[0] is not a valid email"},
		{"blank group", spYAML(okACS + "    access: {allow_groups: [\" \"]}\n"), "allow_groups[0] must be a non-empty"},
		{"no acs", spYAML(okAccess), "acs_urls must list at least one URL"},
		{"http acs", spYAML(okAccess + "    acs_urls: [http://app.example.com/acs]\n"), "acs_urls[0] must use https"},
		{"duplicate acs in sp", spYAML(okAccess + "    acs_urls: [https://a.example.com/x, https://a.example.com/x]\n"), "listed twice"},
		{"idp acs not listed", spYAML(okACS + okAccess + "    idp_initiated: {enabled: true, acs_url: https://other.example.com/acs}\n"), "must be one of acs_urls"},
		{"idp acs while disabled", spYAML(okACS + okAccess + "    idp_initiated: {acs_url: https://app.example.com/acs}\n"), "enabled is not true"},
		{"gitops rejected", spYAML(okACS + okAccess + "    attributes: [{name: FLEET_JIT_USER_ROLE_GLOBAL, default: gitops}]\n"), `"gitops" is only for API-only users`},
		{"invalid role", spYAML(okACS + okAccess + "    attributes: [{name: FLEET_JIT_USER_ROLE_FLEET_2, rules: [{group: g, value: superuser}]}]\n"), `invalid Fleet role "superuser"`},
		{"fleet team dup", spYAML(okACS + okAccess + "    attributes:\n      - {name: FLEET_JIT_USER_ROLE_FLEET_3, default: observer}\n      - {name: FLEET_JIT_USER_ROLE_TEAM_3, default: observer}\n"), "both FLEET_JIT_USER_ROLE_FLEET_3 and FLEET_JIT_USER_ROLE_TEAM_3"},
		{"reserved attribute", spYAML(okACS + okAccess + "    attributes: [{name: email, default: x}]\n"), "name is reserved"},
		{"duplicate attribute", spYAML(okACS + okAccess + "    attributes: [{name: a, default: x}, {name: a, default: y}]\n"), "defined more than once"},
		{"rule with group and claim", spYAML(okACS + okAccess + "    attributes: [{name: a, rules: [{group: g, claim: {name: c, equals: d}, value: v}]}]\n"), "either group or claim, not both"},
		{"rule without matcher", spYAML(okACS + okAccess + "    attributes: [{name: a, rules: [{value: v}]}]\n"), "set one of group or claim"},
		{"rule without value", spYAML(okACS + okAccess + "    attributes: [{name: a, rules: [{group: g}]}]\n"), "value is required"},
		{"claim incomplete", spYAML(okACS + okAccess + "    attributes: [{name: a, rules: [{claim: {name: c}, value: v}]}]\n"), "claim needs both name and equals"},
		{"attribute without rules", spYAML(okACS + okAccess + "    attributes: [{name: a}]\n"), "at least one rule or a default"},
		{"empty default", spYAML(okACS + okAccess + "    attributes: [{name: a, default: \"\"}]\n"), "default must not be empty"},
		{"blank passthrough prefix", spYAML(okACS + okAccess + "    passthrough_prefixes: [\"\"]\n"), "passthrough_prefixes[0]"},
		{"bad id", "service_providers:\n  - {id: Fleet_Admin, entity_id: x, acs_urls: [https://a.example.com/a], access: {allow_all: true}}\n", "id must match ^[a-z0-9-]+$"},
		{"missing id", "service_providers:\n  - {entity_id: x, acs_urls: [https://a.example.com/a], access: {allow_all: true}}\n", "service_providers[0]: id is required"},
		{"missing entity id", "service_providers:\n  - {id: a, acs_urls: [https://a.example.com/a], access: {allow_all: true}}\n", "entity_id is required"},
		{"entity id whitespace", "service_providers:\n  - {id: a, entity_id: \"a b\", acs_urls: [https://a.example.com/a], access: {allow_all: true}}\n", "entity_id must not contain whitespace"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requireProblem(t, spProblems(t, tc.yaml), tc.want)
		})
	}
}

func TestParseServiceProvidersCrossSPConflicts(t *testing.T) {
	problems := spProblems(t, `
service_providers:
  - {id: a, entity_id: same, acs_urls: [https://x.example.com/acs], access: {allow_all: true}}
  - {id: a, entity_id: same, acs_urls: [https://x.example.com/acs], access: {allow_all: true}}
`)
	requireProblem(t, problems, "ids must be unique")
	requireProblem(t, problems, `entity_id "same" is also used by`)
	requireProblem(t, problems, "an ACS URL may belong to only one service provider")
}

func TestLoadServiceProvidersFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "symbiont.yaml")
	if err := os.WriteFile(p, []byte(amendmentExample), 0o600); err != nil {
		t.Fatal(err)
	}
	sps, _, err := LoadServiceProviders(p)
	if err != nil || len(sps) != 2 {
		t.Fatalf("LoadServiceProviders = %d, %v", len(sps), err)
	}
	_, _, err = LoadServiceProviders(filepath.Join(dir, "missing.yaml"))
	if err == nil || !strings.Contains(err.Error(), "cannot read") {
		t.Errorf("missing file error = %v", err)
	}
}
