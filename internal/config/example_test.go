package config

import (
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestShippedExampleIsValid keeps examples/symbiont.yaml loadable. Its only
// warnings are the deliberate placeholder-domain ones (one per SP), which
// catch deployments that point at the example file by mistake.
func TestShippedExampleIsValid(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "..", "..", "examples", "symbiont.yaml")
	sps, warnings, err := LoadServiceProviders(path)
	if err != nil {
		t.Fatalf("examples/symbiont.yaml: %v", err)
	}
	want := []string{"service provider fleet-admin " + placeholderMsg, "service provider fleet-enduser " + placeholderMsg}
	if !slices.Equal(warnings, want) {
		t.Errorf("warnings = %q, want %q", warnings, want)
	}
	if len(sps) != 2 || sps[0].ID != "fleet-admin" || sps[1].ID != "fleet-enduser" {
		t.Fatalf("unexpected SPs: %+v", sps)
	}
	if !sps[0].IDPInitiatedEnabled || sps[0].IDPInitiatedACSURL != sps[0].ACSURLs[0] {
		t.Errorf("fleet-admin idp_initiated = %v %q", sps[0].IDPInitiatedEnabled, sps[0].IDPInitiatedACSURL)
	}
	if sps[1].IDPInitiatedEnabled {
		t.Errorf("fleet-enduser must not enable idp_initiated")
	}
}

func TestShippedMappingExampleIsValid(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "..", "..", "examples", "mapping.fleet.yaml")
	sps, warnings, err := LoadServiceProviders(path)
	if err != nil {
		t.Fatalf("examples/mapping.fleet.yaml: %v", err)
	}
	if !slices.Equal(warnings, []string{"service provider fleet-admin " + placeholderMsg}) ||
		len(sps) != 1 || len(sps[0].Attributes) != 2 {
		t.Errorf("warnings=%q sps=%+v", warnings, sps)
	}
}

func TestFleetDefaultsInBothScopesIsStartupError(t *testing.T) {
	both := `
service_providers:
  - id: x
    entity_id: x
    acs_urls: [https://x.example.com/acs]
    access: {allow_groups: [g]}
    attributes:
      - {name: FLEET_JIT_USER_ROLE_GLOBAL, rules: [{group: a, value: admin}], default: observer}
      - {name: FLEET_JIT_USER_ROLE_FLEET_2, default: observer}
`
	requireProblem(t, spProblems(t, both), `service provider "x": FLEET_JIT_USER_ROLE_GLOBAL and FLEET_JIT_USER_ROLE_FLEET_2 both set a default`)

	// A fleet-level default with GLOBAL rules (no GLOBAL default) is fine and
	// produces no warning: defaults never cause conflicts.
	_, warnings := parseSPs(t, strings.Replace(both, ", default: observer}\n      - {name: FLEET_JIT_USER_ROLE_FLEET_2", "}\n      - {name: FLEET_JIT_USER_ROLE_FLEET_2", 1))
	if warnings = otherWarnings(warnings); len(warnings) != 0 {
		t.Errorf("warnings = %v", warnings)
	}
}

func TestIDPInitiatedToFleetMDMACSWarns(t *testing.T) {
	_, warnings := parseSPs(t, `
service_providers:
  - id: mdm
    entity_id: fleet.example.com/mdm
    acs_urls: [https://fleet.example.com/api/v1/fleet/mdm/sso/callback]
    idp_initiated: {enabled: true}
    access: {allow_groups: [employees]}
`)
	if warnings = otherWarnings(warnings); len(warnings) != 1 || !strings.Contains(warnings[0],
		"Fleet's MDM end-user authentication requires SP-initiated login; IdP-initiated responses to this ACS will be rejected") {
		t.Errorf("warnings = %v", warnings)
	}

	// Enabled, but unsolicited responses go to a different ACS: no warning.
	_, warnings = parseSPs(t, `
service_providers:
  - id: fleet
    entity_id: fleet.example.com
    acs_urls:
      - https://fleet.example.com/api/v1/fleet/sso/callback
      - https://fleet.example.com/api/v1/fleet/mdm/sso/callback
    idp_initiated: {enabled: true, acs_url: https://fleet.example.com/api/v1/fleet/sso/callback}
    access: {allow_groups: [g]}
`)
	if warnings = otherWarnings(warnings); len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}
