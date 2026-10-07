package config

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestShippedExampleIsValid keeps examples/symbiont.yaml loadable and
// warning-free.
func TestShippedExampleIsValid(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "..", "..", "examples", "symbiont.yaml")
	sps, warnings, err := LoadServiceProviders(path)
	if err != nil {
		t.Fatalf("examples/symbiont.yaml: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
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

func TestIDPInitiatedToFleetMDMACSWarns(t *testing.T) {
	_, warnings := parseSPs(t, `
service_providers:
  - id: mdm
    entity_id: fleet.example.com/mdm
    acs_urls: [https://fleet.example.com/api/v1/fleet/mdm/sso/callback]
    idp_initiated: {enabled: true}
    access: {allow_groups: [employees]}
`)
	if len(warnings) != 1 || !strings.Contains(warnings[0],
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
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}
