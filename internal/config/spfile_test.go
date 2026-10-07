package config

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// amendmentExample is the service provider file from the build plan.
const amendmentExample = `
service_providers:
  - id: fleet-admin
    display_name: Fleet
    entity_id: fleet.example.com
    acs_urls:
      - https://fleet.example.com/api/v1/fleet/sso/callback
    idp_initiated:
      enabled: true
      acs_url: https://fleet.example.com/api/v1/fleet/sso/callback
    access:
      allow_groups: [fleet-admins, fleet-maintainers, fleet-observers]
    fleet_role_validation: true
    passthrough_prefixes: []
    attributes:
      - name: FLEET_JIT_USER_ROLE_GLOBAL
        rules:
          - group: fleet-admins
            value: admin
          - group: fleet-maintainers
            value: maintainer
        default: observer

  - id: fleet-enduser
    display_name: Fleet device enrollment
    entity_id: fleet.example.com/mdm
    acs_urls:
      - https://fleet.example.com/api/v1/fleet/mdm/sso/callback
    idp_initiated:
      enabled: false
    access:
      allow_groups: [employees]
    fleet_role_validation: false
    attributes: []
`

func parseSPs(t *testing.T, y string) ([]ServiceProvider, []string) {
	t.Helper()
	sps, warnings, err := ParseServiceProviders([]byte(y))
	if err != nil {
		t.Fatalf("ParseServiceProviders: %v", err)
	}
	return sps, warnings
}

func spProblems(t *testing.T, y string) []string {
	t.Helper()
	_, _, err := ParseServiceProviders([]byte(y))
	var cerr *Error
	if !errors.As(err, &cerr) {
		t.Fatalf("want *config.Error, got %v", err)
	}
	return cerr.Problems
}

func TestParseServiceProvidersAmendmentExample(t *testing.T) {
	sps, warnings := parseSPs(t, amendmentExample)
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if len(sps) != 2 {
		t.Fatalf("got %d SPs", len(sps))
	}
	admin, enduser := sps[0], sps[1]
	if admin.ID != "fleet-admin" || admin.DisplayName != "Fleet" || admin.EntityID != "fleet.example.com" {
		t.Errorf("admin identity = %+v", admin)
	}
	if !admin.IDPInitiatedEnabled || admin.IDPInitiatedACSURL != "https://fleet.example.com/api/v1/fleet/sso/callback" {
		t.Errorf("admin idp-initiated = %v %q", admin.IDPInitiatedEnabled, admin.IDPInitiatedACSURL)
	}
	if !slices.Equal(admin.Access.AllowGroups, []string{"fleet-admins", "fleet-maintainers", "fleet-observers"}) || admin.Access.AllowAll {
		t.Errorf("admin access = %+v", admin.Access)
	}
	if !admin.FleetRoleValidation || len(admin.Attributes) != 1 || *admin.Attributes[0].Default != "observer" {
		t.Errorf("admin mapping = %+v", admin)
	}
	if enduser.IDPInitiatedEnabled || enduser.IDPInitiatedACSURL != "" || enduser.FleetRoleValidation {
		t.Errorf("enduser = %+v", enduser)
	}
}

func TestParseServiceProvidersDefaults(t *testing.T) {
	sps, _ := parseSPs(t, `
service_providers:
  - id: app
    entity_id: urn:app
    acs_urls: [https://a.example.com/acs1, https://a.example.com/acs2]
    idp_initiated: {enabled: true}
    access: {allow_emails: [" Admin@Example.COM "]}
`)
	sp := sps[0]
	if sp.DisplayName != "app" {
		t.Errorf("DisplayName default = %q, want id", sp.DisplayName)
	}
	if sp.IDPInitiatedACSURL != "https://a.example.com/acs1" {
		t.Errorf("idp-initiated ACS default = %q, want first ACS", sp.IDPInitiatedACSURL)
	}
	if !sp.FleetRoleValidation {
		t.Errorf("fleet_role_validation should default to true")
	}
	if !slices.Equal(sp.Access.AllowEmails, []string{"admin@example.com"}) {
		t.Errorf("AllowEmails = %v (want trimmed, lower-cased)", sp.Access.AllowEmails)
	}

	sps, _ = parseSPs(t, `
service_providers:
  - {id: x, entity_id: x, acs_urls: ["http://localhost:8080/acs"], access: {allow_all: true}}
`)
	if sps[0].IDPInitiatedEnabled {
		t.Errorf("idp_initiated must default to disabled")
	}
}

func TestAllowAllWithFleetRolesWarns(t *testing.T) {
	_, warnings := parseSPs(t, `
service_providers:
  - id: x
    entity_id: x
    acs_urls: [https://x.example.com/acs]
    access: {allow_all: true}
    attributes:
      - {name: FLEET_JIT_USER_ROLE_GLOBAL, default: observer}
`)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "allow_all is true and Fleet role attributes") {
		t.Errorf("warnings = %v", warnings)
	}
	_, warnings = parseSPs(t, `
service_providers:
  - {id: x, entity_id: x, acs_urls: [https://x.example.com/acs], access: {allow_all: true}, passthrough_prefixes: [FLEET_]}
`)
	if len(warnings) != 1 {
		t.Errorf("passthrough prefix covering Fleet roles should warn; got %v", warnings)
	}
}
