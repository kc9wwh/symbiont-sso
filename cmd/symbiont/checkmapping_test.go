package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func examplesDir(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "examples")
}

func checkMapping(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), append([]string{"check-mapping"}, args...), noEnv, &out, &errb)
	return code, out.String(), errb.String()
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckMappingExamples(t *testing.T) {
	ex := examplesDir(t)
	sps := filepath.Join(ex, "symbiont.yaml")

	code, out, errOut := checkMapping(t, "--file", sps, "--claims", filepath.Join(ex, "claims.admin.json"))
	if code != exitOK {
		t.Fatalf("admin: exit %d\n%s%s", code, out, errOut)
	}
	for _, want := range []string{"[fleet-admin]", "FLEET_JIT_USER_ROLE_GLOBAL = admin  (rule)", "[fleet-enduser]", "email = alice@example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("admin output missing %q:\n%s", want, out)
		}
	}
	_, enduser, found := strings.Cut(out, "[fleet-enduser]")
	if !found {
		t.Fatalf("admin output missing [fleet-enduser]:\n%s", out)
	}
	if strings.Contains(enduser, "FLEET_JIT") {
		t.Errorf("fleet-enduser shows role attributes:\n%s", enduser)
	}

	code, out, _ = checkMapping(t, "--file", sps, "--claims", filepath.Join(ex, "claims.employee.json"))
	if code != exitError || !strings.Contains(out, "access: DENIED (no_matching_group)") {
		t.Errorf("employee: exit %d\n%s", code, out)
	}
	code, out, _ = checkMapping(t, "--file", sps, "--claims", filepath.Join(ex, "claims.employee.json"), "--sp", "fleet-enduser")
	if code != exitOK || strings.Contains(out, "[fleet-admin]") {
		t.Errorf("--sp filter: exit %d\n%s", code, out)
	}

	code, out, errOut = checkMapping(t, "--file", filepath.Join(ex, "mapping.fleet.yaml"), "--claims", filepath.Join(ex, "claims.admin.json"))
	if code != exitOK || !strings.Contains(out, "FLEET_JIT_USER_ROLE_GLOBAL = admin") {
		t.Errorf("mapping.fleet.yaml: exit %d\n%s%s", code, out, errOut)
	}
}

func TestCheckMappingConflictAndDefaults(t *testing.T) {
	ex := examplesDir(t)
	file := filepath.Join(ex, "mapping.fleet.yaml")

	both := writeTemp(t, "both.json", `{"email":"c@example.com","groups":["fleet-admins","workstations-maint"]}`)
	code, out, _ := checkMapping(t, "--file", file, "--claims", both)
	if code != exitError || !strings.Contains(out, "REJECTED (fleet_role_conflict): conflicting Fleet roles") {
		t.Errorf("conflict: exit %d\n%s", code, out)
	}

	fleetOnly := writeTemp(t, "fleet.json", `{"email":"d@example.com","groups":["workstations-maint"]}`)
	code, out, _ = checkMapping(t, "--file", file, "--claims", fleetOnly)
	if code != exitOK || !strings.Contains(out, "FLEET_JIT_USER_ROLE_FLEET_2 = maintainer") ||
		strings.Contains(out, "FLEET_JIT_USER_ROLE_GLOBAL =") || !strings.Contains(out, "default dropped") {
		t.Errorf("default dropping: exit %d\n%s", code, out)
	}

	breakGlass := writeTemp(t, "bg.json", `{"email":"Break-Glass@example.com"}`)
	code, out, _ = checkMapping(t, "--file", file, "--claims", breakGlass)
	if code != exitOK || !strings.Contains(out, "FLEET_JIT_USER_ROLE_GLOBAL = observer  (default)") {
		t.Errorf("allow_emails + default: exit %d\n%s", code, out)
	}
}

func TestCheckMappingErrors(t *testing.T) {
	ex := examplesDir(t)
	sps := filepath.Join(ex, "symbiont.yaml")
	claims := filepath.Join(ex, "claims.admin.json")
	bad := writeTemp(t, "bad.yaml", "service_providers:\n  - {id: x, entity_id: x, acs_urls: [https://x.example.com/a], attributes: [{name: FLEET_JIT_USER_ROLE_GLOBAL, default: gitops}]}\n")
	tests := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"missing flags", nil, exitUsage, "Usage"},
		{"invalid sp file", []string{"--file", bad, "--claims", claims}, exitConfig, "gitops"},
		{"default deny at load", []string{"--file", bad, "--claims", claims}, exitConfig, "access block is required"},
		{"bad json", []string{"--file", sps, "--claims", writeTemp(t, "c.json", "[1,2]")}, exitConfig, "invalid claims JSON"},
		{"no email", []string{"--file", sps, "--claims", writeTemp(t, "c.json", `{"name":"x"}`)}, exitConfig, "missing or not an email"},
		{"unknown sp", []string{"--file", sps, "--claims", claims, "--sp", "nope"}, exitUsage, `no service provider with id "nope"`},
		{"missing claims file", []string{"--file", sps, "--claims", "/nonexistent.json"}, exitConfig, "no such file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := checkMapping(t, tc.args...)
			if code != tc.code || !strings.Contains(out+errOut, tc.want) {
				t.Errorf("exit %d (want %d)\nstdout:%s\nstderr:%s", code, tc.code, out, errOut)
			}
		})
	}
}
