package mapping

import (
	"strings"
	"testing"
)

func ptr(s string) *string { return &s }

func TestValidateAcceptsFleetExample(t *testing.T) {
	attrs := []Attribute{
		{Name: "FLEET_JIT_USER_ROLE_GLOBAL", Rules: []Rule{
			{Group: "fleet-admins", Value: "admin"},
			{Group: "fleet-maintainers", Value: "maintainer"},
			{Claim: &ClaimMatch{Name: "department", Equals: "it"}, Value: "observer_plus"},
		}, Default: ptr("observer")},
		{Name: "FLEET_JIT_USER_ROLE_FLEET_2", Rules: []Rule{{Group: "workstations-maint", Value: "maintainer"}}},
		{Name: "FLEET_JIT_USER_ROLE_TEAM_3", Rules: []Rule{{Group: "t", Value: "technician"}}},
		{Name: "FLEET_JIT_USER_ROLE_FLEET_4", Default: ptr("null")},
		{Name: "department", Rules: []Rule{{Group: "x", Value: "anything-goes"}}},
	}
	if p := Validate(attrs, []string{"FLEET_JIT_USER_ROLE_"}, true); len(p) != 0 {
		t.Fatalf("unexpected problems: %v", p)
	}
}

func TestValidateFleetRolesOnlyWhenEnabled(t *testing.T) {
	attrs := []Attribute{{Name: "FLEET_JIT_USER_ROLE_GLOBAL", Default: ptr("gitops")}}
	if p := Validate(attrs, nil, false); len(p) != 0 {
		t.Errorf("fleet validation disabled but got %v", p)
	}
	p := Validate(attrs, nil, true)
	if len(p) != 1 || !strings.Contains(p[0], "gitops") {
		t.Errorf("problems = %v", p)
	}
}

func TestValidateProblems(t *testing.T) {
	tests := []struct {
		name  string
		attrs []Attribute
		want  string
	}{
		{"no name", []Attribute{{Default: ptr("x")}}, "attributes[0]: name is required"},
		{"whitespace name", []Attribute{{Name: "a b", Default: ptr("x")}}, "whitespace"},
		{"reserved", []Attribute{{Name: "name", Default: ptr("x")}}, "reserved"},
		{"duplicate", []Attribute{{Name: "a", Default: ptr("x")}, {Name: "a", Default: ptr("x")}}, "more than once"},
		{"empty", []Attribute{{Name: "a"}}, "at least one rule or a default"},
		{"empty default", []Attribute{{Name: "a", Default: ptr("")}}, "default must not be empty"},
		{"invalid rule role", []Attribute{{Name: "FLEET_JIT_USER_ROLE_GLOBAL", Rules: []Rule{{Group: "g", Value: "root"}}}}, `rules[0]: invalid Fleet role "root"`},
		{"invalid default role", []Attribute{{Name: "FLEET_JIT_USER_ROLE_FLEET_1", Default: ptr("Admin")}}, `default: invalid Fleet role "Admin"`},
		{"fleet/team dup", []Attribute{
			{Name: "FLEET_JIT_USER_ROLE_TEAM_9", Default: ptr("observer")},
			{Name: "FLEET_JIT_USER_ROLE_FLEET_9", Default: ptr("observer")},
		}, "both FLEET_JIT_USER_ROLE_FLEET_9 and FLEET_JIT_USER_ROLE_TEAM_9"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := Validate(tc.attrs, nil, true)
			if !strings.Contains(strings.Join(p, "\n"), tc.want) {
				t.Errorf("problems %v do not contain %q", p, tc.want)
			}
		})
	}
}

func TestHasFleetRoleAttributes(t *testing.T) {
	for _, tc := range []struct {
		attrs    []Attribute
		prefixes []string
		want     bool
	}{
		{nil, nil, false},
		{[]Attribute{{Name: "department"}}, nil, false},
		{[]Attribute{{Name: "FLEET_JIT_USER_ROLE_TEAM_1"}}, nil, true},
		{nil, []string{"FLEET_JIT_USER_ROLE_"}, true},
		{nil, []string{"FLEET_"}, true},
		{nil, []string{"FLEET_JIT_USER_ROLE_GLOBAL"}, true},
		{nil, []string{"ACME_"}, false},
	} {
		if got := HasFleetRoleAttributes(tc.attrs, tc.prefixes); got != tc.want {
			t.Errorf("HasFleetRoleAttributes(%v, %v) = %v", tc.attrs, tc.prefixes, got)
		}
	}
}
