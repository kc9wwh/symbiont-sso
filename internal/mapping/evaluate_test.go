package mapping

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// fleetSpec is the build plan's example mapping.
func fleetSpec() Spec {
	return Spec{
		FleetRoleValidation: true,
		PassthroughPrefixes: []string{"FLEET_JIT_USER_ROLE_"},
		Attributes: []Attribute{
			{Name: "FLEET_JIT_USER_ROLE_GLOBAL", Rules: []Rule{
				{Group: "fleet-admins", Value: "admin"},
				{Group: "fleet-maintainers", Value: "maintainer"},
				{Group: "fleet-observers", Value: "observer"},
			}, Default: ptr("observer")},
			{Name: "FLEET_JIT_USER_ROLE_FLEET_2", Rules: []Rule{
				{Group: "workstations-maint", Value: "maintainer"},
			}},
		},
	}
}

type kv = map[string]string

func values(r *Result) kv {
	m := kv{}
	for _, a := range r.Attributes {
		m[a.Name] = a.Value
	}
	return m
}

type evalCase struct {
	name   string
	spec   Spec
	in     Input
	want   kv
	errCat string
	note   string
}

func runEval(t *testing.T, tests []evalCase) {
	t.Helper()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Evaluate(tc.spec, tc.in)
			if tc.errCat != "" {
				var me *Error
				if !errors.As(err, &me) || me.Category != tc.errCat {
					t.Fatalf("err = %v, want %s", err, tc.errCat)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := values(res); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("attributes = %v, want %v", got, tc.want)
			}
			if tc.note != "" && !strings.Contains(strings.Join(res.Notes, "\n"), tc.note) {
				t.Errorf("notes %v missing %q", res.Notes, tc.note)
			}
		})
	}
}

func TestEvaluateRulesAndFleetRoles(t *testing.T) {
	noValidation := fleetSpec()
	noValidation.FleetRoleValidation = false
	runEval(t, []evalCase{
		{name: "first match wins", spec: fleetSpec(),
			in:   Input{Groups: []string{"fleet-maintainers", "fleet-admins"}},
			want: kv{"FLEET_JIT_USER_ROLE_GLOBAL": "admin"}},
		{name: "default applied", spec: fleetSpec(),
			in: Input{Groups: []string{"employees"}}, want: kv{"FLEET_JIT_USER_ROLE_GLOBAL": "observer"}},
		{name: "default GLOBAL dropped when fleet role matched", spec: fleetSpec(),
			in:   Input{Groups: []string{"workstations-maint"}},
			want: kv{"FLEET_JIT_USER_ROLE_FLEET_2": "maintainer"}, note: "default dropped"},
		{name: "GLOBAL rule + fleet rule conflict rejected", spec: fleetSpec(),
			in: Input{Groups: []string{"fleet-admins", "workstations-maint"}}, errCat: CategoryRoleConflict},
		{name: "validation off: no conflict check", spec: noValidation,
			in:   Input{Groups: []string{"fleet-admins", "workstations-maint"}},
			want: kv{"FLEET_JIT_USER_ROLE_GLOBAL": "admin", "FLEET_JIT_USER_ROLE_FLEET_2": "maintainer"}},
		{name: "group match is case-sensitive", spec: fleetSpec(),
			in: Input{Groups: []string{"Fleet-Admins"}}, want: kv{"FLEET_JIT_USER_ROLE_GLOBAL": "observer"}},
		{name: "no attributes configured", spec: Spec{}, in: Input{Groups: []string{"fleet-admins"}}, want: kv{}},
		{name: "claim rule scalar", spec: Spec{Attributes: []Attribute{{Name: "dept",
			Rules: []Rule{{Claim: &ClaimMatch{Name: "department", Equals: "it"}, Value: "IT"}}}}},
			in: Input{Claims: map[string]any{"department": "it"}}, want: kv{"dept": "IT"}},
		{name: "claim rule array membership", spec: Spec{Attributes: []Attribute{{Name: "r",
			Rules: []Rule{{Claim: &ClaimMatch{Name: "roles", Equals: "ops"}, Value: "yes"}}}}},
			in: Input{Claims: map[string]any{"roles": []any{"dev", "ops"}}}, want: kv{"r": "yes"}},
		{name: "claim rule no match", spec: Spec{Attributes: []Attribute{{Name: "r",
			Rules: []Rule{{Claim: &ClaimMatch{Name: "roles", Equals: "ops"}, Value: "yes"}}}}},
			in: Input{Claims: map[string]any{"roles": "dev"}}, want: kv{}},
	})
}

func TestEvaluatePassthrough(t *testing.T) {
	runEval(t, []evalCase{
		{name: "scalars copied", spec: Spec{PassthroughPrefixes: []string{"ACME_"}},
			in:   Input{Claims: map[string]any{"ACME_DEPT": "it", "ACME_LEVEL": 3.0, "ACME_ADMIN": true, "OTHER": "x"}},
			want: kv{"ACME_DEPT": "it", "ACME_LEVEL": "3", "ACME_ADMIN": "true"}},
		{name: "arrays, objects, reserved names skipped", spec: Spec{PassthroughPrefixes: []string{"e", "A"}},
			in:   Input{Claims: map[string]any{"email": "x@y", "A_LIST": []any{"a"}, "A_OBJ": map[string]any{}, "A_OK": "ok"}},
			want: kv{"A_OK": "ok"}, note: "skipped"},
		{name: "rule overrides passthrough", spec: fleetSpec(),
			in:   Input{Groups: []string{"fleet-admins"}, Claims: map[string]any{"FLEET_JIT_USER_ROLE_GLOBAL": "observer"}},
			want: kv{"FLEET_JIT_USER_ROLE_GLOBAL": "admin"}, note: "overrides passthrough"},
		{name: "kept when no rule matches and no default", spec: Spec{
			PassthroughPrefixes: []string{"X_"},
			Attributes:          []Attribute{{Name: "X_ROLE", Rules: []Rule{{Group: "g", Value: "rule"}}}}},
			in: Input{Claims: map[string]any{"X_ROLE": "claim"}}, want: kv{"X_ROLE": "claim"}},
		{name: "passthrough fleet role drops default GLOBAL", spec: fleetSpec(),
			in:   Input{Claims: map[string]any{"FLEET_JIT_USER_ROLE_FLEET_7": "observer"}},
			want: kv{"FLEET_JIT_USER_ROLE_FLEET_7": "observer"}},
		{name: "invalid passthrough role rejected at login", spec: fleetSpec(),
			in: Input{Claims: map[string]any{"FLEET_JIT_USER_ROLE_FLEET_7": "gitops"}}, errCat: CategoryInvalidRole},
		{name: "FLEET_ and TEAM_ same id rejected", spec: Spec{FleetRoleValidation: true, PassthroughPrefixes: []string{"FLEET_"}},
			in:     Input{Claims: map[string]any{"FLEET_JIT_USER_ROLE_FLEET_3": "observer", "FLEET_JIT_USER_ROLE_TEAM_3": "observer"}},
			errCat: CategoryFleetTeamClash},
	})
}
