package mapping

import (
	"reflect"
	"strings"
	"testing"
)

func TestRoleConflictMessageAndNoValuesInErrors(t *testing.T) {
	_, err := Evaluate(fleetSpec(), Input{Groups: []string{"fleet-admins", "workstations-maint"}})
	if err == nil || err.Error() != MsgRoleConflict {
		t.Fatalf("err = %v", err)
	}
	// Passthrough only (no rule/default to override it): invalid value is
	// rejected without echoing it.
	passOnly := Spec{FleetRoleValidation: true, PassthroughPrefixes: []string{"FLEET_JIT_USER_ROLE_"}}
	_, err = Evaluate(passOnly, Input{Claims: map[string]any{"FLEET_JIT_USER_ROLE_GLOBAL": "superuser-secret"}})
	if err == nil || strings.Contains(err.Error(), "superuser-secret") {
		t.Errorf("err = %v (want rejection without the claim value)", err)
	}
	// With a default configured, the default overrides an invalid passthrough.
	res, err := Evaluate(fleetSpec(), Input{Claims: map[string]any{"FLEET_JIT_USER_ROLE_GLOBAL": "superuser-secret"}})
	if err != nil || values(res)["FLEET_JIT_USER_ROLE_GLOBAL"] != "observer" {
		t.Errorf("default should override passthrough: %v %v", res, err)
	}
}

func TestEvaluateOrderIsDeterministic(t *testing.T) {
	spec := Spec{PassthroughPrefixes: []string{"P_"}}
	in := Input{Claims: map[string]any{"P_C": "3", "P_A": "1", "P_B": "2"}}
	for range 20 {
		res, _ := Evaluate(spec, in)
		if res.Attributes[0].Name != "P_A" || res.Attributes[2].Name != "P_C" {
			t.Fatalf("order = %v", res.Attributes)
		}
	}
}

// fleetDefaultSpec has a default on the fleet-level role only.
func fleetDefaultSpec() Spec {
	return Spec{
		FleetRoleValidation: true,
		Attributes: []Attribute{
			{Name: "FLEET_JIT_USER_ROLE_GLOBAL", Rules: []Rule{{Group: "fleet-admins", Value: "admin"}}},
			{Name: "FLEET_JIT_USER_ROLE_FLEET_2", Rules: []Rule{{Group: "workstations-maint", Value: "maintainer"}},
				Default: ptr("observer")},
		},
	}
}

// "A default is only applied when no rule for the other scope matched."
func TestDefaultsAreSymmetric(t *testing.T) {
	runEval(t, []evalCase{
		{name: "fleet rule drops GLOBAL default", spec: fleetSpec(),
			in:   Input{Groups: []string{"workstations-maint"}},
			want: kv{"FLEET_JIT_USER_ROLE_FLEET_2": "maintainer"}, note: `"FLEET_JIT_USER_ROLE_GLOBAL": default dropped because a fleet-level role matched`},
		{name: "GLOBAL rule drops fleet default", spec: fleetDefaultSpec(),
			in:   Input{Groups: []string{"fleet-admins"}},
			want: kv{"FLEET_JIT_USER_ROLE_GLOBAL": "admin"}, note: `"FLEET_JIT_USER_ROLE_FLEET_2": default dropped because a global role matched`},
		{name: "fleet default applies when no global rule matched", spec: fleetDefaultSpec(),
			in: Input{Groups: []string{"employees"}}, want: kv{"FLEET_JIT_USER_ROLE_FLEET_2": "observer"}},
		{name: "fleet rule beats its own default", spec: fleetDefaultSpec(),
			in: Input{Groups: []string{"workstations-maint"}}, want: kv{"FLEET_JIT_USER_ROLE_FLEET_2": "maintainer"}},
		{name: "rule vs rule still conflicts (global default spec)", spec: fleetSpec(),
			in: Input{Groups: []string{"fleet-admins", "workstations-maint"}}, errCat: CategoryRoleConflict},
		{name: "rule vs rule still conflicts (fleet default spec)", spec: fleetDefaultSpec(),
			in: Input{Groups: []string{"fleet-admins", "workstations-maint"}}, errCat: CategoryRoleConflict},
		{name: "passthrough GLOBAL counts as a match and drops fleet default", spec: func() Spec {
			s := fleetDefaultSpec()
			s.PassthroughPrefixes = []string{"FLEET_JIT_USER_ROLE_GLOBAL"}
			s.Attributes = s.Attributes[1:]
			return s
		}(), in: Input{Claims: map[string]any{"FLEET_JIT_USER_ROLE_GLOBAL": "observer"}},
			want: kv{"FLEET_JIT_USER_ROLE_GLOBAL": "observer"}},
	})
}

func TestBothScopeDefaultsRejectedAtStartup(t *testing.T) {
	attrs := []Attribute{
		{Name: "FLEET_JIT_USER_ROLE_GLOBAL", Default: ptr("observer")},
		{Name: "FLEET_JIT_USER_ROLE_FLEET_2", Default: ptr("observer")},
		{Name: "FLEET_JIT_USER_ROLE_TEAM_3", Default: ptr("observer")},
	}
	p := Validate(attrs, nil, true)
	if len(p) != 1 || !strings.Contains(p[0], "FLEET_JIT_USER_ROLE_GLOBAL and FLEET_JIT_USER_ROLE_FLEET_2, FLEET_JIT_USER_ROLE_TEAM_3 both set a default") {
		t.Errorf("problems = %v", p)
	}
	if p := Validate(attrs, nil, false); len(p) != 0 {
		t.Errorf("fleet validation off: problems = %v", p)
	}
	if p := Validate(fleetSpec().Attributes, nil, true); len(p) != 0 {
		t.Errorf("global-default-only spec rejected: %v", p)
	}
	if p := Validate(fleetDefaultSpec().Attributes, nil, true); len(p) != 0 {
		t.Errorf("fleet-default-only spec rejected: %v", p)
	}
}

func TestInvalidPassthroughErrorNamesAttribute(t *testing.T) {
	spec := Spec{FleetRoleValidation: true, PassthroughPrefixes: []string{"FLEET_JIT_USER_ROLE_"}}
	_, err := Evaluate(spec, Input{Claims: map[string]any{"FLEET_JIT_USER_ROLE_FLEET_9": "root"}})
	me, ok := err.(*Error)
	if !ok || me.Category != CategoryInvalidRole || me.Attribute != "FLEET_JIT_USER_ROLE_FLEET_9" || me.Source != SourcePassthrough {
		t.Fatalf("err = %#v", err)
	}
	if strings.Contains(me.Message, "root") {
		t.Errorf("message leaks value: %q", me.Message)
	}
}

func TestRoleAttributeNames(t *testing.T) {
	names := RoleAttributeNames([]Value{{Name: "FLEET_JIT_USER_ROLE_GLOBAL"}, {Name: "dept"}})
	if !reflect.DeepEqual(names, []string{"FLEET_JIT_USER_ROLE_GLOBAL"}) {
		t.Errorf("RoleAttributeNames = %v", names)
	}
}
