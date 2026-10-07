package mapping

import "testing"

func TestParseFleetRoleAttribute(t *testing.T) {
	tests := []struct {
		name  string
		scope FleetRoleScope
		id    int
		ok    bool
	}{
		{"FLEET_JIT_USER_ROLE_GLOBAL", FleetRoleGlobal, 0, true},
		{"FLEET_JIT_USER_ROLE_FLEET_2", FleetRoleFleet, 2, true},
		{"FLEET_JIT_USER_ROLE_TEAM_17", FleetRoleTeam, 17, true},
		{"FLEET_JIT_USER_ROLE_FLEET_", 0, 0, false},
		{"FLEET_JIT_USER_ROLE_FLEET_x", 0, 0, false},
		{"FLEET_JIT_USER_ROLE_GLOBAL_EXTRA", 0, 0, false},
		{"fleet_jit_user_role_global", 0, 0, false},
		{"email", 0, 0, false},
	}
	for _, tc := range tests {
		scope, id, ok := ParseFleetRoleAttribute(tc.name)
		if scope != tc.scope || id != tc.id || ok != tc.ok {
			t.Errorf("%s: got (%v,%d,%v), want (%v,%d,%v)", tc.name, scope, id, ok, tc.scope, tc.id, tc.ok)
		}
	}
}
