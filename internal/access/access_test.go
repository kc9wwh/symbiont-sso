package access

import (
	"testing"

	"github.com/kc9wwh/symbiont-sso/internal/config"
	"github.com/kc9wwh/symbiont-sso/internal/mapping"
)

func TestAllowed(t *testing.T) {
	groups := config.AccessPolicy{AllowGroups: []string{"fleet-admins", "fleet-observers"}}
	emails := config.AccessPolicy{AllowEmails: []string{"break-glass@example.com"}}
	both := config.AccessPolicy{AllowGroups: []string{"employees"}, AllowEmails: []string{"contractor@example.com"}}
	tests := []struct {
		name   string
		p      config.AccessPolicy
		email  string
		groups []string
		ok     bool
		reason string
	}{
		{"group any-of", groups, "a@example.com", []string{"x", "fleet-observers"}, true, ""},
		{"group none", groups, "a@example.com", []string{"employees"}, false, ReasonNoMatchingGroup},
		{"group case-sensitive", groups, "a@example.com", []string{"Fleet-Admins"}, false, ReasonNoMatchingGroup},
		{"no groups claim", groups, "a@example.com", nil, false, ReasonNoMatchingGroup},
		{"email match case-insensitive", emails, "Break-Glass@Example.com", nil, true, ""},
		{"email no match", emails, "a@example.com", nil, false, ReasonEmailNotAllowed},
		{"either: group", both, "a@example.com", []string{"employees"}, true, ""},
		{"either: email", both, "contractor@example.com", nil, true, ""},
		{"either: neither", both, "a@example.com", nil, false, ReasonNoMatchingGroup},
		{"allow_all", config.AccessPolicy{AllowAll: true}, "anyone@x.y", nil, true, ""},
		{"empty policy denies", config.AccessPolicy{}, "a@example.com", []string{"g"}, false, ReasonNotConfigured},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := Allowed(tc.p, tc.email, tc.groups)
			if ok != tc.ok || reason != tc.reason {
				t.Errorf("Allowed = %v %q, want %v %q", ok, reason, tc.ok, tc.reason)
			}
		})
	}
}

func TestDecide(t *testing.T) {
	sp := &config.ServiceProvider{
		ID:                  "fleet-admin",
		Access:              config.AccessPolicy{AllowGroups: []string{"fleet-admins", "workstations-maint"}},
		FleetRoleValidation: true,
		Attributes: []mapping.Attribute{
			{Name: "FLEET_JIT_USER_ROLE_GLOBAL", Rules: []mapping.Rule{{Group: "fleet-admins", Value: "admin"}}},
			{Name: "FLEET_JIT_USER_ROLE_FLEET_2", Rules: []mapping.Rule{{Group: "workstations-maint", Value: "maintainer"}}},
		},
	}

	d, err := Decide(sp, Subject{Email: "e@example.com", Groups: []string{"employees"}})
	if err != nil || d.Allowed || d.Reason != ReasonNoMatchingGroup || d.Mapping != nil {
		t.Errorf("denied subject: %+v %v (mapping must not be evaluated)", d, err)
	}

	d, err = Decide(sp, Subject{Email: "a@example.com", Groups: []string{"fleet-admins"}})
	if err != nil || !d.Allowed || len(d.Mapping.Attributes) != 1 || d.Mapping.Attributes[0].Value != "admin" {
		t.Errorf("allowed subject: %+v %v", d, err)
	}

	d, err = Decide(sp, Subject{Email: "a@example.com", Groups: []string{"fleet-admins", "workstations-maint"}})
	if err == nil || !d.Allowed || err.(*mapping.Error).Category != mapping.CategoryRoleConflict {
		t.Errorf("conflict: %+v %v", d, err)
	}
}
