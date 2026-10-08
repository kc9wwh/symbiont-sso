package mapping

import (
	"fmt"
	"slices"
	"strings"
)

// fleetCheck applies Fleet JIT role rules to resolved attributes:
//
//   - every role value must be a valid SSO role (catches passthrough values,
//     which are not validated at startup);
//   - FLEET_JIT_USER_ROLE_FLEET_<n> and ..._TEAM_<n> must not both be present;
//   - a default is only applied when no rule for the other scope matched:
//     an explicitly resolved (rule or passthrough) role in one scope drops
//     default-only roles in the other scope, in both directions. Defaults
//     therefore never cause conflicts (and Validate forbids configuring
//     defaults in both scopes);
//   - explicit GLOBAL plus explicit fleet-scoped roles is a conflict and
//     rejects the login.
//
// Each attribute is single-valued by construction, so Fleet's "last value
// wins" behaviour for multi-valued attributes never applies.
func fleetCheck(res *Result) error {
	var globalExplicit, fleetExplicit bool
	scopes := map[int]FleetRoleScope{}

	for _, a := range res.Attributes {
		scope, id, ok := ParseFleetRoleAttribute(a.Name)
		if !ok {
			continue
		}
		if a.Value == "gitops" || !slices.Contains(FleetRoles, a.Value) {
			return &Error{Category: CategoryInvalidRole, Attribute: a.Name, Source: a.Source,
				Message: fmt.Sprintf("invalid Fleet role in attribute %s; contact your administrator", a.Name)}
		}
		explicit := a.Source != SourceDefault
		if scope == FleetRoleGlobal {
			globalExplicit = globalExplicit || explicit
			continue
		}
		if prev, dup := scopes[id]; dup && prev != scope {
			return &Error{Category: CategoryFleetTeamClash, Attribute: a.Name, Source: a.Source,
				Message: fmt.Sprintf("both FLEET_JIT_USER_ROLE_FLEET_%d and FLEET_JIT_USER_ROLE_TEAM_%d were resolved; contact your administrator", id, id)}
		}
		scopes[id] = scope
		fleetExplicit = fleetExplicit || explicit
	}

	if globalExplicit && fleetExplicit {
		return &Error{Category: CategoryRoleConflict, Message: MsgRoleConflict}
	}

	// Drop default-only roles in the scope opposite an explicit match.
	kept := res.Attributes[:0]
	for _, a := range res.Attributes {
		scope, _, ok := ParseFleetRoleAttribute(a.Name)
		isGlobal := ok && scope == FleetRoleGlobal
		drop := ok && a.Source == SourceDefault &&
			((isGlobal && fleetExplicit) || (!isGlobal && globalExplicit))
		if drop {
			other := "global"
			if isGlobal {
				other = "fleet-level"
			}
			res.Notes = append(res.Notes, fmt.Sprintf("attribute %q: default dropped because a %s role matched", a.Name, other))
			continue
		}
		kept = append(kept, a)
	}
	res.Attributes = kept
	return nil
}

// RoleAttributeNames returns the names of Fleet role attributes in attrs
// (for logging at info level without values).
func RoleAttributeNames(attrs []Value) []string {
	var out []string
	for _, a := range attrs {
		if _, _, ok := ParseFleetRoleAttribute(a.Name); ok {
			out = append(out, a.Name)
		}
	}
	return out
}

// defaultScopeProblem reports configuring a default in both the global and
// a fleet-level scope: for a user matching no rule it would be ambiguous
// which default applies, and Fleet cannot hold both.
func defaultScopeProblem(attrs []Attribute) string {
	var globalDefault string
	var fleetDefaults []string
	for _, a := range attrs {
		scope, _, ok := ParseFleetRoleAttribute(a.Name)
		if !ok || a.Default == nil {
			continue
		}
		if scope == FleetRoleGlobal {
			globalDefault = a.Name
		} else {
			fleetDefaults = append(fleetDefaults, a.Name)
		}
	}
	if globalDefault == "" || len(fleetDefaults) == 0 {
		return ""
	}
	return fmt.Sprintf("%s and %s both set a default; a default may be configured for the global role "+
		"or for fleet-level roles, not both (it would be ambiguous for users matching no rule)",
		globalDefault, strings.Join(fleetDefaults, ", "))
}
