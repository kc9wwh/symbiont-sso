package mapping

import (
	"fmt"
	"slices"
	"strings"
)

// FleetRoles are the role values Fleet accepts in JIT role attributes for
// SSO users. "gitops" exists in Fleet but is reserved for API-only users.
var FleetRoles = []string{"admin", "maintainer", "observer", "observer_plus", "technician", "null"}

// ReservedAttributeNames are always emitted by the bridge and cannot be
// produced by rules.
var ReservedAttributeNames = []string{"email", "name"}

// Validate statically checks rule-based attributes and passthrough prefixes.
// It returns human-readable problems, each prefixed with nothing; callers
// add context (file, service provider). When fleetRoles is true, Fleet JIT
// role attributes are checked against FleetRoles and for FLEET_/TEAM_
// duplicates.
func Validate(attrs []Attribute, passthroughPrefixes []string, fleetRoles bool) []string {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	for i, p := range passthroughPrefixes {
		if strings.TrimSpace(p) == "" || p != strings.TrimSpace(p) {
			add("passthrough_prefixes[%d] must be a non-empty prefix without surrounding whitespace", i)
		}
	}

	seen := map[string]bool{}
	fleetIDs := map[int]FleetRoleScope{}
	for i, a := range attrs {
		where := fmt.Sprintf("attributes[%d]", i)
		if a.Name != "" {
			where = fmt.Sprintf("attribute %q", a.Name)
		}
		switch {
		case a.Name == "":
			add("%s: name is required", where)
		case strings.ContainsFunc(a.Name, func(r rune) bool { return r <= ' ' || r == 0x7f }):
			add("%s: name must not contain whitespace or control characters", where)
		case slices.Contains(ReservedAttributeNames, a.Name):
			add("%s: name is reserved (email and name are always sent by the bridge)", where)
		case seen[a.Name]:
			add("%s: defined more than once", where)
		}
		seen[a.Name] = true

		if len(a.Rules) == 0 && a.Default == nil {
			add("%s: needs at least one rule or a default", where)
		}
		for j, r := range a.Rules {
			validateRule(add, fmt.Sprintf("%s rules[%d]", where, j), r)
		}
		if a.Default != nil && *a.Default == "" {
			add("%s: default must not be empty (omit it to send nothing)", where)
		}

		if !fleetRoles {
			continue
		}
		scope, id, ok := ParseFleetRoleAttribute(a.Name)
		if !ok {
			continue
		}
		for j, r := range a.Rules {
			if msg := fleetRoleProblem(r.Value); msg != "" {
				add("%s rules[%d]: %s", where, j, msg)
			}
		}
		if a.Default != nil {
			if msg := fleetRoleProblem(*a.Default); msg != "" {
				add("%s default: %s", where, msg)
			}
		}
		if scope == FleetRoleGlobal {
			continue
		}
		if prev, dup := fleetIDs[id]; dup && prev != scope {
			add("%s: both FLEET_JIT_USER_ROLE_FLEET_%d and FLEET_JIT_USER_ROLE_TEAM_%d are configured; use only FLEET_%d",
				where, id, id, id)
		}
		fleetIDs[id] = scope
	}
	if fleetRoles {
		if p := defaultScopeProblem(attrs); p != "" {
			add("%s", p)
		}
	}
	return problems
}

func validateRule(add func(string, ...any), where string, r Rule) {
	hasGroup, hasClaim := r.Group != "", r.Claim != nil
	switch {
	case hasGroup && hasClaim:
		add("%s: set either group or claim, not both", where)
	case !hasGroup && !hasClaim:
		add("%s: set one of group or claim", where)
	case hasClaim && (r.Claim.Name == "" || r.Claim.Equals == ""):
		add("%s: claim needs both name and equals", where)
	}
	if r.Value == "" {
		add("%s: value is required", where)
	}
}

func fleetRoleProblem(v string) string {
	if v == "gitops" {
		return `role "gitops" is only for API-only users and cannot be assigned via SSO`
	}
	if !slices.Contains(FleetRoles, v) {
		return fmt.Sprintf("invalid Fleet role %q (allowed: %s)", v, strings.Join(FleetRoles, ", "))
	}
	return ""
}

// HasFleetRoleAttributes reports whether any attribute name is a Fleet JIT
// role attribute, or any passthrough prefix could produce one.
func HasFleetRoleAttributes(attrs []Attribute, passthroughPrefixes []string) bool {
	for _, a := range attrs {
		if _, _, ok := ParseFleetRoleAttribute(a.Name); ok {
			return true
		}
	}
	for _, p := range passthroughPrefixes {
		// Either direction overlaps: prefix "FLEET_" can produce role
		// attributes, and so can "FLEET_JIT_USER_ROLE_GLOBAL".
		if strings.HasPrefix("FLEET_JIT_USER_ROLE_", p) || strings.HasPrefix(p, "FLEET_JIT_USER_ROLE_") { //nolint:gocritic // argOrder: reversed order is intentional, see above
			return true
		}
	}
	return false
}
