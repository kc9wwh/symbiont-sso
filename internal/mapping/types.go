package mapping

import (
	"regexp"
	"strconv"
)

// Attribute is one rule-based SAML attribute. Rules are evaluated top-down
// and the first match wins; Default (if set) is used when nothing matches.
type Attribute struct {
	Name    string  `yaml:"name"`
	Rules   []Rule  `yaml:"rules"`
	Default *string `yaml:"default"`
}

// Rule matches either a group membership or a claim value.
type Rule struct {
	Group string      `yaml:"group"`
	Claim *ClaimMatch `yaml:"claim"`
	Value string      `yaml:"value"`
}

// ClaimMatch matches a scalar claim equal to Equals, or an array claim that
// contains Equals.
type ClaimMatch struct {
	Name   string `yaml:"name"`
	Equals string `yaml:"equals"`
}

// FleetRoleScope identifies which Fleet JIT role attribute a name refers to.
type FleetRoleScope int

// Fleet role attribute scopes.
const (
	FleetRoleGlobal FleetRoleScope = iota + 1
	FleetRoleFleet                 // FLEET_JIT_USER_ROLE_FLEET_<id>
	FleetRoleTeam                  // legacy FLEET_JIT_USER_ROLE_TEAM_<id>
)

var fleetRoleRE = regexp.MustCompile(`^FLEET_JIT_USER_ROLE_(?:(GLOBAL)|FLEET_([0-9]+)|TEAM_([0-9]+))$`)

// ParseFleetRoleAttribute reports whether name is a Fleet JIT role attribute
// and, for fleet/team scoped names, returns the numeric ID.
func ParseFleetRoleAttribute(name string) (scope FleetRoleScope, id int, ok bool) {
	m := fleetRoleRE.FindStringSubmatch(name)
	if m == nil {
		return 0, 0, false
	}
	switch {
	case m[1] != "":
		return FleetRoleGlobal, 0, true
	case m[2] != "":
		id, err := strconv.Atoi(m[2])
		return FleetRoleFleet, id, err == nil
	default:
		id, err := strconv.Atoi(m[3])
		return FleetRoleTeam, id, err == nil
	}
}
