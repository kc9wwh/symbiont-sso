package mapping

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Spec is one service provider's mapping configuration.
type Spec struct {
	Attributes          []Attribute
	PassthroughPrefixes []string
	FleetRoleValidation bool
}

// Input is the identity a mapping is evaluated against.
type Input struct {
	Groups []string
	Claims map[string]any
}

// Source records where an attribute value came from.
type Source string

// Attribute sources.
const (
	SourcePassthrough Source = "passthrough"
	SourceRule        Source = "rule"
	SourceDefault     Source = "default"
)

// Value is one resolved, single-valued SAML attribute.
type Value struct {
	Name   string
	Value  string
	Source Source
}

// Result is the outcome of a successful evaluation.
type Result struct {
	Attributes []Value
	// Notes explain overrides, dropped defaults and skipped claims. They
	// name attributes but never contain values; log them at debug level.
	Notes []string
}

// Error categories for rejected evaluations.
const (
	CategoryRoleConflict   = "fleet_role_conflict"
	CategoryInvalidRole    = "invalid_fleet_role"
	CategoryFleetTeamClash = "fleet_team_duplicate"
)

// MsgRoleConflict is the user-facing explanation for a role conflict.
const MsgRoleConflict = "conflicting Fleet roles: user matched both global and fleet-level role rules"

// Error rejects an assertion. Message is safe to show to users (it never
// contains claim values).
type Error struct {
	Category string
	Message  string
	// Attribute is the offending attribute (= claim name, for passthrough),
	// when one is responsible. Names only; never values.
	Attribute string
	// Source is where Attribute's value came from.
	Source Source
}

func (e *Error) Error() string { return e.Message }

// Evaluate resolves SAML attributes for in according to spec:
//
//  1. Passthrough: every scalar claim whose name starts with a configured
//     prefix becomes an attribute of the same name.
//  2. Rules: per attribute, the first matching rule wins; otherwise the
//     default (if any). A rule/default value overrides a passthrough value
//     of the same name; if no rule matches and there is no default, a
//     passthrough value is kept.
//  3. Fleet role validation (if enabled), see fleetCheck.
func Evaluate(spec Spec, in Input) (*Result, error) {
	res := &Result{}
	index := map[string]int{}
	set := func(v Value) {
		if i, ok := index[v.Name]; ok {
			res.Attributes[i] = v
			return
		}
		index[v.Name] = len(res.Attributes)
		res.Attributes = append(res.Attributes, v)
	}

	if len(spec.PassthroughPrefixes) > 0 {
		keys := make([]string, 0, len(in.Claims))
		for k := range in.Claims {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if !hasAnyPrefix(k, spec.PassthroughPrefixes) {
				continue
			}
			switch {
			case slices.Contains(ReservedAttributeNames, k):
				res.Notes = append(res.Notes, fmt.Sprintf("passthrough claim %q skipped: reserved attribute name", k))
				continue
			case strings.ContainsFunc(k, func(r rune) bool { return r <= ' ' || r == 0x7f }):
				res.Notes = append(res.Notes, fmt.Sprintf("passthrough claim %q skipped: invalid attribute name", k))
				continue
			}
			s, ok := scalarString(in.Claims[k])
			if !ok {
				res.Notes = append(res.Notes, fmt.Sprintf("passthrough claim %q skipped: not a single string, number or boolean", k))
				continue
			}
			set(Value{Name: k, Value: s, Source: SourcePassthrough})
		}
	}

	for _, a := range spec.Attributes {
		v, src, ok := evalAttribute(a, in)
		if !ok {
			continue
		}
		if i, exists := index[a.Name]; exists && res.Attributes[i].Source == SourcePassthrough {
			res.Notes = append(res.Notes, fmt.Sprintf("attribute %q: %s value overrides passthrough claim", a.Name, src))
		}
		set(Value{Name: a.Name, Value: v, Source: src})
	}

	if spec.FleetRoleValidation {
		if err := fleetCheck(res); err != nil {
			return nil, err
		}
	}
	return res, nil
}

func evalAttribute(a Attribute, in Input) (string, Source, bool) {
	for _, r := range a.Rules {
		if ruleMatches(r, in) {
			return r.Value, SourceRule, true
		}
	}
	if a.Default != nil {
		return *a.Default, SourceDefault, true
	}
	return "", "", false
}

func ruleMatches(r Rule, in Input) bool {
	if r.Group != "" {
		return slices.Contains(in.Groups, r.Group)
	}
	if r.Claim == nil {
		return false
	}
	switch v := in.Claims[r.Claim.Name].(type) {
	case []any:
		for _, e := range v {
			if s, ok := scalarString(e); ok && s == r.Claim.Equals {
				return true
			}
		}
		return false
	default:
		s, ok := scalarString(v)
		return ok && s == r.Claim.Equals
	}
}

// scalarString renders JSON scalars (string, number, boolean).
func scalarString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case int:
		return strconv.Itoa(t), true
	case int64:
		return strconv.FormatInt(t, 10), true
	}
	return "", false
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
