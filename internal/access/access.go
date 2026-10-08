// Package access is symbiont's single authorization point. Every SAML
// assertion, SP- or IdP-initiated, is decided by Decide: the target service
// provider's access policy first, then its attribute mapping and Fleet role
// validation. check-mapping uses the same function.
package access

import (
	"slices"
	"strings"

	"github.com/kc9wwh/symbiont-sso/internal/config"
	"github.com/kc9wwh/symbiont-sso/internal/mapping"
)

// Denial reasons (logged at WARN).
const (
	ReasonNoMatchingGroup = "no_matching_group"
	ReasonEmailNotAllowed = "email_not_allowed"
	ReasonNotConfigured   = "no_access_rule" // defensive: empty policy
)

// Subject is the identity being authorized.
type Subject struct {
	Email  string
	Groups []string
	Claims map[string]any
}

// Decision is the outcome of Decide.
type Decision struct {
	Allowed bool
	// Reason is set when Allowed is false.
	Reason string
	// Mapping is set when Allowed is true and mapping succeeded.
	Mapping *mapping.Result
}

// Allowed evaluates p (default deny). Groups match exactly and
// case-sensitively; emails case-insensitively.
func Allowed(p config.AccessPolicy, email string, groups []string) (bool, string) {
	if p.AllowAll {
		return true, ""
	}
	for _, g := range p.AllowGroups {
		if slices.Contains(groups, g) {
			return true, ""
		}
	}
	if slices.Contains(p.AllowEmails, strings.ToLower(strings.TrimSpace(email))) {
		return true, ""
	}
	switch {
	case len(p.AllowGroups) > 0:
		return false, ReasonNoMatchingGroup
	case len(p.AllowEmails) > 0:
		return false, ReasonEmailNotAllowed
	default:
		return false, ReasonNotConfigured
	}
}

// Decide authorizes s for sp and, if allowed, resolves sp's attributes. A
// denied subject's mapping is never evaluated. A non-nil error (always a
// *mapping.Error) means the subject is allowed but the assertion must be
// refused (e.g. a Fleet role conflict).
func Decide(sp *config.ServiceProvider, s Subject) (*Decision, error) {
	if ok, reason := Allowed(sp.Access, s.Email, s.Groups); !ok {
		return &Decision{Reason: reason}, nil
	}
	res, err := mapping.Evaluate(SpecFor(sp), mapping.Input{Groups: s.Groups, Claims: s.Claims})
	if err != nil {
		return &Decision{Allowed: true}, err
	}
	return &Decision{Allowed: true, Mapping: res}, nil
}

// SpecFor extracts sp's mapping configuration.
func SpecFor(sp *config.ServiceProvider) mapping.Spec {
	return mapping.Spec{
		Attributes:          sp.Attributes,
		PassthroughPrefixes: sp.PassthroughPrefixes,
		FleetRoleValidation: sp.FleetRoleValidation,
	}
}
