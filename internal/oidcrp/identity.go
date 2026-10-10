package oidcrp

import (
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"strings"
	"time"
)

// ClaimNames selects which claims carry email, name, and groups.
type ClaimNames struct {
	Email  string
	Name   string
	Groups string
}

// Policy is the global (pre-SP) gate applied to every login.
type Policy struct {
	RequireEmailVerified bool
	// AllowedDomains is lower-cased; empty allows any domain.
	AllowedDomains []string
}

// Identity is the user extracted from verified claims.
type Identity struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
	// Claims holds the merged claims minus protocol claims (iss, aud, exp,
	// nonce, ...), for use by attribute mapping rules.
	Claims map[string]any
	// AuthTime is the upstream authentication time (auth_time), if sent.
	AuthTime time.Time
}

// protocolClaims carry token mechanics rather than user identity; they are
// never stored in bridge sessions.
var protocolClaims = []string{
	"iss", "aud", "exp", "iat", "nbf", "jti", "nonce", "at_hash", "c_hash",
	"azp", "sid", "auth_time", "acr", "amr",
}

// Identity rejection categories (logged; users see generic text).
const (
	CategoryMissingEmail     = "missing_email"
	CategoryEmailUnverified  = "email_not_verified"
	CategoryDomainNotAllowed = "global_domain_block"
	CategoryBadGroups        = "invalid_groups_claim"
)

// ExtractIdentity pulls email, name and groups out of claims and applies the
// global email policy.
func ExtractIdentity(res *Result, names ClaimNames, pol Policy) (*Identity, error) {
	email, _ := res.Claims[names.Email].(string)
	email = strings.TrimSpace(email)
	if !validEmail(email) {
		return nil, &Error{Category: CategoryMissingEmail,
			Err: fmt.Errorf("claim %q is missing or not an email address", names.Email)}
	}
	if pol.RequireEmailVerified && !truthy(res.Claims["email_verified"]) {
		return nil, &Error{Category: CategoryEmailUnverified, Err: errors.New("email_verified is not true")}
	}
	domain := strings.ToLower(email[strings.LastIndexByte(email, '@')+1:])
	if len(pol.AllowedDomains) > 0 && !slices.Contains(pol.AllowedDomains, domain) {
		return nil, &Error{Category: CategoryDomainNotAllowed, Err: fmt.Errorf("email domain %q is not allowed", domain)}
	}
	groups, err := stringList(res.Claims[names.Groups])
	if err != nil {
		return nil, &Error{Category: CategoryBadGroups, Err: fmt.Errorf("claim %q: %w", names.Groups, err)}
	}
	name, _ := res.Claims[names.Name].(string)
	id := &Identity{
		Subject: res.Subject,
		Email:   email,
		Name:    strings.TrimSpace(name),
		Groups:  groups,
		Claims:  make(map[string]any, len(res.Claims)),
	}
	for k, v := range res.Claims {
		if !slices.Contains(protocolClaims, k) {
			id.Claims[k] = v
		}
	}
	if at, ok := res.Claims["auth_time"].(float64); ok && at > 0 {
		id.AuthTime = time.Unix(int64(at), 0).UTC()
	}
	return id, nil
}

// validEmail accepts a bare addr-spec with exactly one "@". Anything else
// (display names, extra "@", whitespace) could smuggle a different domain past
// the allowlist.
func validEmail(s string) bool {
	if strings.Count(s, "@") != 1 {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s
}

// truthy accepts a JSON boolean true or the string "true" (some providers,
// e.g. AWS Cognito, send strings).
func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	}
	return false
}

// stringList decodes an absent claim (nil), a string array, or a single
// string into a list.
func stringList(v any) ([]string, error) {
	switch t := v.(type) {
	case nil:
		return nil, nil
	case string:
		return []string{t}, nil
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("must be an array of strings, found element of type %T", e)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("must be an array of strings, got %T", v)
	}
}
