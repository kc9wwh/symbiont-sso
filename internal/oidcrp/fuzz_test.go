package oidcrp

import (
	"errors"
	"strings"
	"testing"
)

// FuzzExtractIdentityEmail: the email claim comes from the upstream IdP and
// feeds the domain allowlist. A crafted value (display name, second "@",
// comments, whitespace) must never be accepted with a domain different from
// the one the policy checked.
func FuzzExtractIdentityEmail(f *testing.F) {
	for _, s := range []string{"alice@example.com", " Alice@Example.COM ", "x@evil.com@allowed.com", "Alice <a@allowed.com>",
		"a b@allowed.com", "a@", "@allowed.com", "nodomain", "\"a@evil.com\"@allowed.com", "a@allowed.com (evil.com)",
		"a@[127.0.0.1]", "a@allowed.com\n", "a@ALLOWED.com", "a@allowed.com.", "caf\u00e9@allowed.com"} {
		f.Add(s)
	}
	pol := Policy{AllowedDomains: []string{"allowed.com"}}
	f.Fuzz(func(t *testing.T, email string) {
		id, err := ExtractIdentity(res(map[string]any{"email": email}), names, pol)
		if err != nil {
			var e *Error
			if !errors.As(err, &e) || e.Category == "" {
				t.Fatalf("error is %T (%v), want *Error with a category", err, err)
			}
			return
		}
		if id.Email != strings.TrimSpace(email) {
			t.Fatalf("Email = %q, want trimmed %q", id.Email, email)
		}
		if strings.Count(id.Email, "@") != 1 {
			t.Fatalf("accepted %q with %d '@' characters", id.Email, strings.Count(id.Email, "@"))
		}
		domain := strings.ToLower(id.Email[strings.LastIndexByte(id.Email, '@')+1:])
		if domain != "allowed.com" {
			t.Fatalf("accepted %q whose domain %q is not on the allowlist", id.Email, domain)
		}
		if strings.ContainsAny(id.Email, " \t\r\n<>()\"") {
			t.Fatalf("accepted %q containing display-name or comment syntax", id.Email)
		}
	})
}
