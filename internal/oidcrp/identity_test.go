package oidcrp

import (
	"errors"
	"slices"
	"testing"
	"time"
)

var names = ClaimNames{Email: "email", Name: "name", Groups: "groups"}

func res(claims map[string]any) *Result { return &Result{Subject: "sub", Claims: claims} }

func TestExtractIdentity(t *testing.T) {
	id, err := ExtractIdentity(res(map[string]any{
		"email": " Alice@Example.com ", "email_verified": true, "name": " Alice ",
		"groups": []any{"a", "b"}, "department": "it",
		"iss": "x", "aud": "y", "nonce": "n", "exp": 1.0, "auth_time": 1700000000.0,
	}), names, Policy{RequireEmailVerified: true, AllowedDomains: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if id.Email != "Alice@Example.com" || id.Name != "Alice" || !slices.Equal(id.Groups, []string{"a", "b"}) {
		t.Errorf("identity = %+v", id)
	}
	if id.Claims["department"] != "it" {
		t.Error("non-protocol claim dropped")
	}
	for _, k := range []string{"iss", "aud", "nonce", "exp", "auth_time"} {
		if _, ok := id.Claims[k]; ok {
			t.Errorf("protocol claim %q retained", k)
		}
	}
	if !id.AuthTime.Equal(time.Unix(1700000000, 0)) {
		t.Errorf("AuthTime = %v", id.AuthTime)
	}
}

func TestExtractIdentityCustomClaimNamesAndShapes(t *testing.T) {
	id, err := ExtractIdentity(res(map[string]any{
		"mail": "bob@example.com", "display": "Bob", "roles": "single-group", "email_verified": "true",
	}), ClaimNames{Email: "mail", Name: "display", Groups: "roles"}, Policy{RequireEmailVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "Bob" || !slices.Equal(id.Groups, []string{"single-group"}) {
		t.Errorf("identity = %+v", id)
	}
	id, err = ExtractIdentity(res(map[string]any{"email": "c@example.com"}), names, Policy{})
	if err != nil || id.Groups != nil {
		t.Errorf("absent groups: %+v %v", id, err)
	}
}

func TestExtractIdentityRejections(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
		pol    Policy
		cat    string
	}{
		{"missing email", map[string]any{"email_verified": true}, Policy{}, CategoryMissingEmail},
		{"empty email", map[string]any{"email": "  "}, Policy{}, CategoryMissingEmail},
		{"not an email", map[string]any{"email": "alice"}, Policy{}, CategoryMissingEmail},
		{"email not string", map[string]any{"email": 42.0}, Policy{}, CategoryMissingEmail},
		{"unverified", map[string]any{"email": "a@example.com", "email_verified": false}, Policy{RequireEmailVerified: true}, CategoryEmailUnverified},
		{"verified absent", map[string]any{"email": "a@example.com"}, Policy{RequireEmailVerified: true}, CategoryEmailUnverified},
		{"domain blocked", map[string]any{"email": "a@evil.com"}, Policy{AllowedDomains: []string{"example.com"}}, CategoryDomainNotAllowed},
		{"subdomain is not the domain", map[string]any{"email": "a@sub.example.com"}, Policy{AllowedDomains: []string{"example.com"}}, CategoryDomainNotAllowed},
		{"groups wrong type", map[string]any{"email": "a@example.com", "groups": 5.0}, Policy{}, CategoryBadGroups},
		{"groups mixed array", map[string]any{"email": "a@example.com", "groups": []any{"a", 1.0}}, Policy{}, CategoryBadGroups},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ExtractIdentity(res(tc.claims), names, tc.pol)
			var oe *Error
			if !errors.As(err, &oe) || oe.Category != tc.cat {
				t.Errorf("err = %v, want %s", err, tc.cat)
			}
		})
	}
}

func TestDomainCheckIsCaseInsensitive(t *testing.T) {
	if _, err := ExtractIdentity(res(map[string]any{"email": "a@EXAMPLE.com"}), names,
		Policy{AllowedDomains: []string{"example.com"}}); err != nil {
		t.Errorf("err = %v", err)
	}
}
