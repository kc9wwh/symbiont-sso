// Package oidctest provides a mock OIDC provider for tests, built on
// github.com/oauth2-proxy/mockoidc with fully scripted claims.
package oidctest

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/mockoidc"
)

// User is a mockoidc.User whose ID token and userinfo claims are given
// verbatim (no scope filtering), so tests can craft edge cases such as a
// userinfo sub that differs from the ID token sub.
type User struct {
	Sub string
	// IDToken claims are merged into the signed ID token (registered claims
	// such as iss/aud/exp/nonce are set by the provider and win).
	IDToken map[string]any
	// UserinfoClaims are returned verbatim by the userinfo endpoint; if it has no
	// "sub", Sub is used.
	UserinfoClaims map[string]any
}

var _ mockoidc.User = (*User)(nil)

// ID implements mockoidc.User.
func (u *User) ID() string { return u.Sub }

// Userinfo implements mockoidc.User.
func (u *User) Userinfo([]string) ([]byte, error) {
	m := map[string]any{"sub": u.Sub}
	maps.Copy(m, u.UserinfoClaims)
	return json.Marshal(m)
}

// Claims implements mockoidc.User.
func (u *User) Claims(_ []string, base *mockoidc.IDTokenClaims) (jwt.Claims, error) {
	return &idClaims{base: base, extra: u.IDToken}, nil
}

// idClaims serialises extra claims plus the provider's base claims.
type idClaims struct {
	base  *mockoidc.IDTokenClaims
	extra map[string]any
}

func (c *idClaims) MarshalJSON() ([]byte, error) {
	baseJSON, err := json.Marshal(c.base)
	if err != nil {
		return nil, err
	}
	m := map[string]any{}
	maps.Copy(m, c.extra)
	var b map[string]any
	if err := json.Unmarshal(baseJSON, &b); err != nil {
		return nil, err
	}
	maps.Copy(m, b) // registered claims win
	return json.Marshal(m)
}

func (c *idClaims) GetExpirationTime() (*jwt.NumericDate, error) { return c.base.GetExpirationTime() }
func (c *idClaims) GetIssuedAt() (*jwt.NumericDate, error)       { return c.base.GetIssuedAt() }
func (c *idClaims) GetNotBefore() (*jwt.NumericDate, error)      { return c.base.GetNotBefore() }
func (c *idClaims) GetIssuer() (string, error)                   { return c.base.GetIssuer() }
func (c *idClaims) GetSubject() (string, error)                  { return c.base.GetSubject() }
func (c *idClaims) GetAudience() (jwt.ClaimStrings, error)       { return c.base.GetAudience() }

// Alice is a typical verified user in the given groups.
func Alice(groups ...string) *User {
	return &User{
		Sub: "sub-alice",
		IDToken: map[string]any{
			"email": "alice@example.com", "email_verified": true, "name": "Alice Example",
		},
		UserinfoClaims: map[string]any{"groups": groups},
	}
}

// Start runs a mock provider for the duration of the test.
func Start(t testing.TB) *mockoidc.MockOIDC {
	t.Helper()
	m, err := mockoidc.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown() })
	return m
}

// Authorize drives the provider's authorization endpoint for an auth URL
// (as a browser would) and returns the redirect back to the client, which
// carries code and state.
func Authorize(t testing.TB, authURL string) *url.URL {
	t.Helper()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: status %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc
}
