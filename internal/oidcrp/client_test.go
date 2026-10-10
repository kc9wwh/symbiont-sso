package oidcrp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/oauth2-proxy/mockoidc"

	"github.com/kc9wwh/symbiont-sso/internal/oidcrp"
	"github.com/kc9wwh/symbiont-sso/internal/oidcrp/oidctest"
)

const redirect = "https://saml.example.com/oidc/callback"

func newClient(t *testing.T, m *mockoidc.MockOIDC, fetchUserinfo bool) *oidcrp.Client {
	t.Helper()
	c, err := oidcrp.New(context.Background(), oidcrp.Options{
		Issuer: m.Issuer(), ClientID: m.ClientID, ClientSecret: m.ClientSecret,
		RedirectURL: redirect, Scopes: []string{"openid", "email", "profile", "groups"},
		FetchUserinfo: fetchUserinfo,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// login runs the authorization step and returns the code.
func login(t *testing.T, c *oidcrp.Client, state, nonce, verifier string) string {
	t.Helper()
	back := oidctest.Authorize(t, c.AuthCodeURL(state, nonce, verifier, false))
	if got := back.Query().Get("state"); got != state {
		t.Fatalf("state round-trip = %q", got)
	}
	return back.Query().Get("code")
}

func requireCategory(t *testing.T, err error, cat string) {
	t.Helper()
	var oe *oidcrp.Error
	if !errors.As(err, &oe) || oe.Category != cat {
		t.Fatalf("err = %v, want category %s", err, cat)
	}
}

func TestAuthCodeURL(t *testing.T) {
	m := oidctest.Start(t)
	c, err := oidcrp.New(context.Background(), oidcrp.Options{
		Issuer: m.Issuer(), ClientID: m.ClientID, RedirectURL: redirect,
		Scopes: []string{"openid", "email"}, Prompt: "login",
	})
	if err != nil {
		t.Fatal(err)
	}
	u := c.AuthCodeURL("st", "nn", oidcrp.NewVerifier(), false)
	for _, want := range []string{"state=st", "nonce=nn", "code_challenge_method=S256", "code_challenge=", "prompt=login",
		"response_type=code", "scope=openid+email", "redirect_uri=https%3A%2F%2Fsaml.example.com%2Foidc%2Fcallback"} {
		if !strings.Contains(u, want) {
			t.Errorf("auth URL missing %s: %s", want, u)
		}
	}
}

func TestAuthCodeURLForceLogin(t *testing.T) {
	m := oidctest.Start(t)
	for _, tc := range []struct{ prompt, want string }{
		{"", "prompt=login"},
		{"login", "prompt=login"},
		{"select_account", "prompt=login+select_account"},
	} {
		c, err := oidcrp.New(context.Background(), oidcrp.Options{
			Issuer: m.Issuer(), ClientID: m.ClientID, RedirectURL: redirect,
			Scopes: []string{"openid"}, Prompt: tc.prompt,
		})
		if err != nil {
			t.Fatal(err)
		}
		u := c.AuthCodeURL("st", "nn", oidcrp.NewVerifier(), true)
		if !strings.Contains(u, tc.want) || strings.Contains(u, tc.want+"+login") {
			t.Errorf("prompt %q: auth URL %s, want %s once", tc.prompt, u, tc.want)
		}
		if strings.Contains(c.AuthCodeURL("st", "nn", oidcrp.NewVerifier(), false), "prompt=login") && tc.prompt == "" {
			t.Error("prompt=login added without forceLogin")
		}
	}
}

func TestExchangeMergesUserinfoIDTokenWins(t *testing.T) {
	m := oidctest.Start(t)
	m.QueueUser(&oidctest.User{
		Sub:            "sub-1",
		IDToken:        map[string]any{"email": "alice@example.com", "email_verified": true, "name": "From ID token"},
		UserinfoClaims: map[string]any{"name": "From userinfo", "groups": []string{"fleet-admins"}},
	})
	c := newClient(t, m, true)
	v := oidcrp.NewVerifier()
	res, err := c.Exchange(context.Background(), login(t, c, "s", "n", v), v, "n")
	if err != nil {
		t.Fatal(err)
	}
	if res.Subject != "sub-1" || res.Claims["name"] != "From ID token" {
		t.Errorf("result = %+v (ID token must win on conflict)", res)
	}
	if g, _ := res.Claims["groups"].([]any); len(g) != 1 || g[0] != "fleet-admins" {
		t.Errorf("userinfo-only claim not merged: %v", res.Claims["groups"])
	}
}

func TestExchangeWithoutUserinfo(t *testing.T) {
	m := oidctest.Start(t)
	m.QueueUser(oidctest.Alice("g"))
	c := newClient(t, m, false)
	v := oidcrp.NewVerifier()
	res, err := c.Exchange(context.Background(), login(t, c, "s", "n", v), v, "n")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.Claims["groups"]; ok {
		t.Error("userinfo fetched although disabled")
	}
}

func TestExchangeFailures(t *testing.T) {
	ctx := context.Background()
	t.Run("nonce mismatch", func(t *testing.T) {
		m := oidctest.Start(t)
		c := newClient(t, m, false)
		v := oidcrp.NewVerifier()
		_, err := c.Exchange(ctx, login(t, c, "s", "real-nonce", v), v, "other-nonce")
		requireCategory(t, err, oidcrp.CategoryNonce)
	})
	t.Run("userinfo sub mismatch", func(t *testing.T) {
		m := oidctest.Start(t)
		m.QueueUser(&oidctest.User{Sub: "sub-1", UserinfoClaims: map[string]any{"sub": "sub-2"}})
		c := newClient(t, m, true)
		v := oidcrp.NewVerifier()
		_, err := c.Exchange(ctx, login(t, c, "s", "n", v), v, "n")
		requireCategory(t, err, oidcrp.CategorySubjectMismatch)
	})
	t.Run("userinfo without sub", func(t *testing.T) {
		m := oidctest.Start(t) // mockoidc's default user omits sub from userinfo
		c := newClient(t, m, true)
		v := oidcrp.NewVerifier()
		_, err := c.Exchange(ctx, login(t, c, "s", "n", v), v, "n")
		requireCategory(t, err, oidcrp.CategorySubjectMismatch)
		if !strings.Contains(err.Error(), "no sub claim") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("wrong PKCE verifier", func(t *testing.T) {
		m := oidctest.Start(t)
		c := newClient(t, m, false)
		code := login(t, c, "s", "n", oidcrp.NewVerifier())
		_, err := c.Exchange(ctx, code, oidcrp.NewVerifier(), "n")
		requireCategory(t, err, oidcrp.CategoryTokenExchange)
	})
	t.Run("code reuse", func(t *testing.T) {
		m := oidctest.Start(t)
		c := newClient(t, m, false)
		v := oidcrp.NewVerifier()
		code := login(t, c, "s", "n", v)
		if _, err := c.Exchange(ctx, code, v, "n"); err != nil {
			t.Fatal(err)
		}
		_, err := c.Exchange(ctx, code, v, "n")
		requireCategory(t, err, oidcrp.CategoryTokenExchange)
	})
	t.Run("expired ID token", func(t *testing.T) {
		m := oidctest.Start(t)
		// The verifier's clock runs an hour ahead; mockoidc tokens live 10m.
		c, err := oidcrp.New(ctx, oidcrp.Options{
			Issuer: m.Issuer(), ClientID: m.ClientID, ClientSecret: m.ClientSecret,
			RedirectURL: redirect, Scopes: []string{"openid"},
			Now: func() time.Time { return time.Now().Add(time.Hour) },
		})
		if err != nil {
			t.Fatal(err)
		}
		v := oidcrp.NewVerifier()
		_, err = c.Exchange(ctx, login(t, c, "s", "n", v), v, "n")
		requireCategory(t, err, oidcrp.CategoryIDToken)
	})
	t.Run("wrong client secret", func(t *testing.T) {
		m := oidctest.Start(t)
		c, err := oidcrp.New(ctx, oidcrp.Options{
			Issuer: m.Issuer(), ClientID: m.ClientID, ClientSecret: "wrong",
			RedirectURL: redirect, Scopes: []string{"openid"},
		})
		if err != nil {
			t.Fatal(err)
		}
		v := oidcrp.NewVerifier()
		_, err = c.Exchange(ctx, login(t, c, "s", "n", v), v, "n")
		requireCategory(t, err, oidcrp.CategoryTokenExchange)
	})
	t.Run("idp error queued on token endpoint", func(t *testing.T) {
		m := oidctest.Start(t)
		c := newClient(t, m, false)
		v := oidcrp.NewVerifier()
		code := login(t, c, "s", "n", v)
		// oauth2 auto-detects the client auth style, retrying once with the
		// other style after a failure, so fail both attempts.
		for range 2 {
			m.QueueError(&mockoidc.ServerError{Code: http.StatusInternalServerError, Error: "server_error"})
		}
		_, err := c.Exchange(ctx, code, v, "n")
		requireCategory(t, err, oidcrp.CategoryTokenExchange)
	})
}

// discoveryServer serves a minimal discovery document with the given extra
// fields, for warning tests.
func discoveryServer(t *testing.T, extra map[string]any) string {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"issuer": srv.URL, "authorization_endpoint": srv.URL + "/auth", "token_endpoint": srv.URL + "/token",
			"jwks_uri": srv.URL + "/jwks", "userinfo_endpoint": srv.URL + "/userinfo",
		}
		for k, v := range extra {
			doc[k] = v
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}
