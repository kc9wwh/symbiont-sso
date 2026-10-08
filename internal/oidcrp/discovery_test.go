package oidcrp_test

import (
	"context"
	"strings"
	"testing"

	"github.com/kc9wwh/symbiont-sso/internal/oidcrp"
)

func TestDiscoveryWarnings(t *testing.T) {
	tests := []struct {
		name   string
		extra  map[string]any
		prompt string
		scopes []string
		want   []string // substrings, one per expected warning
	}{
		{
			name:   "prompt not supported",
			extra:  map[string]any{"prompt_values_supported": []string{"none", "consent"}},
			prompt: "login", scopes: []string{"openid"},
			want: []string{`OIDC_PROMPT value "login" is not listed in the provider's prompt_values_supported`},
		},
		{
			name:   "prompt supported",
			extra:  map[string]any{"prompt_values_supported": []string{"login", "consent"}},
			prompt: "login", scopes: []string{"openid"},
		},
		{
			name:   "prompt_values_supported absent: no warning",
			prompt: "login", scopes: []string{"openid"},
		},
		{
			name:   "no prompt configured",
			extra:  map[string]any{"prompt_values_supported": []string{"none"}},
			scopes: []string{"openid"},
		},
		{
			name:  "S256 missing",
			extra: map[string]any{"code_challenge_methods_supported": []string{"plain"}}, scopes: []string{"openid"},
			want: []string{"does not list S256"},
		},
		{
			name:  "scope not supported",
			extra: map[string]any{"scopes_supported": []string{"openid", "email"}}, scopes: []string{"openid", "groups"},
			want: []string{`OIDC_SCOPES requests "groups"`},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			issuer := discoveryServer(t, tc.extra)
			c, err := oidcrp.New(context.Background(), oidcrp.Options{
				Issuer: issuer, ClientID: "c", RedirectURL: redirect, Scopes: tc.scopes, Prompt: tc.prompt,
			})
			if err != nil {
				t.Fatal(err)
			}
			got := c.Warnings()
			if len(got) != len(tc.want) {
				t.Fatalf("warnings = %v, want %d", got, len(tc.want))
			}
			for i, w := range tc.want {
				if !strings.Contains(got[i], w) {
					t.Errorf("warning %q does not contain %q", got[i], w)
				}
			}
		})
	}
}

func TestNewFailures(t *testing.T) {
	ctx := context.Background()
	issuer := discoveryServer(t, nil)
	tests := []struct {
		name string
		o    oidcrp.Options
		want string
	}{
		{"missing fields", oidcrp.Options{Issuer: issuer}, "required"},
		{"issuer mismatch", oidcrp.Options{Issuer: issuer + "/", ClientID: "c", RedirectURL: redirect}, "including any trailing slash"},
		{"unreachable", oidcrp.Options{Issuer: "http://127.0.0.1:1", ClientID: "c", RedirectURL: redirect}, "OIDC discovery for"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := oidcrp.New(ctx, tc.o)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestNoUserinfoEndpointWithFetchEnabled(t *testing.T) {
	issuer := discoveryServer(t, map[string]any{"userinfo_endpoint": ""})
	_, err := oidcrp.New(context.Background(), oidcrp.Options{
		Issuer: issuer, ClientID: "c", RedirectURL: redirect, FetchUserinfo: true,
	})
	if err == nil || !strings.Contains(err.Error(), "OIDC_FETCH_USERINFO=false") {
		t.Errorf("err = %v", err)
	}
}
