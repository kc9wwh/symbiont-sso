package config

import (
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"
)

func mustLoad(t *testing.T, f *fixture) *Config {
	t.Helper()
	cfg, err := Load(f.lookup)
	if err != nil {
		t.Fatalf("Load: unexpected error: %v", err)
	}
	return cfg
}

// loadProblems runs Load expecting failure and returns the problem list.
func loadProblems(t *testing.T, lookup LookupFunc) []string {
	t.Helper()
	cfg, err := Load(lookup)
	if err == nil {
		t.Fatalf("Load: expected error, got config %+v", cfg)
	}
	var cerr *Error
	if !errors.As(err, &cerr) {
		t.Fatalf("Load: error is %T, want *config.Error", err)
	}
	return cerr.Problems
}

func requireProblem(t *testing.T, problems []string, substr string) {
	t.Helper()
	for _, p := range problems {
		if strings.Contains(p, substr) {
			return
		}
	}
	t.Fatalf("no problem containing %q in:\n  %s", substr, strings.Join(problems, "\n  "))
}

func TestLoadDefaults(t *testing.T) {
	f := newFixture(t)
	cfg := mustLoad(t, f)

	if got := cfg.BaseURL.String(); got != "https://saml.example.com" {
		t.Errorf("BaseURL = %q", got)
	}
	if got := cfg.CallbackURL(); got != "https://saml.example.com/oidc/callback" {
		t.Errorf("CallbackURL = %q", got)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q", cfg.ListenAddr)
	}
	if want := []string{"openid", "email", "profile", "groups"}; !slices.Equal(cfg.OIDC.Scopes, want) {
		t.Errorf("Scopes = %v, want %v", cfg.OIDC.Scopes, want)
	}
	if cfg.OIDC.EmailClaim != "email" || cfg.OIDC.NameClaim != "name" || cfg.OIDC.GroupsClaim != "groups" {
		t.Errorf("claim defaults = %q/%q/%q", cfg.OIDC.EmailClaim, cfg.OIDC.NameClaim, cfg.OIDC.GroupsClaim)
	}
	if !cfg.OIDC.FetchUserinfo || !cfg.OIDC.RequireEmailVerified {
		t.Errorf("FetchUserinfo=%v RequireEmailVerified=%v, want true/true", cfg.OIDC.FetchUserinfo, cfg.OIDC.RequireEmailVerified)
	}
	if cfg.OIDC.Prompt != "" {
		t.Errorf("Prompt = %q, want empty", cfg.OIDC.Prompt)
	}
	if cfg.AllowedEmailDomains != nil {
		t.Errorf("AllowedEmailDomains = %v, want nil", cfg.AllowedEmailDomains)
	}
	if cfg.Session.TTL != 60*time.Second || cfg.PendingRequestTTL != 10*time.Minute {
		t.Errorf("TTLs = %v/%v", cfg.Session.TTL, cfg.PendingRequestTTL)
	}
	if cfg.Session.Secret.Len() != 32 {
		t.Errorf("session secret len = %d, want 32 decoded bytes", cfg.Session.Secret.Len())
	}
	if string(cfg.OIDC.ClientSecret.Bytes()) != "client-secret-value" {
		t.Errorf("client secret not loaded")
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v", cfg.LogLevel)
	}
	if cfg.SAML.Certificate == nil || cfg.SAML.PrivateKey == nil {
		t.Errorf("SAML key pair not loaded")
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", cfg.Warnings)
	}
}

func TestLoadOverrides(t *testing.T) {
	f := newFixture(t)
	f.env[EnvBaseURL] = "https://SAML.Example.com:8443/"
	f.env[EnvListenAddr] = "127.0.0.1:9000"
	f.env[EnvOIDCScopes] = " openid  email openid "
	f.env[EnvOIDCEmailClaim] = "preferred_email"
	f.env[EnvOIDCFetchUserinfo] = "false"
	f.env[EnvOIDCPrompt] = "login  select_account"
	f.env[EnvOIDCRequireVerified] = "0"
	f.env[EnvAllowedEmailDomains] = " Example.com, @corp.example.org ,,example.com"
	f.env[EnvSessionTTL] = "5m"
	f.env[EnvPendingRequestTTL] = "90s"
	f.env[EnvLogLevel] = "DEBUG"
	cfg := mustLoad(t, f)

	if got := cfg.BaseURL.String(); got != "https://saml.example.com:8443" {
		t.Errorf("BaseURL = %q (trailing slash stripped, host lower-cased)", got)
	}
	if got := cfg.URL("/metadata"); got != "https://saml.example.com:8443/metadata" {
		t.Errorf("URL(/metadata) = %q", got)
	}
	if cfg.ListenAddr != "127.0.0.1:9000" {
		t.Errorf("ListenAddr = %q", cfg.ListenAddr)
	}
	if want := []string{"openid", "email"}; !slices.Equal(cfg.OIDC.Scopes, want) {
		t.Errorf("Scopes = %v, want %v (deduplicated)", cfg.OIDC.Scopes, want)
	}
	if cfg.OIDC.EmailClaim != "preferred_email" || cfg.OIDC.FetchUserinfo || cfg.OIDC.RequireEmailVerified {
		t.Errorf("OIDC overrides not applied: %+v", cfg.OIDC)
	}
	if cfg.OIDC.Prompt != "login select_account" {
		t.Errorf("Prompt = %q", cfg.OIDC.Prompt)
	}
	if want := []string{"example.com", "corp.example.org"}; !slices.Equal(cfg.AllowedEmailDomains, want) {
		t.Errorf("AllowedEmailDomains = %v, want %v", cfg.AllowedEmailDomains, want)
	}
	if cfg.Session.TTL != 5*time.Minute || cfg.PendingRequestTTL != 90*time.Second {
		t.Errorf("TTLs = %v/%v", cfg.Session.TTL, cfg.PendingRequestTTL)
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Errorf("LogLevel = %v", cfg.LogLevel)
	}
}
