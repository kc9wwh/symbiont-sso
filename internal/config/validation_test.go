package config

import (
	"encoding/base64"
	"testing"
)

// TestLoadInvalidValues covers each single-variable validation rule. Every
// case starts from a valid fixture and breaks exactly one thing.
func TestLoadInvalidValues(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 31))
	const dirMarker = "<fixture dir>"
	tests := []struct {
		name, key, value, want string
	}{
		{"base url http non-local", EnvBaseURL, "http://saml.example.com", "must use https (http is only allowed for localhost)"},
		{"base url bad scheme", EnvBaseURL, "ftp://saml.example.com", "must use https"},
		{"base url relative", EnvBaseURL, "saml.example.com", "absolute URL including a host"},
		{"base url with path", EnvBaseURL, "https://example.com/saml", "must not include a path"},
		{"base url with query", EnvBaseURL, "https://saml.example.com?x=1", "must not include a query"},
		{"base url with fragment", EnvBaseURL, "https://saml.example.com#x", "must not contain a fragment"},
		{"base url with credentials", EnvBaseURL, "https://u:p@saml.example.com", "must not contain credentials"},
		{"base url unparsable", EnvBaseURL, "https://%zz", "not a valid URL"},
		{"localhost lookalike", EnvBaseURL, "http://localhost.evil.com", "must use https"},
		{"issuer http", EnvOIDCIssuer, "http://id.example.com", "OIDC_ISSUER must use https"},
		{"issuer query", EnvOIDCIssuer, "https://id.example.com?tenant=1", "OIDC_ISSUER must not include a query"},
		{"scopes without openid", EnvOIDCScopes, "email profile", `must include the "openid" scope`},
		{"claim with space", EnvOIDCGroupsClaim, "my groups", "OIDC_GROUPS_CLAIM must be a claim name"},
		{"bool garbage", EnvOIDCFetchUserinfo, "yes please", "OIDC_FETCH_USERINFO must be a boolean"},
		{"bool garbage verified", EnvOIDCRequireVerified, "maybe", "OIDC_REQUIRE_EMAIL_VERIFIED must be a boolean"},
		{"prompt none rejected", EnvOIDCPrompt, "none", `unsupported value "none"`},
		{"prompt unknown", EnvOIDCPrompt, "login bogus", `unsupported value "bogus"`},
		{"domain invalid", EnvAllowedEmailDomains, "example.com, bad_domain.com", `"bad_domain.com" is not a valid domain`},
		{"domain only commas", EnvAllowedEmailDomains, " , ,", "contains no domains"},
		{"domain leading hyphen", EnvAllowedEmailDomains, "-example.com", "not a valid domain"},
		{"session secret not base64", EnvSessionSecret, "not base64!!", "SESSION_SECRET must be base64-encoded"},
		{"session secret short", EnvSessionSecret, short, "must decode to at least 32 bytes, got 31"},
		{"session ttl unparsable", EnvSessionTTL, "60", "SESSION_TTL must be a Go duration"},
		{"session ttl zero", EnvSessionTTL, "0s", "SESSION_TTL must be greater than zero"},
		{"pending ttl negative", EnvPendingRequestTTL, "-1m", "PENDING_REQUEST_TTL must be greater than zero"},
		{"log level unknown", EnvLogLevel, "verbose", "LOG_LEVEL must be one of"},
		{"sp file missing", EnvSPConfigFile, "/nonexistent/symbiont.yaml", "SYMBIONT_SP_CONFIG_FILE: cannot open"},
		{"sp file is dir", EnvSPConfigFile, dirMarker, "is not a regular file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.env[tc.key] = tc.value
			if tc.value == dirMarker {
				f.env[tc.key] = f.dir
			}
			problems := loadProblems(t, f.lookup)
			requireProblem(t, problems, tc.want)
			if len(problems) != 1 {
				t.Errorf("want exactly one problem, got %d: %v", len(problems), problems)
			}
		})
	}
}

func TestLoadAcceptsValidValues(t *testing.T) {
	tests := []struct{ key, value string }{
		{EnvLogLevel, "warning"},
		{EnvLogLevel, "error"},
		{EnvSessionSecret, base64.RawURLEncoding.EncodeToString(make([]byte, 48))},
		{EnvOIDCIssuer, "https://id.example.com/"}, // trailing slash preserved
		{EnvOIDCIssuer, "https://login.example.com/realms/main"},
		{EnvOIDCPrompt, "consent"},
		{EnvOIDCFetchUserinfo, "FALSE"},
	}
	for _, tc := range tests {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			f := newFixture(t)
			f.env[tc.key] = tc.value
			cfg := mustLoad(t, f)
			if tc.key == EnvOIDCIssuer && cfg.OIDC.Issuer != tc.value {
				t.Errorf("issuer = %q, want verbatim %q", cfg.OIDC.Issuer, tc.value)
			}
		})
	}
}
