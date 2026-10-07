// Package config parses and validates symbiont's environment configuration.
//
// All validation problems are collected and reported together so that an
// operator can fix a broken deployment in one pass. Secret-bearing variables
// additionally accept a "<NAME>_FILE" variant pointing at a file containing
// the value (Docker/Kubernetes secrets style).
package config

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"
)

// LookupFunc resolves an environment variable. It has the same contract as
// os.LookupEnv, which makes loading testable without touching the process
// environment.
type LookupFunc func(key string) (string, bool)

// Config is the fully validated runtime configuration.
type Config struct {
	// BaseURL is the public URL of the bridge (scheme + host[:port], no path).
	BaseURL *url.URL
	// ListenAddr is the address the HTTP server binds to.
	ListenAddr string
	// SPConfigFile is the path to the service provider YAML file. Load only
	// checks that it is readable; the service provider loader parses it.
	SPConfigFile string
	// AllowedEmailDomains is a lower-cased allowlist; empty means any domain.
	AllowedEmailDomains []string

	OIDC    OIDCConfig
	SAML    SAMLConfig
	Session SessionConfig

	// PendingRequestTTL bounds how long an in-flight login may take.
	PendingRequestTTL time.Duration
	// LogLevel is the minimum slog level.
	LogLevel slog.Level

	// Warnings are non-fatal issues the caller should log at startup.
	Warnings []string
}

// OIDCConfig configures the upstream OpenID Connect relying party.
type OIDCConfig struct {
	Issuer               string
	ClientID             string
	ClientSecret         Secret
	Scopes               []string
	EmailClaim           string
	NameClaim            string
	GroupsClaim          string
	FetchUserinfo        bool
	Prompt               string
	RequireEmailVerified bool
}

// SAMLConfig holds the IdP signing material.
type SAMLConfig struct {
	CertFile    string
	KeyFile     string
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

// SessionConfig configures the bridge SSO session.
type SessionConfig struct {
	// Secret is the decoded HMAC key used to sign cookies.
	Secret Secret
	// TTL is the bridge session lifetime, short by design (no Single Logout).
	TTL time.Duration
}

// URL returns the absolute public URL for path (which must start with "/").
func (c *Config) URL(path string) string {
	u := *c.BaseURL
	u.Path = path
	return u.String()
}

// CallbackURL is the OIDC redirect URI to register at the identity provider.
func (c *Config) CallbackURL() string { return c.URL(CallbackPath) }

// FromEnv loads configuration from the process environment.
func FromEnv() (*Config, error) { return Load(os.LookupEnv) }

// Load builds and validates a Config using lookup to resolve variables. On
// failure it returns an *Error listing every problem found.
func Load(lookup LookupFunc) (*Config, error) {
	l := &loader{lookup: lookup}
	cfg := &Config{}

	cfg.BaseURL = l.baseURL(EnvBaseURL)
	cfg.ListenAddr = l.str(EnvListenAddr, DefaultListenAddr)
	cfg.SPConfigFile = l.readableFile(EnvSPConfigFile)
	cfg.AllowedEmailDomains = l.domains(EnvAllowedEmailDomains)

	cfg.OIDC = OIDCConfig{
		Issuer:               l.issuer(EnvOIDCIssuer),
		ClientID:             l.required(EnvOIDCClientID),
		ClientSecret:         l.requiredSecret(EnvOIDCClientSecret),
		Scopes:               l.scopes(EnvOIDCScopes),
		EmailClaim:           l.claimName(EnvOIDCEmailClaim, defaultEmailClaim),
		NameClaim:            l.claimName(EnvOIDCNameClaim, defaultNameClaim),
		GroupsClaim:          l.claimName(EnvOIDCGroupsClaim, defaultGroupsClaim),
		FetchUserinfo:        l.boolean(EnvOIDCFetchUserinfo, true),
		Prompt:               l.prompt(EnvOIDCPrompt),
		RequireEmailVerified: l.boolean(EnvOIDCRequireVerified, true),
	}

	cfg.SAML = l.samlKeyPair(EnvSAMLCertFile, EnvSAMLKeyFile)

	cfg.Session = SessionConfig{
		Secret: l.sessionSecret(EnvSessionSecret),
		TTL:    l.positiveDuration(EnvSessionTTL, DefaultSessionTTL),
	}
	cfg.PendingRequestTTL = l.positiveDuration(EnvPendingRequestTTL, DefaultPendingTTL)
	cfg.LogLevel = l.logLevel(EnvLogLevel)

	l.checkRemovedVars()

	if len(l.problems) > 0 {
		return nil, &Error{Problems: l.problems}
	}
	cfg.Warnings = l.warnings
	return cfg, nil
}

// Error reports every configuration problem found during Load.
type Error struct {
	Problems []string
}

func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "invalid configuration (%d problem", len(e.Problems))
	if len(e.Problems) != 1 {
		b.WriteString("s")
	}
	b.WriteString("):")
	for _, p := range e.Problems {
		b.WriteString("\n  - ")
		b.WriteString(p)
	}
	return b.String()
}
