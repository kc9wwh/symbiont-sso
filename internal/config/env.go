package config

import "time"

// Environment variable names.
const (
	EnvBaseURL             = "SYMBIONT_BASE_URL"
	EnvListenAddr          = "SYMBIONT_LISTEN_ADDR"
	EnvSPConfigFile        = "SYMBIONT_SP_CONFIG_FILE"
	EnvOIDCIssuer          = "OIDC_ISSUER"
	EnvOIDCClientID        = "OIDC_CLIENT_ID"
	EnvOIDCClientSecret    = "OIDC_CLIENT_SECRET"
	EnvOIDCScopes          = "OIDC_SCOPES"
	EnvOIDCEmailClaim      = "OIDC_EMAIL_CLAIM"
	EnvOIDCNameClaim       = "OIDC_NAME_CLAIM"
	EnvOIDCGroupsClaim     = "OIDC_GROUPS_CLAIM"
	EnvOIDCFetchUserinfo   = "OIDC_FETCH_USERINFO"
	EnvOIDCPrompt          = "OIDC_PROMPT"
	EnvOIDCRequireVerified = "OIDC_REQUIRE_EMAIL_VERIFIED"
	EnvAllowedEmailDomains = "ALLOWED_EMAIL_DOMAINS"
	EnvSAMLCertFile        = "SAML_CERT_FILE"
	EnvSAMLKeyFile         = "SAML_KEY_FILE"
	EnvSessionSecret       = "SESSION_SECRET"
	EnvSessionTTL          = "SESSION_TTL"
	EnvPendingRequestTTL   = "PENDING_REQUEST_TTL"
	EnvLogLevel            = "LOG_LEVEL"

	// FileSuffix marks the "<NAME>_FILE" variant of a secret variable.
	FileSuffix = "_FILE"
)

// Defaults and limits.
const (
	DefaultListenAddr = ":8080"
	DefaultScopes     = "openid email profile groups"
	DefaultSessionTTL = 60 * time.Second
	DefaultPendingTTL = 10 * time.Minute

	defaultEmailClaim  = "email"
	defaultNameClaim   = "name"
	defaultGroupsClaim = "groups"

	// MinSessionSecretBytes is the minimum decoded SESSION_SECRET length.
	MinSessionSecretBytes = 32
	// MinRSAKeyBits is the minimum SAML signing key size.
	MinRSAKeyBits = 2048

	maxSecretFileBytes      = 64 << 10
	certExpiryWarningWindow = 30 * 24 * time.Hour

	// CallbackPath is the OIDC redirect path, relative to the base URL.
	CallbackPath = "/oidc/callback"
)

// removedVars maps environment variables from earlier designs to a hint
// about their replacement. Setting one produces a startup warning instead of
// being silently ignored.
var removedVars = map[string]string{
	"BRIDGE_BASE_URL":            "renamed to " + EnvBaseURL,
	"BRIDGE_LISTEN_ADDR":         "renamed to " + EnvListenAddr,
	"SP_CONFIG_FILE":             "renamed to " + EnvSPConfigFile,
	"SAML_SP_ENTITY_ID":          "configure service providers in " + EnvSPConfigFile,
	"SAML_SP_ACS_URLS":           "configure service providers in " + EnvSPConfigFile,
	"SAML_IDP_INITIATED_ENABLED": "configure idp_initiated per service provider in " + EnvSPConfigFile,
	"SAML_IDP_INITIATED_ACS_URL": "configure idp_initiated per service provider in " + EnvSPConfigFile,
	"ATTRIBUTE_MAPPING_FILE":     "configure attributes per service provider in " + EnvSPConfigFile,
	"FLEET_ROLE_VALIDATION":      "configure fleet_role_validation per service provider in " + EnvSPConfigFile,
}
