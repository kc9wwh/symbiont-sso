// Package oidcrp is symbiont's OpenID Connect relying party: discovery,
// authorization URLs (state, nonce, PKCE S256), code exchange, ID token
// verification, and userinfo merging.
package oidcrp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// DefaultHTTPTimeout bounds every upstream call (discovery, token, JWKS,
// userinfo).
const DefaultHTTPTimeout = 10 * time.Second

// Options configures a Client.
type Options struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	// Prompt is sent as the OIDC prompt parameter when non-empty.
	Prompt string
	// FetchUserinfo merges userinfo claims into the ID token claims.
	FetchUserinfo bool
	// HTTPClient is used for all upstream calls. Defaults to a client with
	// DefaultHTTPTimeout.
	HTTPClient *http.Client
	// Now overrides the clock for ID token expiry checks (tests).
	Now func() time.Time
}

// Client is an OIDC relying party bound to one issuer.
type Client struct {
	opts       Options
	provider   *oidc.Provider
	verifier   *oidc.IDTokenVerifier
	oauth      *oauth2.Config
	httpClient *http.Client
	discovery  Discovery
}

// Discovery holds the optional discovery fields symbiont inspects.
type Discovery struct {
	PromptValuesSupported         []string `json:"prompt_values_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	ScopesSupported               []string `json:"scopes_supported"`
}

// New performs OIDC discovery against o.Issuer and returns a Client. It
// fails if discovery is unreachable or the advertised issuer does not
// exactly match o.Issuer.
func New(ctx context.Context, o Options) (*Client, error) {
	if o.Issuer == "" || o.ClientID == "" || o.RedirectURL == "" {
		return nil, errors.New("oidcrp: Issuer, ClientID and RedirectURL are required")
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, o.HTTPClient), o.Issuer)
	if err != nil {
		var mismatch *oidc.IssuerMismatchError
		if errors.As(err, &mismatch) {
			return nil, fmt.Errorf("OIDC discovery: OIDC_ISSUER is %q but the provider reports issuer %q; "+
				"they must match exactly, including any trailing slash", mismatch.Provided, mismatch.Discovered)
		}
		return nil, fmt.Errorf("OIDC discovery for %q failed: %w", o.Issuer, err)
	}
	c := &Client{opts: o, provider: provider, httpClient: o.HTTPClient}
	if err := provider.Claims(&c.discovery); err != nil {
		return nil, fmt.Errorf("OIDC discovery: cannot parse document: %w", err)
	}
	if o.FetchUserinfo && provider.UserInfoEndpoint() == "" {
		return nil, errors.New("OIDC_FETCH_USERINFO is true but the provider advertises no userinfo_endpoint; " +
			"set OIDC_FETCH_USERINFO=false")
	}
	c.verifier = provider.Verifier(&oidc.Config{ClientID: o.ClientID, Now: o.Now})
	c.oauth = &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		RedirectURL:  o.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       o.Scopes,
	}
	return c, nil
}

// Discovery returns the parsed optional discovery fields.
func (c *Client) Discovery() Discovery { return c.discovery }

// Warnings returns non-fatal mismatches between configuration and the
// discovery document. Each check is skipped when the provider does not
// publish the corresponding field.
func (c *Client) Warnings() []string {
	var w []string
	d := c.discovery
	if c.opts.Prompt != "" && len(d.PromptValuesSupported) > 0 {
		for _, p := range strings.Fields(c.opts.Prompt) {
			if !slices.Contains(d.PromptValuesSupported, p) {
				w = append(w, fmt.Sprintf("OIDC_PROMPT value %q is not listed in the provider's prompt_values_supported %v; "+
					"the provider may ignore or reject it", p, d.PromptValuesSupported))
			}
		}
	}
	if len(d.CodeChallengeMethodsSupported) > 0 && !slices.Contains(d.CodeChallengeMethodsSupported, "S256") {
		w = append(w, fmt.Sprintf("the provider does not list S256 in code_challenge_methods_supported %v; "+
			"PKCE may be rejected", d.CodeChallengeMethodsSupported))
	}
	if len(d.ScopesSupported) > 0 {
		for _, s := range c.opts.Scopes {
			if !slices.Contains(d.ScopesSupported, s) {
				w = append(w, fmt.Sprintf("OIDC_SCOPES requests %q, which is not listed in the provider's scopes_supported %v",
					s, d.ScopesSupported))
			}
		}
	}
	return w
}

// AuthCodeURL returns the authorization URL for a new login. The caller
// must persist verifier and nonce, keyed by state. forceLogin adds
// prompt=login so the user re-authenticates even with a live provider
// session (an SP's ForceAuthn), and max_age=0, which also obliges the
// provider to return auth_time so the caller can verify it happened.
func (c *Client) AuthCodeURL(state, nonce, verifier string, forceLogin bool) string {
	opts := []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)}
	prompt := strings.Fields(c.opts.Prompt)
	if forceLogin && !slices.Contains(prompt, "login") {
		prompt = append([]string{"login"}, prompt...)
	}
	if len(prompt) > 0 {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", strings.Join(prompt, " ")))
	}
	if forceLogin {
		opts = append(opts, oauth2.SetAuthURLParam("max_age", "0"))
	}
	return c.oauth.AuthCodeURL(state, opts...)
}

// NewVerifier returns a fresh PKCE code verifier.
func NewVerifier() string { return oauth2.GenerateVerifier() }
