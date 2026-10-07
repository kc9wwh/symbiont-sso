// Package web holds HTML rendering and Content-Security-Policy helpers
// shared by symbiont's handlers.
package web

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// DefaultCSP is applied to every response unless a handler overrides it.
// It forbids all scripts, styles, framing, and form submission.
const DefaultCSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// CSPHeader is the Content-Security-Policy header name.
const CSPHeader = "Content-Security-Policy"

// ScriptHash returns the CSP source expression ('sha256-...') for an inline
// script body. The body must be byte-identical to what is rendered between
// <script> and </script>.
func ScriptHash(script string) string {
	sum := sha256.Sum256([]byte(script))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

// Origin returns the scheme://host[:port] origin of an absolute URL.
func Origin(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("not an absolute URL: %q", rawURL)
	}
	return u.Scheme + "://" + u.Host, nil
}

// PostFormCSP builds the policy for an auto-submitting POST form page: only
// the exact inline script (by hash) may run, the form may only target
// formAction (an origin, or 'self'), and nothing else is permitted.
func PostFormCSP(scriptHash, formAction string) string {
	return strings.Join([]string{
		"default-src 'none'",
		"script-src " + scriptHash,
		"style-src " + styleHash,
		"form-action " + formAction,
		"frame-ancestors 'none'",
		"base-uri 'none'",
	}, "; ")
}

// SetCSP overrides the default policy for this response. Call it before
// writing the header.
func SetCSP(w http.ResponseWriter, policy string) { w.Header().Set(CSPHeader, policy) }
