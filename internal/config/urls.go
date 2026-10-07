package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// IsLoopbackHost reports whether host (without port) is a loopback name or
// address. Plain http is accepted only for these hosts.
func IsLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ParsePublicURL validates that raw is an absolute https URL (or http on a
// loopback host) without credentials or fragment. Error messages are phrased
// to follow a "<name> " prefix supplied by the caller.
func ParsePublicURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("is not a valid URL: %q", raw)
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("must be an absolute URL including a host, got %q", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !IsLoopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("must use https (http is only allowed for localhost), got %q", raw)
		}
	default:
		return nil, fmt.Errorf("must use https, got %q", raw)
	}
	if u.User != nil {
		return nil, errors.New("must not contain credentials")
	}
	if strings.Contains(raw, "#") {
		return nil, fmt.Errorf("must not contain a fragment, got %q", raw)
	}
	return u, nil
}

// checkPublicURL wraps ParsePublicURL, recording a problem against key.
func (l *loader) checkPublicURL(key, raw string) (*url.URL, bool) {
	u, err := ParsePublicURL(raw)
	if err != nil {
		l.problemf("%s %v", key, err)
		return nil, false
	}
	return u, true
}

// baseURL parses the bridge's public URL. It must be an origin (no path,
// query or fragment); a single trailing slash is tolerated and removed.
func (l *loader) baseURL(key string) *url.URL {
	raw, ok := l.get(key)
	if !ok {
		l.problemf("%s is required (e.g. https://saml.example.com)", key)
		return nil
	}
	u, ok := l.checkPublicURL(key, raw)
	if !ok {
		return nil
	}
	if u.Path != "" && u.Path != "/" {
		l.problemf("%s must not include a path (serving under a sub-path is not supported), got %q", key, raw)
		return nil
	}
	if u.RawQuery != "" || u.ForceQuery {
		l.problemf("%s must not include a query string, got %q", key, raw)
		return nil
	}
	if u.Scheme == "http" {
		l.warnf("%s uses plain http; this is only suitable for local development", key)
	}
	return &url.URL{Scheme: u.Scheme, Host: strings.ToLower(u.Host)}
}

// issuer validates the OIDC issuer. The value is returned verbatim because
// OIDC requires an exact string match against the "iss" claim, so a trailing
// slash is significant.
func (l *loader) issuer(key string) string {
	raw, ok := l.get(key)
	if !ok {
		l.problemf("%s is required", key)
		return ""
	}
	u, ok := l.checkPublicURL(key, raw)
	if !ok {
		return raw
	}
	if u.RawQuery != "" || u.ForceQuery {
		l.problemf("%s must not include a query string, got %q", key, raw)
	}
	return raw
}
