package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// placeholderDomains are the RFC 2606 reserved example domains. A host
// equal to one of these, or a subdomain of one, is a placeholder.
var placeholderDomains = []string{"example.com", "example.net", "example.org", "example"}

// isPlaceholderHost reports whether host is under a reserved example domain.
func isPlaceholderHost(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if h == "" {
		return false
	}
	for _, d := range placeholderDomains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// entityIDHost extracts the host from an entity ID, which may be a URL
// ("https://fleet.example.com/saml"), a bare host with optional port and
// path ("fleet.example.com/mdm", as Fleet uses), or a URN (no host).
func entityIDHost(id string) string {
	if strings.Contains(id, "://") {
		u, err := url.Parse(id)
		if err != nil {
			return ""
		}
		return u.Hostname()
	}
	if strings.HasPrefix(strings.ToLower(id), "urn:") {
		return ""
	}
	h, _, _ := strings.Cut(id, "/")
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

// usesPlaceholderDomain reports whether sp's entity ID or any ACS URL host
// is under a reserved example domain.
func usesPlaceholderDomain(sp *ServiceProvider) bool {
	if isPlaceholderHost(entityIDHost(sp.EntityID)) {
		return true
	}
	for _, raw := range sp.ACSURLs {
		if u, err := url.Parse(raw); err == nil && isPlaceholderHost(u.Hostname()) {
			return true
		}
	}
	return false
}

func placeholderWarning(spID string) string {
	return fmt.Sprintf("service provider %s uses a placeholder domain; did you point %s at the example file?",
		spID, EnvSPConfigFile)
}
