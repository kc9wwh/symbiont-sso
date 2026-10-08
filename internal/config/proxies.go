package config

import (
	"net/netip"

	"github.com/kc9wwh/symbiont-sso/internal/clientip"
)

// trustedProxies parses SYMBIONT_TRUSTED_PROXIES (comma-separated CIDRs or
// IPs). Trusting very broad ranges lets any client spoof its logged IP, so
// those produce a warning.
func (l *loader) trustedProxies(key string) []netip.Prefix {
	raw, ok := l.get(key)
	if !ok {
		return nil
	}
	p, err := clientip.ParsePrefixes(raw)
	if err != nil {
		l.problemf("%s: %v", key, err)
		return nil
	}
	if len(p) == 0 {
		l.problemf("%s is set but contains no CIDRs", key)
		return nil
	}
	for _, pr := range p {
		if (pr.Addr().Is4() && pr.Bits() < 8) || (pr.Addr().Is6() && pr.Bits() < 16) {
			l.warnf("%s: %s trusts a very large range; any client inside it can spoof the logged client_ip", key, pr)
		}
	}
	return p
}
