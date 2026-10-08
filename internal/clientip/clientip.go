// Package clientip resolves the real client IP behind trusted reverse
// proxies (e.g. Cloudflare Tunnel's cloudflared). Forwarding headers are
// only ever believed when the TCP peer itself is a trusted proxy; otherwise
// they are attacker-controlled and ignored.
package clientip

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Header names consulted when the peer is trusted.
const (
	HeaderCFConnectingIP = "CF-Connecting-IP"
	HeaderXForwardedFor  = "X-Forwarded-For"
)

// maxXFFHops bounds how many X-Forwarded-For entries are examined.
const maxXFFHops = 32

// Resolver maps a request to the client IP for logging.
type Resolver struct {
	trusted []netip.Prefix
}

// ParsePrefixes parses a comma-separated list of CIDRs or bare IPs (a bare
// IP is a /32 or /128). Empty input yields no prefixes.
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if strings.Contains(f, "%") {
			return nil, fmt.Errorf("%q: IPv6 zones are not supported", f)
		}
		var p netip.Prefix
		var err error
		if strings.Contains(f, "/") {
			p, err = netip.ParsePrefix(f)
		} else {
			var a netip.Addr
			a, err = netip.ParseAddr(f)
			if err == nil {
				p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
			}
		}
		if err != nil {
			return nil, fmt.Errorf("%q is not a CIDR or IP address", f)
		}
		out = append(out, unmapPrefix(p.Masked()))
	}
	return out, nil
}

func unmapPrefix(p netip.Prefix) netip.Prefix {
	if !p.Addr().Is4In6() {
		return p
	}
	bits := p.Bits() - 96
	if bits < 0 {
		bits = 0
	}
	return netip.PrefixFrom(p.Addr().Unmap(), bits).Masked()
}

// New returns a Resolver trusting the given prefixes. With none, forwarding
// headers are never used.
func New(trusted []netip.Prefix) *Resolver { return &Resolver{trusted: trusted} }

// Enabled reports whether any proxy is trusted.
func (r *Resolver) Enabled() bool { return r != nil && len(r.trusted) > 0 }

func (r *Resolver) isTrusted(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range r.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ClientIP returns the client IP for req, and whether it was derived from a
// forwarding header. When the peer is not a trusted proxy (or no proxies
// are configured) it returns the peer address and false.
func (r *Resolver) ClientIP(req *http.Request) (string, bool) {
	peer, ok := parseRemoteAddr(req.RemoteAddr)
	if !ok {
		return "", false
	}
	if !r.Enabled() || !r.isTrusted(peer) {
		return peer.String(), false
	}
	// Cloudflare sets CF-Connecting-IP to the visitor address and strips any
	// client-supplied value, so it is authoritative once the peer is trusted.
	if v := strings.TrimSpace(req.Header.Get(HeaderCFConnectingIP)); v != "" {
		if a, err := netip.ParseAddr(v); err == nil && a.Zone() == "" {
			return a.Unmap().String(), true
		}
	}
	// X-Forwarded-For: each proxy appends the address it received from, so
	// the right-most entry that is not itself a trusted proxy is the first
	// address no trusted party vouches past. Everything left of it is
	// client-controlled and ignored.
	hops := xffHops(req.Header.Values(HeaderXForwardedFor))
	var leftmostTrusted netip.Addr
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(hops[i])
		if err != nil || a.Zone() != "" {
			break // malformed: stop rather than trust anything further left
		}
		a = a.Unmap()
		if !r.isTrusted(a) {
			return a.String(), true
		}
		leftmostTrusted = a
	}
	if leftmostTrusted.IsValid() {
		return leftmostTrusted.String(), true // chain of trusted proxies only
	}
	return peer.String(), false
}

// xffHops flattens (possibly repeated) X-Forwarded-For headers, keeping at
// most the right-most maxXFFHops entries.
func xffHops(values []string) []string {
	var hops []string
	for _, v := range values {
		for _, h := range strings.Split(v, ",") {
			if h = strings.TrimSpace(h); h != "" {
				hops = append(hops, h)
			}
		}
	}
	if len(hops) > maxXFFHops {
		hops = hops[len(hops)-maxXFFHops:]
	}
	return hops
}

func parseRemoteAddr(remote string) (netip.Addr, bool) {
	host := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.WithZone("").Unmap(), true
}
