package clientip

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// FuzzParsePrefixes: the trusted-proxy list comes from an environment
// variable. Parsing never panics, and every prefix it returns is already in
// canonical form (masked, IPv4-mapped IPv6 unmapped, no zone), so that
// containment checks later behave predictably.
func FuzzParsePrefixes(f *testing.F) {
	for _, s := range []string{"", ",", " 172.16.0.0/12 , 10.1.2.3, ::1, 2001:db8::/32, ::ffff:192.168.0.0/112,",
		"fe80::1%eth0", "10.0.0.0/33", "::/0", "0.0.0.0/0", "::ffff:10.0.0.1", "1.2.3.4/", "/8", "a,b,c", "10.0.0.1/24/8"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ps, err := ParsePrefixes(s)
		if err != nil {
			if ps != nil {
				t.Fatalf("returned prefixes %v alongside error %v", ps, err)
			}
			return
		}
		for _, p := range ps {
			if !p.IsValid() {
				t.Fatalf("invalid prefix from %q", s)
			}
			if p != p.Masked() {
				t.Fatalf("%v from %q is not masked", p, s)
			}
			if p.Addr().Zone() != "" {
				t.Fatalf("%v from %q carries a zone", p, s)
			}
			if p.Addr().Is4In6() {
				t.Fatalf("%v from %q is an unmapped IPv4-in-IPv6 prefix", p, s)
			}
			// Round-trips through its own string form.
			if q, err := netip.ParsePrefix(p.String()); err != nil || q != p {
				t.Fatalf("%v does not round-trip: %v, %v", p, q, err)
			}
		}
	})
}

// FuzzClientIP: forwarding headers are attacker-controlled. Whatever they
// contain, ClientIP never panics and returns a valid address (or nothing),
// and it only believes a header when the TCP peer is a trusted proxy.
func FuzzClientIP(f *testing.F) {
	f.Add("10.0.0.1:1234", "203.0.113.9", "203.0.113.7, 10.0.0.2", true)
	f.Add("198.51.100.4:80", "203.0.113.9", "203.0.113.7", true)
	f.Add("10.0.0.1:1", "not-an-ip", "also, not, ips", false)
	f.Add("[fe80::1%eth0]:443", "fe80::1%eth0", "fe80::1%eth0", true)
	f.Add("garbage", "", "", false)
	f.Add("10.0.0.1", "::ffff:203.0.113.9", "::ffff:10.0.0.2, ::ffff:203.0.113.7", true)
	f.Add("10.0.0.1:1", "1.1.1.1", strings.Repeat("10.0.0.3, ", 200)+"203.0.113.7", true)
	trusted, err := ParsePrefixes("10.0.0.0/8, fd00::/8")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, remote, cf, xff string, withCF bool) {
		var opts []Option
		if withCF {
			opts = append(opts, WithCloudflareHeader())
		}
		r := New(trusted, opts...)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remote
		// Header values with control characters cannot arrive over HTTP/1,
		// but the resolver must not depend on that.
		req.Header[http.CanonicalHeaderKey(HeaderCFConnectingIP)] = []string{cf}
		req.Header[http.CanonicalHeaderKey(HeaderXForwardedFor)] = []string{xff}

		ip, fromHeader := r.ClientIP(req)
		if ip == "" {
			if fromHeader {
				t.Fatal("reported a header-derived IP but returned none")
			}
			return
		}
		a, err := netip.ParseAddr(ip)
		if err != nil {
			t.Fatalf("ClientIP returned %q, not an address: %v", ip, err)
		}
		if a.Zone() != "" || a.Is4In6() {
			t.Fatalf("ClientIP returned non-canonical %q", ip)
		}

		// Untrusted peer: headers must have no influence at all.
		if peer, ok := parseRemoteAddr(remote); ok && !r.isTrusted(peer) {
			if fromHeader || ip != peer.String() {
				t.Fatalf("untrusted peer %v: got %q (fromHeader=%v), want the peer address", peer, ip, fromHeader)
			}
		}
	})
}
