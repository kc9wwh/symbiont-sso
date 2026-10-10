package clientip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func mustResolver(t *testing.T, cidrs string) *Resolver {
	t.Helper()
	p, err := ParsePrefixes(cidrs)
	if err != nil {
		t.Fatal(err)
	}
	return New(p, WithCloudflareHeader())
}

func req(remote string, headers map[string][]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	for k, vs := range headers {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	return r
}

func TestClientIP(t *testing.T) {
	const tunnel = "172.18.0.5:51234" // cloudflared on a docker network
	tests := []struct {
		name    string
		trusted string
		remote  string
		headers map[string][]string
		want    string
		fromHdr bool
	}{
		{"no proxies configured: headers ignored", "", tunnel,
			map[string][]string{"CF-Connecting-IP": {"203.0.113.9"}, "X-Forwarded-For": {"203.0.113.9"}}, "172.18.0.5", false},
		{"untrusted peer: CF header ignored", "10.0.0.0/8", tunnel,
			map[string][]string{"CF-Connecting-IP": {"203.0.113.9"}}, "172.18.0.5", false},
		{"untrusted peer: XFF ignored", "10.0.0.0/8", "198.51.100.7:4000",
			map[string][]string{"X-Forwarded-For": {"1.2.3.4"}}, "198.51.100.7", false},
		{"trusted peer: CF-Connecting-IP", "172.16.0.0/12", tunnel,
			map[string][]string{"CF-Connecting-IP": {" 203.0.113.9 "}, "X-Forwarded-For": {"9.9.9.9"}}, "203.0.113.9", true},
		{"trusted peer: CF-Connecting-IP IPv6", "172.16.0.0/12", tunnel,
			map[string][]string{"CF-Connecting-IP": {"2001:db8::1"}}, "2001:db8::1", true},
		{"trusted peer: invalid CF header falls back to XFF", "172.16.0.0/12", tunnel,
			map[string][]string{"CF-Connecting-IP": {"not-an-ip"}, "X-Forwarded-For": {"203.0.113.9"}}, "203.0.113.9", true},
		{"right-most untrusted XFF hop; spoofed left entry ignored", "172.16.0.0/12,10.0.0.0/8", tunnel,
			map[string][]string{"X-Forwarded-For": {"6.6.6.6, 203.0.113.9, 10.1.2.3"}}, "203.0.113.9", true},
		{"repeated XFF headers are concatenated", "172.16.0.0/12", tunnel,
			map[string][]string{"X-Forwarded-For": {"6.6.6.6", "203.0.113.9"}}, "203.0.113.9", true},
		{"all hops trusted: left-most", "172.16.0.0/12,10.0.0.0/8", tunnel,
			map[string][]string{"X-Forwarded-For": {"10.0.0.1, 10.0.0.2"}}, "10.0.0.1", true},
		{"malformed hop stops the walk", "172.16.0.0/12,10.0.0.0/8", tunnel,
			map[string][]string{"X-Forwarded-For": {"203.0.113.9, garbage, 10.0.0.2"}}, "10.0.0.2", true},
		{"trusted peer, no headers: peer", "172.16.0.0/12", tunnel, nil, "172.18.0.5", false},
		{"bare IP trusted", "172.18.0.5", tunnel,
			map[string][]string{"CF-Connecting-IP": {"203.0.113.9"}}, "203.0.113.9", true},
		{"IPv4-mapped peer matches IPv4 prefix", "127.0.0.0/8", "[::ffff:127.0.0.1]:8080",
			map[string][]string{"CF-Connecting-IP": {"203.0.113.9"}}, "203.0.113.9", true},
		{"IPv6 loopback trusted", "::1", "[::1]:8080",
			map[string][]string{"X-Forwarded-For": {"2001:db8::7"}}, "2001:db8::7", true},
		{"unparsable remote", "0.0.0.0/0", "pipe", nil, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, fromHdr := mustResolver(t, tc.trusted).ClientIP(req(tc.remote, tc.headers))
			if got != tc.want || fromHdr != tc.fromHdr {
				t.Errorf("ClientIP = %q,%v; want %q,%v", got, fromHdr, tc.want, tc.fromHdr)
			}
		})
	}
}

// Without the Cloudflare opt-in a client-set CF-Connecting-IP must not pick
// the logged address, even from a trusted peer.
func TestCFHeaderIgnoredByDefault(t *testing.T) {
	p, _ := ParsePrefixes("172.16.0.0/12")
	r := req("172.18.0.5:51234", map[string][]string{
		"CF-Connecting-IP": {"6.6.6.6"}, "X-Forwarded-For": {"203.0.113.9"},
	})
	if got, ok := New(p).ClientIP(r); got != "203.0.113.9" || !ok {
		t.Errorf("ClientIP = %q,%v; want XFF value 203.0.113.9,true", got, ok)
	}
}

func TestXFFHopLimit(t *testing.T) {
	r := mustResolver(t, "10.0.0.0/8")
	xff := "203.0.113.9"
	for i := 0; i < maxXFFHops; i++ {
		xff += ", 10.0.0.1"
	}
	// The real client is beyond the inspected window: fall back to the
	// left-most inspected (trusted) hop rather than scanning unboundedly.
	got, _ := r.ClientIP(req("10.0.0.2:1", map[string][]string{"X-Forwarded-For": {xff}}))
	if got != "10.0.0.1" {
		t.Errorf("got %q", got)
	}
}

func TestParsePrefixes(t *testing.T) {
	p, err := ParsePrefixes(" 172.16.0.0/12 , 10.1.2.3, ::1, 2001:db8::/32, ::ffff:192.168.0.0/112,")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"172.16.0.0/12", "10.1.2.3/32", "::1/128", "2001:db8::/32", "192.168.0.0/16"}
	if len(p) != len(want) {
		t.Fatalf("got %v", p)
	}
	for i := range want {
		if p[i].String() != want[i] {
			t.Errorf("prefix %d = %s, want %s", i, p[i], want[i])
		}
	}
	if p, err := ParsePrefixes(""); err != nil || len(p) != 0 || New(p).Enabled() {
		t.Errorf("empty: %v %v", p, err)
	}
	for _, bad := range []string{"10.0.0.0/33", "nope", "10.0.0.0/8, x", "fe80::1%eth0"} {
		if _, err := ParsePrefixes(bad); err == nil {
			t.Errorf("ParsePrefixes(%q) accepted", bad)
		}
	}
	// Host bits are masked.
	if p, _ := ParsePrefixes("10.1.2.3/8"); p[0].String() != "10.0.0.0/8" {
		t.Errorf("not masked: %v", p)
	}
}
