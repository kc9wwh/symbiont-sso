package server

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func TestRateLimiterAllow(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l := NewRateLimiter(6, clk.now) // burst 6, one token per 10s

	for i := 0; i < 6; i++ {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("request %d within burst was limited", i+1)
		}
	}
	ok, wait := l.Allow("a")
	if ok || wait <= 0 || wait > 10*time.Second {
		t.Fatalf("over-budget: ok=%v wait=%v, want limited with wait in (0,10s]", ok, wait)
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Error("a second client shares the first client's budget")
	}
	clk.t = clk.t.Add(10 * time.Second)
	if ok, _ := l.Allow("a"); !ok {
		t.Error("token was not refilled after 10s")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Error("only one token should have refilled")
	}
}

func TestRateLimiterDisabled(t *testing.T) {
	for _, n := range []int{0, -1} {
		if l := NewRateLimiter(n, nil); l != nil {
			t.Errorf("NewRateLimiter(%d) = %v, want nil", n, l)
		}
	}
	var l *RateLimiter
	if ok, _ := l.Allow("x"); !ok {
		t.Error("nil limiter must allow everything")
	}
}

func TestRateLimiterBoundedTable(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l := NewRateLimiter(60, clk.now)
	for i := 0; i < maxLimiterKeys; i++ {
		l.clients[string(rune(i))+"k"] = &bucket{tokens: 0, last: clk.t} // all drained
	}
	if ok, _ := l.Allow("new"); !ok {
		t.Error("new client must be let through when the table is full of active clients")
	}
	if len(l.clients) > maxLimiterKeys {
		t.Errorf("table grew to %d, cap is %d", len(l.clients), maxLimiterKeys)
	}
	clk.t = clk.t.Add(2 * time.Minute) // everyone has refilled
	if ok, _ := l.Allow("newer"); !ok {
		t.Fatal("request rejected after idle purge")
	}
	if len(l.clients) != 1 {
		t.Errorf("idle clients not purged: %d entries", len(l.clients))
	}
}

// A full table must not be rescanned for every new client: an attacker
// with many addresses would turn each request into a 10k-entry scan.
func TestRateLimiterPurgeIsThrottled(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l := NewRateLimiter(60, clk.now)
	for i := 0; i < maxLimiterKeys; i++ {
		l.clients[strconv.Itoa(i)] = &bucket{tokens: 0, last: clk.t} // all drained
	}
	l.Allow("first")                // scans, finds nothing idle
	l.clients["0"].tokens = l.burst // now idle
	l.Allow("second")               // within the interval: no scan
	if _, ok := l.clients["0"]; !ok {
		t.Fatal("table rescanned within the purge interval")
	}
	clk.t = clk.t.Add(purgeInterval)
	l.Allow("third")
	if _, ok := l.clients["0"]; ok {
		t.Error("idle client not purged after the interval")
	}
}

func TestAllowLoginReturns429(t *testing.T) {
	s := New(Options{RateLimit: NewRateLimiter(2, nil)})

	do := func(remote string) (bool, *httptest.ResponseRecorder) {
		r := httptest.NewRequest(http.MethodGet, "/sso", nil)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		return s.allowLogin(w, r), w
	}
	do("192.0.2.1:1000")
	do("192.0.2.1:2000") // same host, different port: one client
	ok, w := do("192.0.2.1:3000")
	if ok || w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Errorf("third request: allowed=%v status %d, Retry-After %q; want refused with 429 and Retry-After", ok, w.Code, w.Header().Get("Retry-After"))
	}
	if ok, _ := do("192.0.2.2:1000"); !ok {
		t.Error("a different client was limited")
	}
}

// One IPv6 host controls a whole /64, so it must not get a bucket per
// address.
func TestLimiterKeyGroupsIPv6By64(t *testing.T) {
	s := New(Options{})
	key := func(remote string) string {
		r := httptest.NewRequest(http.MethodGet, "/sso", nil)
		r.RemoteAddr = remote
		return s.limiterKey(r)
	}
	tests := []struct {
		a, b string
		same bool
	}{
		{"[2001:db8:1:2::1]:1000", "[2001:db8:1:2:ffff::9]:2000", true},
		{"[2001:db8:1:2::1]:1000", "[2001:db8:1:3::1]:1000", false},
		{"192.0.2.1:1000", "192.0.2.2:1000", false},
		{"[::ffff:192.0.2.1]:1000", "[::ffff:192.0.2.2]:1000", false},
	}
	for _, tc := range tests {
		if got := key(tc.a) == key(tc.b); got != tc.same {
			t.Errorf("same key for %s and %s = %v, want %v (%q, %q)", tc.a, tc.b, got, tc.same, key(tc.a), key(tc.b))
		}
	}
}

func TestAllowLoginWhenDisabled(t *testing.T) {
	s := New(Options{})
	if !s.allowLogin(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Error("login refused with limiting disabled")
	}
}
