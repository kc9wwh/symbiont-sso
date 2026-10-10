package server

import (
	"net/http"
	"net/http/httptest"
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

func TestLimitedReturns429(t *testing.T) {
	s := New(Options{RateLimit: NewRateLimiter(2, nil)})
	called := 0
	h := s.limited(func(http.ResponseWriter, *http.Request) { called++ })

	do := func(remote string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/sso", nil)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h(w, r)
		return w
	}
	do("192.0.2.1:1000")
	do("192.0.2.1:2000") // same host, different port: one client
	w := do("192.0.2.1:3000")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Errorf("third request: status %d, Retry-After %q; want 429 with Retry-After", w.Code, w.Header().Get("Retry-After"))
	}
	if called != 2 {
		t.Errorf("handler ran %d times, want 2", called)
	}
	if w := do("192.0.2.2:1000"); w.Code == http.StatusTooManyRequests {
		t.Error("a different client was limited")
	}
}

func TestLimitedPassThroughWhenDisabled(t *testing.T) {
	s := New(Options{})
	ran := false
	s.limited(func(http.ResponseWriter, *http.Request) { ran = true })(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !ran {
		t.Error("handler not called with limiting disabled")
	}
}
