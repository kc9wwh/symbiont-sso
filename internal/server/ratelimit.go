package server

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// ipv6BucketBits is the IPv6 prefix length that counts as one client.
const ipv6BucketBits = 64

// maxLimiterKeys bounds the per-client table. Past it, idle entries are
// purged and, if the table is still full, new clients are let through: the
// pending-login cap, not this limiter, is the backstop against a flood from
// that many distinct addresses.
const maxLimiterKeys = 10000

// RateLimiter is a per-client token bucket guarding the endpoints that start
// a login (/sso and /login/*). Each start allocates a pending-login entry,
// and anonymous callers can make as many as they like.
type RateLimiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	now     func() time.Time
	clients map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter allows perMinute sustained requests per client with a burst
// of the same size. It returns nil (no limiting) when perMinute <= 0.
func NewRateLimiter(perMinute int, now func() time.Time) *RateLimiter {
	if perMinute <= 0 {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	return &RateLimiter{
		rate:    float64(perMinute) / 60,
		burst:   float64(perMinute),
		now:     now,
		clients: map[string]*bucket{},
	}
}

// Allow takes a token for key. When none is left it reports how long until
// one is.
func (l *RateLimiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	if l == nil {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, found := l.clients[key]
	if !found {
		if len(l.clients) >= maxLimiterKeys {
			l.purgeIdleLocked(now)
			if len(l.clients) >= maxLimiterKeys {
				return true, 0
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.clients[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
}

// purgeIdleLocked drops clients whose bucket has refilled completely; they
// are indistinguishable from new ones.
func (l *RateLimiter) purgeIdleLocked(now time.Time) {
	for k, b := range l.clients {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.clients, k)
		}
	}
}

// limited wraps h so that requests over the client's budget get a 429 page.
func (s *Server) limited(h http.HandlerFunc) http.HandlerFunc {
	if s.opts.RateLimit == nil {
		return h
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ok, wait := s.opts.RateLimit.Allow(s.limiterKey(r))
		if ok {
			h(w, r)
			return
		}
		secs := int(wait.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		s.reqLog(r).WarnContext(r.Context(), "rate limited", "error_category", "rate_limited", "retry_after_seconds", secs)
		s.errorPage(w, r, http.StatusTooManyRequests, "Too many sign-in attempts",
			"Please wait a moment and try again.")
	}
}

// limiterKey identifies the caller: the forwarded client address when a
// trusted proxy supplied one, otherwise the socket peer.
func (s *Server) limiterKey(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPKey{}).(string); ok {
		return clientBucket(ip)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return clientBucket(host)
	}
	return r.RemoteAddr
}

// clientBucket groups IPv6 clients by /64: one host routinely controls a
// whole /64, and a key per address would let it mint unlimited buckets and
// exhaust the client table.
func clientBucket(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is4() {
		return a.String()
	}
	return netip.PrefixFrom(a.WithZone(""), ipv6BucketBits).Masked().String()
}
