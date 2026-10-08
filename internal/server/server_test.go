package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newTestServer(t *testing.T, level slog.Level) (*Server, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: level}))
	return New(Options{Logger: logger}), logs
}

func TestHealthz(t *testing.T) {
	s, _ := newTestServer(t, slog.LevelInfo)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["status"] != "ok" {
		t.Errorf("body = %q (err %v)", rec.Body.String(), err)
	}
}

func TestHealthzMethodAndUnknownRoutes(t *testing.T) {
	s, _ := newTestServer(t, slog.LevelInfo)
	tests := []struct {
		method, path string
		want         int
	}{
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
		{http.MethodHead, "/healthz", http.StatusOK}, // GET patterns also match HEAD
		{http.MethodGet, "/nope", http.StatusNotFound},
		{http.MethodGet, "/", http.StatusNotFound},
	}
	for _, tc := range tests {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.want {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	s, _ := newTestServer(t, slog.LevelInfo)
	want := map[string]string{
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"X-Content-Type-Options": "nosniff",
		"Cache-Control":          "no-store",
	}
	for _, path := range []string{"/healthz", "/does-not-exist"} {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		for k, v := range want {
			if got := rec.Header().Get(k); got != v {
				t.Errorf("%s: %s = %q, want %q", path, k, got, v)
			}
		}
		csp := rec.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("%s: CSP = %q", path, csp)
		}
		if len(rec.Header().Get(RequestIDHeader)) != 16 {
			t.Errorf("%s: missing/short request ID %q", path, rec.Header().Get(RequestIDHeader))
		}
	}
}

func TestAccessLogOmitsQueryString(t *testing.T) {
	s, logs := newTestServer(t, slog.LevelDebug)
	req := httptest.NewRequest(http.MethodGet, "/nope?SAMLRequest=SECRETPAYLOAD&code=AUTHCODE", nil)
	s.Handler().ServeHTTP(httptest.NewRecorder(), req)

	out := logs.String()
	if strings.Contains(out, "SECRETPAYLOAD") || strings.Contains(out, "AUTHCODE") {
		t.Fatalf("access log leaked query string: %s", out)
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &entry); err != nil {
		t.Fatalf("log is not a single JSON line: %v\n%s", err, out)
	}
	if entry["path"] != "/nope" || entry["status"] != float64(404) || entry["msg"] != "http request" {
		t.Errorf("unexpected log entry: %v", entry)
	}
}

func TestHealthzLoggedAtDebugOnly(t *testing.T) {
	s, logs := newTestServer(t, slog.LevelInfo)
	s.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if logs.String() != "" {
		t.Errorf("healthz should not be logged at info level: %s", logs.String())
	}
}

func TestPanicRecovery(t *testing.T) {
	logs := &syncBuffer{}
	s := &Server{log: slog.New(slog.NewJSONHandler(logs, nil))}
	h := s.middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	out := logs.String()
	if !strings.Contains(out, "panic in http handler") || !strings.Contains(out, `"status":500`) {
		t.Errorf("panic not logged as expected: %s", out)
	}
}
