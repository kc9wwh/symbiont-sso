package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/kc9wwh/symbiont-sso/internal/web"
)

// RequestIDHeader carries the per-request correlation ID in responses.
const RequestIDHeader = "X-Request-Id"

// middleware wraps h with (outermost first): security headers, access
// logging and panic recovery.
func (s *Server) middleware(h http.Handler) http.Handler {
	return s.securityHeaders(s.accessLog(s.recoverPanics(h)))
}

// securityHeaders sets conservative defaults on every response. The strict
// default CSP forbids all scripts and form submissions; handlers that render
// HTML replace it per response via web.SetCSP (e.g. the POST-binding page
// allows exactly its own script hash and its ACS origin as form-action).
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set(web.CSPHeader, web.DefaultCSP)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// accessLog logs one line per request. Only the path is logged, never the
// query string: SAMLRequest, RelayState, OIDC codes and state all travel in
// query parameters.
func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := newRequestID()
		w.Header().Set(RequestIDHeader, id)
		ctx := context.WithValue(r.Context(), requestIDKey{}, id)
		ip, fromHeader := "", false
		if s.opts.ClientIP.Enabled() {
			ip, fromHeader = s.opts.ClientIP.ClientIP(r)
			if fromHeader {
				ctx = context.WithValue(ctx, clientIPKey{}, ip)
			}
		}
		r = r.WithContext(ctx)
		rec := &statusRecorder{ResponseWriter: w}

		next.ServeHTTP(rec, r)

		level := slog.LevelInfo
		switch {
		case r.URL.Path == "/healthz" && rec.status() < 400:
			level = slog.LevelDebug // keep liveness probes out of info logs
		case rec.status() >= 500:
			level = slog.LevelError
		}
		attrs := []slog.Attr{
			slog.String("request_id", id),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.status()),
			slog.Int64("bytes", rec.bytes),
			slog.Duration("duration", time.Since(start)),
			slog.String("remote_addr", r.RemoteAddr), // always the socket peer
		}
		if fromHeader {
			attrs = append(attrs, slog.String("client_ip", ip))
		}
		s.log.LogAttrs(r.Context(), level, "http request", attrs...)
	})
}

// recoverPanics converts handler panics into a 500 response and an error
// log entry with a stack trace, instead of a dropped connection.
func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			if v == http.ErrAbortHandler {
				panic(v) // deliberate abort; let net/http handle it
			}
			s.log.ErrorContext(r.Context(), "panic in http handler",
				"path", r.URL.Path,
				"panic", v,
				"stack", string(debug.Stack()),
			)
			if rec, ok := w.(*statusRecorder); !ok || !rec.wroteHeader {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type requestIDKey struct{}

type clientIPKey struct{}

// reqLog returns the server logger with attrs plus, when the request came
// through a trusted proxy that supplied it, client_ip. All auth-event
// logging goes through it.
func (s *Server) reqLog(r *http.Request, attrs ...any) *slog.Logger {
	if ip, ok := r.Context().Value(clientIPKey{}).(string); ok {
		attrs = append(attrs, "client_ip", ip)
	}
	return s.log.With(attrs...)
}

// RequestID returns the request correlation ID set by the access-log
// middleware, or "".
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

func newRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never returns an error
	return hex.EncodeToString(b[:])
}

// statusRecorder captures the response status and size for logging.
type statusRecorder struct {
	http.ResponseWriter
	code        int
	bytes       int64
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.code = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

func (r *statusRecorder) status() int {
	if !r.wroteHeader {
		return http.StatusOK
	}
	return r.code
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
