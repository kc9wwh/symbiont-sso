// Package server wires symbiont's HTTP handlers, middleware and lifecycle.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/kc9wwh/symbiont-sso/internal/clientip"
	"github.com/kc9wwh/symbiont-sso/internal/idp"
)

// Default HTTP server limits. Every SAML/OIDC request is small, so the
// limits are deliberately tight.
const (
	DefaultReadHeaderTimeout = 10 * time.Second
	DefaultReadTimeout       = 30 * time.Second
	DefaultWriteTimeout      = 30 * time.Second
	DefaultIdleTimeout       = 120 * time.Second
	DefaultShutdownTimeout   = 15 * time.Second
	DefaultMaxHeaderBytes    = 64 << 10
)

// Options configures a Server. Zero values select the defaults above.
type Options struct {
	Logger *slog.Logger
	// IdP enables the SAML endpoints (/metadata, /sso). Nil serves only
	// /healthz.
	IdP *idp.IdP
	// Login enables the upstream OIDC login (/oidc/callback) and the
	// cookie-backed bridge session. When set, it provides Sessions.
	Login *Login
	// Sessions resolves the signed-in user for SSO requests. Ignored when
	// Login is set. If both are nil, /sso validates requests but answers
	// 503. Tests use fixed identities here.
	Sessions Sessions
	// ClientIP resolves the real client IP for logs when behind trusted
	// proxies. Nil logs only the socket peer.
	ClientIP *clientip.Resolver

	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
}

// Server is symbiont's HTTP front end.
type Server struct {
	log     *slog.Logger
	opts    Options
	handler http.Handler
}

// New builds a Server and registers all routes. It panics on an invalid
// Login configuration (a programming error; config validation happens
// earlier).
func New(opts Options) *Server {
	if opts.Login != nil {
		if err := opts.Login.validate(); err != nil {
			panic(err)
		}
		if opts.IdP == nil {
			panic("server: Login requires IdP")
		}
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	setDefault(&opts.ReadHeaderTimeout, DefaultReadHeaderTimeout)
	setDefault(&opts.ReadTimeout, DefaultReadTimeout)
	setDefault(&opts.WriteTimeout, DefaultWriteTimeout)
	setDefault(&opts.IdleTimeout, DefaultIdleTimeout)
	setDefault(&opts.ShutdownTimeout, DefaultShutdownTimeout)

	s := &Server{log: opts.Logger, opts: opts}
	if opts.Login != nil {
		s.opts.Sessions = oidcSessions{s}
	}
	mux := http.NewServeMux()
	s.routes(mux)
	s.handler = s.middleware(mux)
	return s
}

func setDefault(d *time.Duration, def time.Duration) {
	if *d <= 0 {
		*d = def
	}
}

// Handler returns the fully wrapped root handler (useful for tests).
func (s *Server) Handler() http.Handler { return s.handler }

// routes registers every endpoint.
func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	if s.opts.IdP != nil {
		mux.HandleFunc("GET "+idp.MetadataPath, s.handleMetadata)
		mux.HandleFunc("GET "+idp.SSOPath, s.handleSSO)
		mux.HandleFunc("POST "+idp.SSOPath, s.handleSSO)
	}
	if s.opts.Login != nil {
		mux.HandleFunc("GET "+CallbackPath, s.handleCallback)
		mux.HandleFunc("GET "+LoginPathPrefix+"{sp_id}", s.handleLogin)
	}
}

// Run serves HTTP on ln until ctx is cancelled, then shuts down gracefully,
// waiting up to ShutdownTimeout for in-flight requests. It returns nil after
// a clean shutdown.
func (s *Server) Run(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: s.opts.ReadHeaderTimeout,
		ReadTimeout:       s.opts.ReadTimeout,
		WriteTimeout:      s.opts.WriteTimeout,
		IdleTimeout:       s.opts.IdleTimeout,
		MaxHeaderBytes:    DefaultMaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
		BaseContext:       func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	s.log.Info("http server listening", "addr", ln.Addr().String())

	select {
	case err := <-errCh:
		// Serve never returns nil; anything here is a startup/accept failure.
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
	}

	s.log.Info("shutting down http server", "timeout", s.opts.ShutdownTimeout.String())
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.opts.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		_ = srv.Close()
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server: %w", err)
	}
	s.log.Info("http server stopped")
	return nil
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
}
