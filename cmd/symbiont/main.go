// Command symbiont is a SAML IdP that authenticates users against an
// upstream OpenID Connect provider, letting SAML-only service providers
// (such as Fleet) use OIDC-only identity providers (such as Pocket ID).
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/kc9wwh/symbiont-sso/internal/config"
	"github.com/kc9wwh/symbiont-sso/internal/idp"
	"github.com/kc9wwh/symbiont-sso/internal/server"
)

// version is overridden at build time:
//
//	go build -ldflags "-X main.version=v1.2.3" ./cmd/symbiont
var version = ""

// Exit codes.
const (
	exitOK     = 0
	exitError  = 1
	exitUsage  = 2
	exitConfig = 3
)

const usage = `symbiont: SAML IdP bridge to an upstream OpenID Connect provider

Usage:
  symbiont [serve]    Run the bridge (default). Configured via environment variables.
  symbiont gencert    Generate a SAML signing certificate and key
                      (symbiont gencert --cn saml.example.com).
  symbiont version    Print the version and exit.
  symbiont help       Show this help.

See README.md for the full list of environment variables.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// run dispatches subcommands and returns the process exit code.
func run(ctx context.Context, args []string, lookup config.LookupFunc, stdout, stderr io.Writer) int {
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "serve":
		if len(args) > 0 {
			_, _ = fmt.Fprintf(stderr, "serve takes no arguments (configure via environment variables), got %q\n", args)
			return exitUsage
		}
		return runServe(ctx, lookup, stdout)
	case "gencert":
		return runGencert(args, stdout, stderr)
	case "version", "--version", "-v":
		_, _ = fmt.Fprintln(stdout, "symbiont", buildVersion())
		return exitOK
	case "help", "--help", "-h":
		_, _ = fmt.Fprint(stdout, usage)
		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return exitUsage
	}
}

// runServe loads configuration, binds the listener and serves until ctx is
// cancelled. Logs go to logOut as JSON.
func runServe(ctx context.Context, lookup config.LookupFunc, logOut io.Writer) int {
	levelVar := new(slog.LevelVar) // info until configuration is loaded
	logger := newLogger(logOut, levelVar)

	cfg, err := config.Load(lookup)
	if err != nil {
		var cerr *config.Error
		if errors.As(err, &cerr) {
			logger.Error("invalid configuration", "problems", cerr.Problems)
		} else {
			logger.Error("invalid configuration", "error", err)
		}
		return exitConfig
	}
	levelVar.Set(cfg.LogLevel)
	for _, w := range cfg.Warnings {
		logger.Warn("configuration warning", "detail", w)
	}

	p, err := buildIdP(cfg, logger)
	if err != nil {
		var cerr *config.Error
		if errors.As(err, &cerr) {
			logger.Error("invalid service provider configuration", "file", cfg.SPConfigFile, "problems", cerr.Problems)
		} else {
			logger.Error("invalid service provider configuration", "file", cfg.SPConfigFile, "error", err)
		}
		return exitConfig
	}

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		logger.Error("cannot listen", "addr", cfg.ListenAddr, "error", err)
		return exitError
	}
	if err := serve(ctx, cfg, logger, p, ln); err != nil {
		logger.Error("server error", "error", err)
		return exitError
	}
	return exitOK
}

// buildIdP loads and validates the service provider file and constructs the
// SAML identity provider.
func buildIdP(cfg *config.Config, logger *slog.Logger) (*idp.IdP, error) {
	spCfgs, warnings, err := config.LoadServiceProviders(cfg.SPConfigFile)
	if err != nil {
		return nil, err
	}
	for _, w := range warnings {
		logger.Warn("service provider configuration warning", "detail", w)
	}
	sps, err := idp.NewServiceProviders(spCfgs)
	if err != nil {
		return nil, err
	}
	for _, sp := range sps.All() {
		logger.Info("service provider loaded",
			"sp_id", sp.ID,
			"sp_entity_id", sp.EntityID,
			"acs_urls", sp.ACSURLs,
			"idp_initiated", sp.IDPInitiatedEnabled,
			"access_allow_all", sp.Access.AllowAll,
		)
	}
	return idp.New(idp.Options{
		BaseURL:     cfg.BaseURL,
		Certificate: cfg.SAML.Certificate,
		Key:         cfg.SAML.PrivateKey,
		SPs:         sps,
		Logger:      logger,
	})
}

// serve runs the HTTP server on ln until ctx is cancelled.
func serve(ctx context.Context, cfg *config.Config, logger *slog.Logger, p *idp.IdP, ln net.Listener) error {
	logger.Info("starting symbiont",
		"version", buildVersion(),
		"base_url", cfg.BaseURL.String(),
		"idp_entity_id", p.EntityID(),
		"metadata_url", cfg.URL(idp.MetadataPath),
		"oidc_issuer", cfg.OIDC.Issuer,
		"oidc_redirect_uri", cfg.CallbackURL(),
		"session_ttl", cfg.Session.TTL.String(),
	)
	// Sessions (the OIDC login backend) arrive in phase 3; until then /sso
	// validates requests and answers 503.
	srv := server.New(server.Options{Logger: logger, IdP: p})
	return srv.Run(ctx, ln)
}

func newLogger(w io.Writer, level slog.Leveler) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
}

// buildVersion prefers the ldflags value, then module/VCS build info.
func buildVersion() string {
	if version != "" {
		return version
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var rev, dirty string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if rev == "" {
		return "dev"
	}
	return "dev-" + rev + dirty
}
