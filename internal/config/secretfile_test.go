package config

import (
	"encoding/base64"
	"testing"
)

func TestSecretFileVariants(t *testing.T) {
	t.Run("client secret from file", func(t *testing.T) {
		f := newFixture(t)
		delete(f.env, EnvOIDCClientSecret)
		f.env[EnvOIDCClientSecret+FileSuffix] = writeFile(t, f.dir, "client", []byte("from-file\n"))
		cfg := mustLoad(t, f)
		if got := string(cfg.OIDC.ClientSecret.Bytes()); got != "from-file" {
			t.Errorf("client secret = %q, want trimmed file content", got)
		}
	})
	t.Run("session secret from file", func(t *testing.T) {
		f := newFixture(t)
		delete(f.env, EnvSessionSecret)
		f.env[EnvSessionSecret+FileSuffix] = writeFile(t, f.dir, "session", []byte(validSecret+"\n"))
		if cfg := mustLoad(t, f); cfg.Session.Secret.Len() != 32 {
			t.Errorf("session secret len = %d", cfg.Session.Secret.Len())
		}
	})
	t.Run("both set is an error", func(t *testing.T) {
		f := newFixture(t)
		f.env[EnvOIDCClientSecret+FileSuffix] = writeFile(t, f.dir, "client", []byte("x"))
		problems := loadProblems(t, f.lookup)
		requireProblem(t, problems, "OIDC_CLIENT_SECRET and OIDC_CLIENT_SECRET_FILE are mutually exclusive")
		if len(problems) != 1 {
			t.Errorf("want one problem, got %v", problems)
		}
	})
	t.Run("missing file", func(t *testing.T) {
		f := newFixture(t)
		delete(f.env, EnvOIDCClientSecret)
		f.env[EnvOIDCClientSecret+FileSuffix] = "/nonexistent/secret"
		problems := loadProblems(t, f.lookup)
		requireProblem(t, problems, "OIDC_CLIENT_SECRET_FILE: cannot read secret file")
		if len(problems) != 1 {
			t.Errorf("want one problem (no redundant 'is required'), got %v", problems)
		}
	})
	t.Run("empty file", func(t *testing.T) {
		f := newFixture(t)
		delete(f.env, EnvSessionSecret)
		f.env[EnvSessionSecret+FileSuffix] = writeFile(t, f.dir, "empty", []byte(" \n"))
		requireProblem(t, loadProblems(t, f.lookup), "SESSION_SECRET_FILE: secret file")
	})
	t.Run("short secret in file names the file variable", func(t *testing.T) {
		f := newFixture(t)
		delete(f.env, EnvSessionSecret)
		short := base64.StdEncoding.EncodeToString([]byte("tooshort"))
		f.env[EnvSessionSecret+FileSuffix] = writeFile(t, f.dir, "short", []byte(short))
		requireProblem(t, loadProblems(t, f.lookup), "SESSION_SECRET_FILE must decode to at least 32 bytes")
	})
	t.Run("oversized file", func(t *testing.T) {
		f := newFixture(t)
		delete(f.env, EnvOIDCClientSecret)
		f.env[EnvOIDCClientSecret+FileSuffix] = writeFile(t, f.dir, "big", make([]byte, maxSecretFileBytes+1))
		requireProblem(t, loadProblems(t, f.lookup), "exceeds")
	})
}
