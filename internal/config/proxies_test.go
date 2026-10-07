package config

import (
	"strings"
	"testing"
)

func TestTrustedProxies(t *testing.T) {
	f := newFixture(t)
	if cfg := mustLoad(t, f); cfg.TrustedProxies != nil {
		t.Errorf("default TrustedProxies = %v, want none", cfg.TrustedProxies)
	}

	f.env[EnvTrustedProxies] = "172.16.0.0/12, 127.0.0.1"
	cfg := mustLoad(t, f)
	if len(cfg.TrustedProxies) != 2 || cfg.TrustedProxies[1].String() != "127.0.0.1/32" || len(cfg.Warnings) != 0 {
		t.Errorf("TrustedProxies = %v warnings = %v", cfg.TrustedProxies, cfg.Warnings)
	}

	f.env[EnvTrustedProxies] = "0.0.0.0/0"
	cfg = mustLoad(t, f)
	if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], "very large range") {
		t.Errorf("warnings = %v", cfg.Warnings)
	}

	for _, bad := range []string{"10.0.0.0/40", "cloudflare", " , "} {
		f.env[EnvTrustedProxies] = bad
		requireProblem(t, loadProblems(t, f.lookup), EnvTrustedProxies)
	}
}
