package config

import "testing"

func TestLoadRateLimitAndCFHeader(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		want    int
		wantCF  bool
		problem string
	}{
		{"defaults", nil, DefaultRateLimitPerMinute, false, ""},
		{"custom", map[string]string{EnvRateLimitPerMinute: "10"}, 10, false, ""},
		{"zero disables", map[string]string{EnvRateLimitPerMinute: "0"}, 0, false, ""},
		{"cloudflare header opt-in", map[string]string{EnvTrustCFConnectingIP: "true"}, DefaultRateLimitPerMinute, true, ""},
		{"negative", map[string]string{EnvRateLimitPerMinute: "-1"}, 0, false, EnvRateLimitPerMinute},
		{"not a number", map[string]string{EnvRateLimitPerMinute: "fast"}, 0, false, EnvRateLimitPerMinute},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			for k, v := range tc.env {
				f.env[k] = v
			}
			if tc.problem != "" {
				requireProblem(t, loadProblems(t, f.lookup), tc.problem)
				return
			}
			cfg := mustLoad(t, f)
			if cfg.RateLimitPerMinute != tc.want || cfg.TrustCFConnectingIP != tc.wantCF {
				t.Errorf("RateLimitPerMinute=%d TrustCFConnectingIP=%v; want %d, %v",
					cfg.RateLimitPerMinute, cfg.TrustCFConnectingIP, tc.want, tc.wantCF)
			}
		})
	}
}
