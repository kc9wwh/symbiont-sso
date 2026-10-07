package config

import (
	"strings"
	"testing"
)

func TestLoadLocalhostHTTPAllowed(t *testing.T) {
	for _, u := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		t.Run(u, func(t *testing.T) {
			f := newFixture(t)
			f.env[EnvBaseURL] = u
			f.env[EnvOIDCIssuer] = "http://localhost:1411"
			cfg := mustLoad(t, f)
			if len(cfg.Warnings) == 0 || !strings.Contains(cfg.Warnings[0], "plain http") {
				t.Errorf("expected plain-http warning, got %v", cfg.Warnings)
			}
		})
	}
}

func TestLoadRequiredVariables(t *testing.T) {
	problems := loadProblems(t, func(string) (string, bool) { return "", false })
	for _, key := range []string{
		EnvBaseURL, EnvSPConfigFile, EnvOIDCIssuer, EnvOIDCClientID,
		EnvOIDCClientSecret, EnvSAMLCertFile, EnvSAMLKeyFile, EnvSessionSecret,
	} {
		requireProblem(t, problems, key)
	}
	if len(problems) != 8 {
		t.Errorf("got %d problems, want exactly 8 (one per required variable):\n  %s",
			len(problems), strings.Join(problems, "\n  "))
	}
}

func TestLoadEmptyValueTreatedAsUnset(t *testing.T) {
	f := newFixture(t)
	f.env[EnvOIDCClientID] = "   "
	f.env[EnvListenAddr] = ""
	problems := loadProblems(t, f.lookup)
	requireProblem(t, problems, EnvOIDCClientID+" is required")
	if len(problems) != 1 {
		t.Errorf("empty SYMBIONT_LISTEN_ADDR should fall back to default; problems: %v", problems)
	}
}

func TestErrorMessageListsAllProblems(t *testing.T) {
	err := (&Error{Problems: []string{"a broke", "b broke"}}).Error()
	want := "invalid configuration (2 problems):\n  - a broke\n  - b broke"
	if err != want {
		t.Errorf("Error() = %q, want %q", err, want)
	}
	if one := (&Error{Problems: []string{"x"}}).Error(); !strings.HasPrefix(one, "invalid configuration (1 problem):") {
		t.Errorf("singular form wrong: %q", one)
	}
}

func TestRemovedVariablesWarn(t *testing.T) {
	f := newFixture(t)
	f.env["BRIDGE_BASE_URL"] = "https://old.example.com"
	f.env["SAML_SP_ENTITY_ID"] = "fleet.example.com"
	cfg := mustLoad(t, f)
	joined := strings.Join(cfg.Warnings, "\n")
	for _, want := range []string{
		"BRIDGE_BASE_URL is no longer used (renamed to SYMBIONT_BASE_URL)",
		"SAML_SP_ENTITY_ID is no longer used",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings missing %q:\n%s", want, joined)
		}
	}
}
