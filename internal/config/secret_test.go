package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestSecretNeverRendered(t *testing.T) {
	const raw = "super-secret-value"
	s := NewSecret([]byte(raw))

	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		if out := fmt.Sprintf(verb, s); strings.Contains(out, raw) || strings.Contains(out, fmt.Sprintf("%x", raw)) {
			t.Errorf("fmt %s leaked secret: %q", verb, out)
		}
	}

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "secret", s)
	if strings.Contains(buf.String(), raw) || !strings.Contains(buf.String(), redacted) {
		t.Errorf("slog output not redacted: %s", buf.String())
	}

	j, err := json.Marshal(struct{ S Secret }{s})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(j), raw) {
		t.Errorf("json leaked secret: %s", j)
	}
}

func TestConfigPrintDoesNotLeakSecrets(t *testing.T) {
	f := newFixture(t)
	cfg := mustLoad(t, f)
	for _, out := range []string{fmt.Sprintf("%+v", cfg), fmt.Sprintf("%#v", *cfg)} {
		if strings.Contains(out, "client-secret-value") {
			t.Errorf("config dump leaked OIDC client secret")
		}
	}
}

func TestSecretBytesIsACopy(t *testing.T) {
	in := []byte("abc")
	s := NewSecret(in)
	in[0] = 'X'
	out := s.Bytes()
	out[1] = 'Y'
	if got := string(s.Bytes()); got != "abc" {
		t.Errorf("secret mutated through aliasing: %q", got)
	}
	if !(Secret{}).IsZero() || s.IsZero() || s.Len() != 3 {
		t.Errorf("IsZero/Len wrong")
	}
}
