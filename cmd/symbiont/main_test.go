package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kc9wwh/symbiont-sso/internal/config"
)

func noEnv(string) (string, bool) { return "", false }

const validSPFile = `service_providers:
  - id: fleet-admin
    entity_id: fleet.example.com
    acs_urls: [https://fleet.example.com/api/v1/fleet/sso/callback]
    access: {allow_groups: [fleet-admins]}
`

func TestRunHelpVersionAndUnknown(t *testing.T) {
	tests := []struct {
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{[]string{"help"}, exitOK, "Usage:", ""},
		{[]string{"--help"}, exitOK, "Usage:", ""},
		{[]string{"version"}, exitOK, "symbiont ", ""},
		{[]string{"bogus"}, exitUsage, "", `unknown command "bogus"`},
		{[]string{"serve", "extra"}, exitUsage, "", "serve takes no arguments"},
	}
	for _, tc := range tests {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), tc.args, noEnv, &stdout, &stderr)
			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d", code, tc.wantCode)
			}
			if !strings.Contains(stdout.String(), tc.wantStdout) {
				t.Errorf("stdout = %q, want substring %q", stdout.String(), tc.wantStdout)
			}
			if !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Errorf("stderr = %q, want substring %q", stderr.String(), tc.wantStderr)
			}
		})
	}
}

func TestServeInvalidConfigExitsWithConfigCode(t *testing.T) {
	var logs bytes.Buffer
	code := run(context.Background(), nil, noEnv, &logs, &logs)
	if code != exitConfig {
		t.Fatalf("exit code = %d, want %d", code, exitConfig)
	}
	out := logs.String()
	if !strings.Contains(out, `"msg":"invalid configuration"`) || !strings.Contains(out, "SYMBIONT_BASE_URL is required") {
		t.Errorf("unexpected log output: %s", out)
	}
}

// validEnv writes a valid key pair and SP file and returns an environment.
func validEnv(t *testing.T, listen string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	return map[string]string{
		config.EnvBaseURL:          "http://localhost:8080",
		config.EnvListenAddr:       listen,
		config.EnvSPConfigFile:     write("symbiont.yaml", []byte(validSPFile)),
		config.EnvOIDCIssuer:       "http://localhost:1411",
		config.EnvOIDCClientID:     "symbiont",
		config.EnvOIDCClientSecret: "s3cr3t-client",
		config.EnvSAMLCertFile:     write("cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		config.EnvSAMLKeyFile:      write("key.pem", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		config.EnvSessionSecret:    base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
}

func TestServeStartsAndStopsOnCancel(t *testing.T) {
	// Reserve a free port, then release it for the server to bind.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()

	env := validEnv(t, addr)
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	logs := &lockedBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"serve"}, lookup, logs, logs) }()

	var resp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err = http.Get("http://" + addr + "/healthz"); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("server never became healthy: %v\nlogs:\n%s", err, logs.String())
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d", resp.StatusCode)
	}

	cancel()
	select {
	case code := <-done:
		if code != exitOK {
			t.Fatalf("exit code = %d, want 0\nlogs:\n%s", code, logs.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop after context cancel")
	}

	out := logs.String()
	for _, want := range []string{
		`"msg":"starting symbiont"`,
		`"oidc_redirect_uri":"http://localhost:8080/oidc/callback"`,
		`"metadata_url":"http://localhost:8080/metadata"`,
		`"msg":"service provider loaded"`,
		`"sp_id":"fleet-admin"`,
		`"msg":"http server stopped"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("logs missing %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, "s3cr3t-client") {
		t.Errorf("logs leaked OIDC client secret")
	}
}

func TestServeInvalidSPFileExitsWithConfigCode(t *testing.T) {
	env := validEnv(t, "127.0.0.1:0")
	if err := os.WriteFile(env[config.EnvSPConfigFile], []byte("service_providers:\n  - {id: x, entity_id: x, acs_urls: [https://x.example.com/a]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	var logs bytes.Buffer
	if code := run(context.Background(), nil, lookup, &logs, &logs); code != exitConfig {
		t.Fatalf("exit = %d, want %d", code, exitConfig)
	}
	if !strings.Contains(logs.String(), "access block is required") {
		t.Errorf("logs = %s", logs.String())
	}
}

func TestServeListenFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	env := validEnv(t, ln.Addr().String()) // already in use
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	var logs bytes.Buffer
	if code := run(context.Background(), nil, lookup, &logs, &logs); code != exitError {
		t.Fatalf("exit code = %d, want %d; logs: %s", code, exitError, logs.String())
	}
	if !strings.Contains(logs.String(), "cannot listen") {
		t.Errorf("logs = %s", logs.String())
	}
}
