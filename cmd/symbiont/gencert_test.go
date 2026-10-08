package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kc9wwh/symbiont-sso/internal/config"
)

func gencert(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), append([]string{"gencert"}, args...), noEnv, &out, &errb)
	return code, out.String(), errb.String()
}

func TestGencertWritesUsableKeyPair(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	code, out, errOut := gencert(t, "--cn", "saml.example.com", "--days", "90", "--out-cert", certPath, "--out-key", keyPath)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "CN=saml.example.com") || !strings.Contains(out, "sha256:") {
		t.Errorf("stdout = %q", out)
	}

	st, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("key mode = %o, want 600", perm)
	}

	raw, _ := os.ReadFile(certPath)
	block, _ := pem.Decode(raw)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "saml.example.com" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
	if pub := cert.PublicKey.(*rsa.PublicKey); pub.N.BitLen() != 2048 {
		t.Errorf("key bits = %d", pub.N.BitLen())
	}
	if d := time.Until(cert.NotAfter); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Errorf("NotAfter = %v", cert.NotAfter)
	}

	// The pair must pass the same validation the server applies at startup.
	f := map[string]string{
		config.EnvBaseURL: "https://saml.example.com", config.EnvSPConfigFile: certPath,
		config.EnvOIDCIssuer: "https://id.example.com", config.EnvOIDCClientID: "c",
		config.EnvOIDCClientSecret: "s", config.EnvSAMLCertFile: certPath, config.EnvSAMLKeyFile: keyPath,
		config.EnvSessionSecret: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
	}
	cfg, err := config.Load(func(k string) (string, bool) { v, ok := f[k]; return v, ok })
	if err != nil {
		t.Fatalf("generated pair rejected by config: %v", err)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("warnings: %v", cfg.Warnings)
	}
}

func TestGencertRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := os.WriteFile(keyPath, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := gencert(t, "--cn", "x", "--out-cert", certPath, "--out-key", keyPath)
	if code != exitError || !strings.Contains(errOut, "refusing to overwrite") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if b, _ := os.ReadFile(keyPath); string(b) != "precious" {
		t.Error("existing key was modified")
	}
	if _, err := os.Stat(certPath); !os.IsNotExist(err) {
		t.Error("cert written despite refusal")
	}

	code, _, errOut = gencert(t, "--cn", "x", "--out-cert", certPath, "--out-key", keyPath, "--force")
	if code != exitOK {
		t.Fatalf("--force exit %d: %s", code, errOut)
	}
	if b, _ := os.ReadFile(keyPath); !bytes.Contains(b, []byte("PRIVATE KEY")) {
		t.Error("key not replaced with --force")
	}
	if st, _ := os.Stat(keyPath); st.Mode().Perm() != 0o600 {
		t.Errorf("forced key mode = %o", st.Mode().Perm())
	}
}

func TestGencertUsageErrors(t *testing.T) {
	dir := t.TempDir()
	for name, args := range map[string][]string{
		"missing cn": {},
		"zero days":  {"--cn", "x", "--days", "0"},
		"huge days":  {"--cn", "x", "--days", "99999"},
		"same paths": {"--cn", "x", "--out-cert", filepath.Join(dir, "a"), "--out-key", filepath.Join(dir, "a")},
		"extra args": {"--cn", "x", "oops"},
		"bad flag":   {"--nope"},
	} {
		t.Run(name, func(t *testing.T) {
			if code, _, _ := gencert(t, args...); code != exitUsage {
				t.Errorf("exit = %d, want %d", code, exitUsage)
			}
		})
	}
	if code, _, _ := gencert(t, "-h"); code != exitOK {
		t.Errorf("-h exit = %d", code)
	}
}
