package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// RSA key generation is slow; share keys across tests.
var (
	keyOnce          sync.Once
	rsaKeyA, rsaKeyB *rsa.PrivateKey
	rsaKeySmall      *rsa.PrivateKey
)

func testKeys(t *testing.T) (a, b, small *rsa.PrivateKey) {
	t.Helper()
	keyOnce.Do(func() {
		var err error
		if rsaKeyA, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if rsaKeyB, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		// Deliberately undersized key for negative tests only.
		if rsaKeySmall, err = rsa.GenerateKey(rand.Reader, 1024); err != nil {
			panic(err)
		}
	})
	return rsaKeyA, rsaKeyB, rsaKeySmall
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// certPEM returns a self-signed certificate for pub signed by priv.
func certPEM(t *testing.T, pub, priv any, notBefore, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "saml.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pkcs1PEM(k *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

func pkcs8PEM(t *testing.T, k any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// fixture holds paths to a valid set of files and a matching environment.
type fixture struct {
	dir      string
	certPath string
	keyPath  string
	spPath   string
	env      map[string]string
}

var validSecret = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

func newFixture(t *testing.T) *fixture {
	t.Helper()
	a, _, _ := testKeys(t)
	dir := t.TempDir()
	now := time.Now()
	f := &fixture{dir: dir}
	f.certPath = writeFile(t, dir, "cert.pem", certPEM(t, &a.PublicKey, a, now.Add(-time.Hour), now.Add(365*24*time.Hour)))
	f.keyPath = writeFile(t, dir, "key.pem", pkcs1PEM(a))
	f.spPath = writeFile(t, dir, "symbiont.yaml", []byte("service_providers: []\n"))
	f.env = map[string]string{
		EnvBaseURL:          "https://saml.example.com",
		EnvSPConfigFile:     f.spPath,
		EnvOIDCIssuer:       "https://id.example.com",
		EnvOIDCClientID:     "symbiont",
		EnvOIDCClientSecret: "client-secret-value",
		EnvSAMLCertFile:     f.certPath,
		EnvSAMLKeyFile:      f.keyPath,
		EnvSessionSecret:    validSecret,
	}
	return f
}

func (f *fixture) lookup(key string) (string, bool) {
	v, ok := f.env[key]
	return v, ok
}
