package config

import (
	"encoding/pem"
	"testing"
	"time"
)

func TestSAMLKeyPair(t *testing.T) {
	a, b, small := testKeys(t)
	now := time.Now()
	validCert := func(t *testing.T) []byte {
		return certPEM(t, &a.PublicKey, a, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	}

	tests := []struct {
		name string
		cert func(t *testing.T) []byte // nil = keep fixture
		key  func(t *testing.T) []byte // nil = keep fixture
		want string                    // expected problem substring; "" = success
	}{
		{name: "pkcs8 key accepted", key: func(t *testing.T) []byte { return pkcs8PEM(t, a) }},
		{
			name: "cert chain picks first certificate after other blocks",
			cert: func(t *testing.T) []byte {
				junk := pem.EncodeToMemory(&pem.Block{Type: "COMMENT", Bytes: []byte("x")})
				return append(junk, validCert(t)...)
			},
		},
		{
			name: "mismatched key",
			key:  func(*testing.T) []byte { return pkcs1PEM(b) },
			want: "do not match",
		},
		{
			name: "expired certificate",
			cert: func(t *testing.T) []byte {
				return certPEM(t, &a.PublicKey, a, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
			},
			want: "certificate expired on",
		},
		{
			name: "not yet valid certificate",
			cert: func(t *testing.T) []byte {
				return certPEM(t, &a.PublicKey, a, now.Add(24*time.Hour), now.Add(48*time.Hour))
			},
			want: "certificate is not valid until",
		},
		{
			name: "small key",
			key:  func(*testing.T) []byte { return pkcs1PEM(small) },
			want: "RSA key is 1024 bits, want at least 2048",
		},
		{
			name: "small certificate key",
			cert: func(t *testing.T) []byte {
				return certPEM(t, &small.PublicKey, small, now.Add(-time.Hour), now.Add(time.Hour*24*365))
			},
			want: "certificate RSA key is 1024 bits",
		},
		{
			name: "ecdsa key rejected",
			key:  func(t *testing.T) []byte { return pkcs8PEM(t, ecKey(t)) },
			want: "want RSA",
		},
		{
			name: "ecdsa certificate rejected",
			cert: func(t *testing.T) []byte {
				k := ecKey(t)
				return certPEM(t, &k.PublicKey, k, now.Add(-time.Hour), now.Add(time.Hour*24*365))
			},
			want: "certificate key type is *ecdsa.PublicKey, want RSA",
		},
		{
			name: "encrypted key rejected",
			key: func(*testing.T) []byte {
				return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1}})
			},
			want: "encrypted private keys are not supported",
		},
		{
			name: "garbage cert file",
			cert: func(*testing.T) []byte { return []byte("not a pem") },
			want: "contains no PEM CERTIFICATE block",
		},
		{
			name: "garbage key file",
			key:  func(*testing.T) []byte { return []byte("not a pem") },
			want: "contains no PEM private key block",
		},
		{
			name: "corrupt certificate DER",
			cert: func(*testing.T) []byte {
				return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x00}})
			},
			want: "cannot parse certificate",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			if tc.cert != nil {
				f.env[EnvSAMLCertFile] = writeFile(t, f.dir, "c.pem", tc.cert(t))
			}
			if tc.key != nil {
				f.env[EnvSAMLKeyFile] = writeFile(t, f.dir, "k.pem", tc.key(t))
			}
			if tc.want == "" {
				mustLoad(t, f)
				return
			}
			problems := loadProblems(t, f.lookup)
			requireProblem(t, problems, tc.want)
			if len(problems) != 1 {
				t.Errorf("want exactly one problem, got %v", problems)
			}
		})
	}
}

func TestSAMLKeyPairUnreadableFiles(t *testing.T) {
	f := newFixture(t)
	f.env[EnvSAMLCertFile] = "/nonexistent/cert.pem"
	f.env[EnvSAMLKeyFile] = "/nonexistent/key.pem"
	problems := loadProblems(t, f.lookup)
	requireProblem(t, problems, `SAML_CERT_FILE: cannot read "/nonexistent/cert.pem"`)
	requireProblem(t, problems, `SAML_KEY_FILE: cannot read "/nonexistent/key.pem"`)
}

func TestSAMLCertExpiringSoonWarns(t *testing.T) {
	a, _, _ := testKeys(t)
	f := newFixture(t)
	now := time.Now()
	f.env[EnvSAMLCertFile] = writeFile(t, f.dir, "soon.pem",
		certPEM(t, &a.PublicKey, a, now.Add(-time.Hour), now.Add(7*24*time.Hour)))
	cfg := mustLoad(t, f)
	if len(cfg.Warnings) != 1 {
		t.Fatalf("want one expiry warning, got %v", cfg.Warnings)
	}
}
