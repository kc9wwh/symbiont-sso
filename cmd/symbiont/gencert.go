package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"time"
)

const (
	gencertKeyBits     = 2048
	gencertDefaultDays = 3650
	gencertMaxDays     = 36500
)

// runGencert implements `symbiont gencert`: it writes a self-signed RSA-2048
// SAML signing certificate and private key. Existing files are never
// overwritten unless --force is given.
func runGencert(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gencert", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cn := fs.String("cn", "", "certificate common name, e.g. saml.example.com (required)")
	days := fs.Int("days", gencertDefaultDays, "validity period in days")
	outCert := fs.String("out-cert", "cert.pem", "certificate output path")
	outKey := fs.String("out-key", "key.pem", "private key output path (written with mode 0600)")
	force := fs.Bool("force", false, "overwrite existing files")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Usage: symbiont gencert --cn saml.example.com [--days 3650] [--out-cert cert.pem] [--out-key key.pem] [--force]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "gencert: unexpected arguments %q\n", fs.Args())
		return exitUsage
	}
	*cn = strings.TrimSpace(*cn)
	switch {
	case *cn == "":
		_, _ = fmt.Fprintln(stderr, "gencert: --cn is required")
		return exitUsage
	case *days < 1 || *days > gencertMaxDays:
		_, _ = fmt.Fprintf(stderr, "gencert: --days must be between 1 and %d\n", gencertMaxDays)
		return exitUsage
	case *outCert == *outKey:
		_, _ = fmt.Fprintln(stderr, "gencert: --out-cert and --out-key must differ")
		return exitUsage
	}
	if !*force {
		for _, p := range []string{*outCert, *outKey} {
			if _, err := os.Lstat(p); err == nil {
				_, _ = fmt.Fprintf(stderr, "gencert: %s already exists; refusing to overwrite (use --force)\n", p)
				return exitError
			}
		}
	}

	certPEM, keyPEM, cert, err := generateSigningCert(*cn, time.Duration(*days)*24*time.Hour)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "gencert: %v\n", err)
		return exitError
	}
	if err := writeFileAtomic(*outKey, keyPEM, 0o600, *force); err != nil {
		_, _ = fmt.Fprintf(stderr, "gencert: write key: %v\n", err)
		return exitError
	}
	if err := writeFileAtomic(*outCert, certPEM, 0o644, *force); err != nil {
		_, _ = fmt.Fprintf(stderr, "gencert: write certificate: %v\n", err)
		return exitError
	}
	fp := sha256.Sum256(cert.Raw)
	_, _ = fmt.Fprintf(stdout, "Wrote %s and %s\n  subject:  CN=%s\n  expires:  %s\n  sha256:   %s\n",
		*outCert, *outKey, *cn, cert.NotAfter.UTC().Format(time.RFC3339), colonHex(fp[:]))
	return exitOK
}

func generateSigningCert(cn string, validity time.Duration) (certPEM, keyPEM []byte, cert *x509.Certificate, err error) {
	key, err := rsa.GenerateKey(rand.Reader, gencertKeyBits)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate serial: %w", err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-5 * time.Minute), // tolerate small clock skew
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), cert, nil
}

// writeFileAtomic writes via a temp file + rename so a crash never leaves a
// truncated key. Without overwrite, it fails if path appeared meanwhile.
func writeFileAtomic(path string, data []byte, mode os.FileMode, overwrite bool) error {
	if !overwrite {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return err
		}
		if _, err := f.Write(data); err != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return err
		}
		return f.Close()
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil { // WriteFile honours umask
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func colonHex(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	parts := make([]string, 0, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}
