package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const maxPEMFileBytes = 1 << 20

// samlKeyPair loads and cross-checks the IdP signing certificate and key.
func (l *loader) samlKeyPair(certKey, keyKey string) SAMLConfig {
	out := SAMLConfig{}
	certPath, hasCert := l.get(certKey)
	keyPath, hasKey := l.get(keyKey)
	if !hasCert {
		l.problemf("%s is required (generate a pair with: symbiont gencert)", certKey)
	}
	if !hasKey {
		l.problemf("%s is required (generate a pair with: symbiont gencert)", keyKey)
	}
	out.CertFile, out.KeyFile = certPath, keyPath

	if hasCert {
		cert, err := loadCertificate(certPath)
		if err != nil {
			l.problemf("%s: %v", certKey, err)
		} else {
			out.Certificate = cert
			l.checkCertValidity(certKey, cert)
		}
	}
	if hasKey {
		key, err := loadRSAPrivateKey(keyPath)
		if err != nil {
			l.problemf("%s: %v", keyKey, err)
		} else {
			out.PrivateKey = key
		}
	}

	if out.Certificate != nil && out.PrivateKey != nil {
		pub, ok := out.Certificate.PublicKey.(*rsa.PublicKey)
		if !ok {
			l.problemf("%s: certificate public key is %T, want RSA", certKey, out.Certificate.PublicKey)
		} else if !pub.Equal(&out.PrivateKey.PublicKey) {
			l.problemf("%s and %s do not match: the private key does not belong to the certificate", certKey, keyKey)
		}
	}
	return out
}

func (l *loader) checkCertValidity(key string, cert *x509.Certificate) {
	now := l.clock()
	switch {
	case now.Before(cert.NotBefore):
		l.problemf("%s: certificate is not valid until %s", key, cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"))
	case now.After(cert.NotAfter):
		l.problemf("%s: certificate expired on %s", key, cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"))
	case cert.NotAfter.Sub(now) < certExpiryWarningWindow:
		l.warnf("%s: certificate expires soon (%s); rotate it and update service provider metadata",
			key, cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"))
	}
}

// loadCertificate reads the first CERTIFICATE block from a PEM file.
func loadCertificate(path string) (*x509.Certificate, error) {
	data, err := readLimited(path, maxPEMFileBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot read %q: %w", path, err)
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("%q contains no PEM CERTIFICATE block", path)
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%q: cannot parse certificate: %w", path, err)
		}
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%q: certificate key type is %T, want RSA", path, cert.PublicKey)
		}
		if bits := pub.N.BitLen(); bits < MinRSAKeyBits {
			return nil, fmt.Errorf("%q: certificate RSA key is %d bits, want at least %d", path, bits, MinRSAKeyBits)
		}
		return cert, nil
	}
}

// loadRSAPrivateKey reads an unencrypted RSA key in PKCS#1 or PKCS#8 form.
func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := readLimited(path, maxPEMFileBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot read %q: %w", path, err)
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("%q contains no PEM private key block", path)
		}
		var key *rsa.PrivateKey
		switch block.Type {
		case "RSA PRIVATE KEY":
			if _, encrypted := block.Headers["DEK-Info"]; encrypted {
				return nil, fmt.Errorf("%q: encrypted private keys are not supported", path)
			}
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "PRIVATE KEY":
			var k any
			k, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err == nil {
				var ok bool
				if key, ok = k.(*rsa.PrivateKey); !ok {
					return nil, fmt.Errorf("%q: private key type is %T, want RSA", path, k)
				}
			}
		case "ENCRYPTED PRIVATE KEY":
			return nil, fmt.Errorf("%q: encrypted private keys are not supported", path)
		default:
			continue
		}
		if err != nil {
			// x509 parser errors describe structure only, never key material.
			return nil, fmt.Errorf("%q: cannot parse %s block: %w", path, block.Type, err)
		}
		if bits := key.N.BitLen(); bits < MinRSAKeyBits {
			return nil, fmt.Errorf("%q: RSA key is %d bits, want at least %d", path, bits, MinRSAKeyBits)
		}
		if err := key.Validate(); err != nil {
			return nil, fmt.Errorf("%q: invalid RSA key: %w", path, err)
		}
		return key, nil
	}
}
