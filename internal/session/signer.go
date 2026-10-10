// Package session provides HMAC-signed tokens for cookies, and bounded,
// expiring in-memory stores for pending logins and bridge sessions. Stores
// sit behind interfaces so a shared backend (e.g. Redis) can replace them.
package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"time"
)

// Token purposes. A token signed for one purpose never verifies for another.
const (
	PurposeSession = "session"
	PurposeState   = "state"
	PurposeReplay  = "replay"
)

const (
	tokenVersion   = 1
	maxTokenLength = 4096
	headerLen      = 1 + 8 // version + expiry (unix seconds)
	// MinKeyBytes is the minimum signing key length.
	MinKeyBytes = 32
)

// Verification errors.
var (
	ErrInvalidToken = errors.New("session: invalid token")
	ErrExpiredToken = errors.New("session: expired token")
)

// Signer produces and verifies tamper-evident, expiring tokens:
//
//	base64url(version | expiry | value) "." base64url(HMAC-SHA256)
//
// Each purpose uses its own key derived from the master key.
type Signer struct {
	master []byte
}

// NewSigner returns a Signer using key (at least MinKeyBytes).
func NewSigner(key []byte) (*Signer, error) {
	if len(key) < MinKeyBytes {
		return nil, errors.New("session: signing key must be at least 32 bytes")
	}
	return &Signer{master: append([]byte(nil), key...)}, nil
}

func (s *Signer) mac(purpose string, payload []byte) []byte {
	k := hmac.New(sha256.New, s.master)
	k.Write([]byte("symbiont/token/v1/" + purpose))
	m := hmac.New(sha256.New, k.Sum(nil))
	m.Write(payload)
	return m.Sum(nil)
}

// Sign returns a token carrying value until expires.
func (s *Signer) Sign(purpose, value string, expires time.Time) string {
	payload := make([]byte, headerLen, headerLen+len(value))
	payload[0] = tokenVersion
	binary.BigEndian.PutUint64(payload[1:headerLen], uint64(expires.Unix())) //nolint:gosec // G115: bit-preserving round trip with Verify's int64 cast
	payload = append(payload, value...)
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(s.mac(purpose, payload))
}

// Verify checks token's signature (in constant time) and expiry at now, and
// returns the signed value.
func (s *Signer) Verify(purpose, token string, now time.Time) (string, error) {
	if len(token) == 0 || len(token) > maxTokenLength {
		return "", ErrInvalidToken
	}
	p64, m64, ok := strings.Cut(token, ".")
	if !ok {
		return "", ErrInvalidToken
	}
	enc := base64.RawURLEncoding
	payload, err1 := enc.DecodeString(p64)
	mac, err2 := enc.DecodeString(m64)
	if err1 != nil || err2 != nil || len(payload) < headerLen {
		return "", ErrInvalidToken
	}
	if !hmac.Equal(mac, s.mac(purpose, payload)) {
		return "", ErrInvalidToken
	}
	if payload[0] != tokenVersion {
		return "", ErrInvalidToken
	}
	exp := int64(binary.BigEndian.Uint64(payload[1:headerLen])) //nolint:gosec // G115: inverse of Sign's cast; payload is HMAC-verified above
	if now.Unix() >= exp {
		return "", ErrExpiredToken
	}
	return string(payload[headerLen:]), nil
}

// NewID returns 256 bits of randomness, base64url-encoded (43 characters).
// Used for session IDs, OAuth state, and nonces.
func NewID() string {
	var b [32]byte
	_, _ = rand.Read(b[:]) // never fails
	return base64.RawURLEncoding.EncodeToString(b[:])
}
