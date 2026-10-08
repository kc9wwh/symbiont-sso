package session

import (
	"strings"
	"testing"
	"time"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func newTestSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := NewSigner(testKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignerRoundTrip(t *testing.T) {
	s := newTestSigner(t)
	now := time.Now()
	tok := s.Sign(PurposeSession, "abc.def", now.Add(time.Minute))
	got, err := s.Verify(PurposeSession, tok, now)
	if err != nil || got != "abc.def" {
		t.Fatalf("Verify = %q, %v", got, err)
	}
	if strings.Contains(tok, "abc.def") && !strings.HasPrefix(tok, "AQ") {
		t.Errorf("unexpected token encoding: %s", tok)
	}
}

func TestSignerRejections(t *testing.T) {
	s := newTestSigner(t)
	now := time.Now()
	tok := s.Sign(PurposeSession, "session-id", now.Add(time.Minute))

	other, _ := NewSigner([]byte("ffffffffffffffffffffffffffffffff"))
	payload, mac, _ := strings.Cut(tok, ".")
	flip := func(s string) string {
		b := []byte(s)
		if b[len(b)-2] == 'A' {
			b[len(b)-2] = 'B'
		} else {
			b[len(b)-2] = 'A'
		}
		return string(b)
	}

	tests := []struct {
		name  string
		token string
		purp  string
		at    time.Time
		want  error
	}{
		{"expired", tok, PurposeSession, now.Add(time.Minute), ErrExpiredToken},
		{"wrong purpose", tok, PurposeState, now, ErrInvalidToken},
		{"tampered payload", flip(payload) + "." + mac, PurposeSession, now, ErrInvalidToken},
		{"tampered mac", payload + "." + flip(mac), PurposeSession, now, ErrInvalidToken},
		{"other key", other.Sign(PurposeSession, "session-id", now.Add(time.Minute)), PurposeSession, now, ErrInvalidToken},
		{"no dot", payload, PurposeSession, now, ErrInvalidToken},
		{"empty", "", PurposeSession, now, ErrInvalidToken},
		{"garbage", "!!!.???", PurposeSession, now, ErrInvalidToken},
		{"short payload", "AQ.AA", PurposeSession, now, ErrInvalidToken},
		{"oversized", strings.Repeat("a", maxTokenLength+1), PurposeSession, now, ErrInvalidToken},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.Verify(tc.purp, tc.token, tc.at); err != tc.want {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// Tampering with the expiry (extending a token) must invalidate the MAC.
func TestSignerExpiryIsAuthenticated(t *testing.T) {
	s := newTestSigner(t)
	now := time.Now()
	short := s.Sign(PurposeSession, "x", now.Add(time.Second))
	long := s.Sign(PurposeSession, "x", now.Add(time.Hour))
	sp, _, _ := strings.Cut(short, ".")
	_, lm, _ := strings.Cut(long, ".")
	if _, err := s.Verify(PurposeSession, sp+"."+lm, now); err != ErrInvalidToken {
		t.Errorf("spliced token err = %v", err)
	}
}

func TestNewSignerRejectsShortKey(t *testing.T) {
	if _, err := NewSigner(make([]byte, 31)); err == nil {
		t.Error("31-byte key accepted")
	}
}

func TestNewIDUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := NewID()
		if len(id) != 43 || seen[id] {
			t.Fatalf("bad or duplicate id %q", id)
		}
		seen[id] = true
	}
}
