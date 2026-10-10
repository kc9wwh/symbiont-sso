package session

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// FuzzSignerRoundTrip: whatever value, purpose and expiry are signed, the
// token verifies for that purpose before expiry, returns the exact value,
// and fails after expiry and for any other purpose or key.
func FuzzSignerRoundTrip(f *testing.F) {
	f.Add(PurposeSession, "abc.def", int64(60))
	f.Add(PurposeState, "", int64(1))
	f.Add(PurposeReplay, "1234.digest", int64(300))
	f.Add("", "\x00\xff", int64(-5))
	f.Add(PurposeSession, strings.Repeat("v", 3000), int64(1))
	s, err := NewSigner(testKey)
	if err != nil {
		f.Fatal(err)
	}
	other, err := NewSigner([]byte("ffffffffffffffffffffffffffffffff"))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, purpose, value string, ttlSeconds int64) {
		// Keep within the range where time.Time arithmetic cannot overflow.
		if ttlSeconds < -1<<40 || ttlSeconds > 1<<40 {
			t.Skip()
		}
		now := time.Unix(1_800_000_000, 0)
		exp := now.Add(time.Duration(ttlSeconds) * time.Second)
		tok := s.Sign(purpose, value, exp)

		got, err := s.Verify(purpose, tok, now)
		switch {
		case len(tok) > maxTokenLength:
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("oversized token: err = %v, want ErrInvalidToken", err)
			}
			return
		case ttlSeconds > 0:
			if err != nil || got != value {
				t.Fatalf("Verify = %q, %v; want %q", got, err, value)
			}
		default:
			if !errors.Is(err, ErrExpiredToken) {
				t.Fatalf("expired token: err = %v, want ErrExpiredToken", err)
			}
		}
		if _, err := s.Verify(purpose, tok, exp.Add(time.Second)); err == nil {
			t.Fatal("token verified after its expiry")
		}
		if _, err := s.Verify(purpose+"x", tok, now); err == nil {
			t.Fatal("token verified for a different purpose")
		}
		if _, err := other.Verify(purpose, tok, now); err == nil {
			t.Fatal("token verified under a different key")
		}
	})
}

// FuzzSignerVerify: arbitrary strings handed to Verify (this is the cookie
// and form-field input) never panic, and are rejected unless they happen to
// be a token this signer produced.
func FuzzSignerVerify(f *testing.F) {
	s, err := NewSigner(testKey)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	good := s.Sign(PurposeSession, "session-id", now.Add(time.Minute))
	payload, mac, _ := strings.Cut(good, ".")
	for _, seed := range []string{good, "", ".", "a.b", payload, payload + ".", "." + mac,
		payload + "." + mac + "." + mac, strings.Repeat("A", maxTokenLength+1), "AQ.AQ", "\x00.\x00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, token string) {
		got, err := s.Verify(PurposeSession, token, now)
		if err == nil {
			// The only accepted tokens are ones this signer could have
			// issued, so re-signing the value must reproduce a token that
			// verifies identically.
			if _, err2 := s.Verify(PurposeSession, s.Sign(PurposeSession, got, now.Add(time.Minute)), now); err2 != nil {
				t.Fatalf("accepted %q but its value %q does not round-trip: %v", token, got, err2)
			}
			if token != good && !strings.Contains(token, ".") {
				t.Fatalf("accepted token without a separator: %q", token)
			}
			return
		}
		if !errors.Is(err, ErrInvalidToken) && !errors.Is(err, ErrExpiredToken) {
			t.Fatalf("unexpected error type: %v", err)
		}
		if got != "" {
			t.Fatalf("returned value %q alongside error %v", got, err)
		}
	})
}
