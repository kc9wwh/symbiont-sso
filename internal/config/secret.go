package config

import (
	"fmt"
	"io"
	"log/slog"
	"slices"
)

const redacted = "[REDACTED]"

// Secret holds sensitive bytes (client secrets, HMAC keys). It refuses to
// render its contents through fmt, slog, or text/JSON marshalling, so a
// Config can be logged or printed without leaking credentials.
type Secret struct {
	value []byte
}

// NewSecret wraps b. The slice is copied.
func NewSecret(b []byte) Secret { return Secret{value: slices.Clone(b)} }

// Bytes returns a copy of the secret value.
func (s Secret) Bytes() []byte { return slices.Clone(s.value) }

// Len reports the secret length in bytes.
func (s Secret) Len() int { return len(s.value) }

// IsZero reports whether the secret is empty.
func (s Secret) IsZero() bool { return len(s.value) == 0 }

// String implements fmt.Stringer and never reveals the value.
func (s Secret) String() string { return redacted }

// GoString implements fmt.GoStringer and never reveals the value.
func (s Secret) GoString() string { return redacted }

// Format implements fmt.Formatter so that every verb (%v, %x, %d, %#v, ...)
// is redacted.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// LogValue implements slog.LogValuer.
func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalText implements encoding.TextMarshaler (also used by encoding/json).
func (s Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }
