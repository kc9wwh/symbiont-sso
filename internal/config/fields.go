package config

import (
	"encoding/base64"
	"log/slog"
	"slices"
	"strings"
)

func (l *loader) scopes(key string) []string {
	raw := l.str(key, DefaultScopes)
	var out []string
	for _, s := range strings.Fields(raw) {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	if !slices.Contains(out, "openid") {
		l.problemf("%s must include the \"openid\" scope, got %q", key, raw)
	}
	return out
}

func (l *loader) claimName(key, def string) string {
	v := l.str(key, def)
	if strings.ContainsFunc(v, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		l.problemf("%s must be a claim name without whitespace or control characters, got %q", key, v)
	}
	return v
}

// validPrompts are the OIDC prompt values that make sense for an
// interactive bridge. "none" is rejected: it makes every login fail unless
// the user already has an IdP session, which is never what an operator wants.
var validPrompts = []string{"login", "consent", "select_account"}

func (l *loader) prompt(key string) string {
	raw, ok := l.get(key)
	if !ok {
		return ""
	}
	parts := strings.Fields(raw)
	for _, p := range parts {
		if !slices.Contains(validPrompts, p) {
			l.problemf("%s: unsupported value %q (allowed: %s)", key, p, strings.Join(validPrompts, ", "))
			return ""
		}
	}
	return strings.Join(parts, " ")
}

// domains parses a comma-separated, case-insensitive domain allowlist.
func (l *loader) domains(key string) []string {
	raw, ok := l.get(key)
	if !ok {
		return nil
	}
	before := len(l.problems)
	var out []string
	for _, d := range strings.Split(raw, ",") {
		d = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "@"))
		if d == "" {
			continue
		}
		if !isDomainName(d) {
			l.problemf("%s: %q is not a valid domain name (use punycode for internationalised domains)", key, d)
			continue
		}
		if !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	if len(out) == 0 && len(l.problems) == before {
		l.problemf("%s is set but contains no domains", key)
	}
	return out
}

// isDomainName performs a conservative syntactic check on a lower-case
// ASCII domain name.
func isDomainName(d string) bool {
	if len(d) > 253 {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

// sessionSecret decodes SESSION_SECRET (or SESSION_SECRET_FILE) as base64
// (standard or URL alphabet, padding optional) and enforces a minimum length.
func (l *loader) sessionSecret(key string) Secret {
	raw, src, ok := l.requiredRawSecret(key)
	if !ok {
		return Secret{}
	}
	decoded, err := decodeBase64(string(raw))
	if err != nil {
		l.problemf("%s must be base64-encoded (generate one with: openssl rand -base64 32)", src)
		return Secret{}
	}
	if len(decoded) < MinSessionSecretBytes {
		l.problemf("%s must decode to at least %d bytes, got %d (generate one with: openssl rand -base64 32)",
			src, MinSessionSecretBytes, len(decoded))
		return Secret{}
	}
	return NewSecret(decoded)
}

func decodeBase64(s string) ([]byte, error) {
	var lastErr error
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		b, err := enc.DecodeString(s)
		if err == nil {
			return b, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (l *loader) logLevel(key string) slog.Level {
	raw, ok := l.get(key)
	if !ok {
		return slog.LevelInfo
	}
	if strings.EqualFold(raw, "warning") {
		raw = "warn"
	}
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(raw)); err != nil {
		l.problemf("%s must be one of debug, info, warn, error; got %q", key, raw)
		return slog.LevelInfo
	}
	return lvl
}
