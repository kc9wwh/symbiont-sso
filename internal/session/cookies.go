package session

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"
)

// Cookies names and writes symbiont's cookies. All cookies are HttpOnly,
// SameSite=Lax, Path=/ and host-only (no Domain). With Secure (https
// deployments) names carry the __Host- prefix, which makes browsers enforce
// Secure, Path=/ and host-only.
type Cookies struct {
	secure bool
	prefix string
}

// NewCookies returns cookie settings; secure should be true unless the
// bridge is served over plain http on localhost.
func NewCookies(secure bool) Cookies {
	c := Cookies{secure: secure, prefix: "symbiont_"}
	if secure {
		c.prefix = "__Host-symbiont_"
	}
	return c
}

// Secure reports whether cookies carry the Secure attribute.
func (c Cookies) Secure() bool { return c.secure }

// SessionName is the bridge session cookie name.
func (c Cookies) SessionName() string { return c.prefix + "session" }

// StateName is the state-binding cookie name for one pending login. Each
// login gets its own cookie so concurrent logins (e.g. two tabs) do not
// clobber each other.
func (c Cookies) StateName(state string) string {
	sum := sha256.Sum256([]byte(state))
	return c.prefix + "state_" + hex.EncodeToString(sum[:8])
}

// Set writes a cookie expiring at expires.
func (c Cookies) Set(w http.ResponseWriter, name, value string, now, expires time.Time) {
	maxAge := int(expires.Sub(now).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	// Secure is false only for an http://localhost base URL (config rejects
	// plain http elsewhere); HttpOnly and SameSite are always set.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure follows the base URL scheme, see above
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  expires.UTC(),
		MaxAge:   maxAge,
		Secure:   c.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// Clear deletes a cookie.
func (c Cookies) Clear(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: same attributes as Set
		Name:     name,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   c.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
