package session

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCookies(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	secure := NewCookies(true)
	if secure.SessionName() != "__Host-symbiont_session" {
		t.Errorf("SessionName = %q", secure.SessionName())
	}
	a, b := secure.StateName("state-a"), secure.StateName("state-b")
	if a == b || !strings.HasPrefix(a, "__Host-symbiont_state_") || strings.Contains(a, "state-a") {
		t.Errorf("StateName = %q / %q", a, b)
	}
	if a == secure.SessionName() {
		t.Error("state and session cookies must have distinct names")
	}

	rec := httptest.NewRecorder()
	secure.Set(rec, secure.SessionName(), "v", now, now.Add(time.Minute))
	c := rec.Result().Cookies()[0]
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" || c.MaxAge != 60 {
		t.Errorf("cookie attributes = %+v", c)
	}

	rec = httptest.NewRecorder()
	secure.Clear(rec, "x")
	if c := rec.Result().Cookies()[0]; c.MaxAge != -1 || !c.Secure {
		t.Errorf("clear = %+v", c)
	}

	plain := NewCookies(false)
	if plain.SessionName() != "symbiont_session" || plain.Secure() {
		t.Errorf("insecure cookie name must not use __Host- prefix: %q", plain.SessionName())
	}
	rec = httptest.NewRecorder()
	plain.Set(rec, "n", "v", now, now) // expiry already reached still yields MaxAge >= 1
	if c := rec.Result().Cookies()[0]; c.Secure || c.MaxAge != 1 {
		t.Errorf("plain cookie = %+v", c)
	}
}
