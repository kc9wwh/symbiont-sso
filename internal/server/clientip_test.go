package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kc9wwh/symbiont-sso/internal/clientip"
)

func logLines(t *testing.T, s string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("bad log line %q: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

func TestAccessLogClientIP(t *testing.T) {
	trusted, _ := clientip.ParsePrefixes("172.16.0.0/12")
	tests := []struct {
		name     string
		resolver *clientip.Resolver
		remote   string
		want     string // "" = no client_ip attribute
	}{
		{"no trusted proxies configured", nil, "172.18.0.5:1234", ""},
		{"trusted peer", clientip.New(trusted), "172.18.0.5:1234", "203.0.113.9"},
		{"untrusted peer: spoofed header ignored", clientip.New(trusted), "198.51.100.7:1234", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, logs := newTestServer(t, 0)
			s.opts.ClientIP = tc.resolver
			r := httptest.NewRequest(http.MethodGet, "/nope", nil)
			r.RemoteAddr = tc.remote
			r.Header.Set("CF-Connecting-IP", "203.0.113.9")
			s.Handler().ServeHTTP(httptest.NewRecorder(), r)

			lines := logLines(t, logs.String())
			entry := lines[len(lines)-1]
			if entry["remote_addr"] != tc.remote {
				t.Errorf("remote_addr = %v, want socket peer %q", entry["remote_addr"], tc.remote)
			}
			got, has := entry["client_ip"]
			if tc.want == "" && has {
				t.Errorf("client_ip = %v, want absent", got)
			}
			if tc.want != "" && got != tc.want {
				t.Errorf("client_ip = %v, want %q", got, tc.want)
			}
		})
	}
}

// Auth events (here: an SSO rejection) carry client_ip too.
func TestAuthEventLogsClientIP(t *testing.T) {
	trusted, _ := clientip.ParsePrefixes("10.0.0.0/8")
	f := newSAMLFixture(t, fixedSessions{testUser()})
	f.srv.opts.ClientIP = clientip.New(trusted)
	r := httptest.NewRequest(http.MethodGet, base+"/sso", nil) // missing SAMLRequest
	r.RemoteAddr = "10.0.0.2:5555"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.50")
	f.do(r)
	for _, e := range logLines(t, f.logs.String()) {
		if e["msg"] == "sso request rejected" {
			if e["client_ip"] != "203.0.113.50" {
				t.Errorf("client_ip = %v", e["client_ip"])
			}
			return
		}
	}
	t.Fatalf("no rejection logged:\n%s", f.logs.String())
}
