package config

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// FuzzParseServiceProviders: the SP file is operator-supplied YAML that
// decides who may log in where. Any input must produce either a *Error or a
// set of providers that satisfy every invariant the rest of the program
// relies on. It must never panic or hang (alias bombs, deep nesting).
func FuzzParseServiceProviders(f *testing.F) {
	f.Add([]byte(amendmentExample))
	f.Add([]byte("service_providers: []\n"))
	f.Add([]byte(""))
	f.Add([]byte("service_providers:\n  - id: a\n    entity_id: x\n    acs_urls: [https://a.example.org/acs]\n    access: {allow_all: true}\n"))
	f.Add([]byte("service_providers:\n  - id: a\n    entity_id: x\n    acs_urls: [https://a.example.org/acs]\n    access: {allow_emails: [\" Bob@Example.ORG \", bob@example.org]}\n"))
	f.Add([]byte("service_providers:\n  - id: a\n    entity_id: x\n    acs_urls: [http://evil.example.org/acs]\n    access: {allow_all: true, allow_groups: [g]}\n"))
	f.Add([]byte("a: &a [x, x]\nb: &b [*a, *a]\nservice_providers: *b\n"))
	f.Add([]byte("---\nservice_providers: []\n---\nservice_providers: []\n"))
	f.Add([]byte("service_providers:\n  - {id: a, entity_id: x, acs_urls: [\"https://u:p@a.example.org/\"], access: {allow_all: true}}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxSPFileBytes {
			t.Skip("LoadServiceProviders rejects larger files before parsing")
		}
		sps, _, err := ParseServiceProviders(data)
		if err != nil {
			var cerr *Error
			if !errors.As(err, &cerr) || len(cerr.Problems) == 0 {
				t.Fatalf("error is %T (%v), want *Error with problems", err, err)
			}
			if sps != nil {
				t.Fatal("returned providers alongside an error")
			}
			return
		}
		if len(sps) == 0 {
			t.Fatal("accepted a file with no service providers")
		}
		ids, entities, acs := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for _, sp := range sps {
			if !spIDPattern.MatchString(sp.ID) || len(sp.ID) > maxSPIDLen || ids[sp.ID] {
				t.Fatalf("bad or duplicate id %q", sp.ID)
			}
			ids[sp.ID] = true
			if sp.EntityID == "" || strings.ContainsFunc(sp.EntityID, isSpaceOrControl) || entities[sp.EntityID] {
				t.Fatalf("bad or duplicate entity_id %q", sp.EntityID)
			}
			entities[sp.EntityID] = true
			if len(sp.ACSURLs) == 0 {
				t.Fatalf("%s has no ACS URLs", sp.ID)
			}
			for _, u := range sp.ACSURLs {
				if _, err := ParsePublicURL(u); err != nil {
					t.Fatalf("%s: accepted ACS URL %q: %v", sp.ID, u, err)
				}
				if acs[u] {
					t.Fatalf("ACS URL %q belongs to more than one service provider", u)
				}
				acs[u] = true
			}
			if sp.IDPInitiatedEnabled != (sp.IDPInitiatedACSURL != "") {
				t.Fatalf("%s: idp_initiated enabled=%v but acs_url=%q", sp.ID, sp.IDPInitiatedEnabled, sp.IDPInitiatedACSURL)
			}
			if sp.IDPInitiatedEnabled && !slices.Contains(sp.ACSURLs, sp.IDPInitiatedACSURL) {
				t.Fatalf("%s: idp_initiated ACS %q is not one of %v", sp.ID, sp.IDPInitiatedACSURL, sp.ACSURLs)
			}
			// Access is default-deny: something must be granted, and
			// allow_all never combines with lists.
			a := sp.Access
			hasLists := len(a.AllowGroups) > 0 || len(a.AllowEmails) > 0
			if a.AllowAll == hasLists {
				t.Fatalf("%s: inconsistent access policy %+v", sp.ID, a)
			}
			for _, e := range a.AllowEmails {
				if e != strings.ToLower(e) || strings.Count(e, "@") != 1 || strings.HasPrefix(e, "@") ||
					strings.HasSuffix(e, "@") || strings.ContainsFunc(e, isSpaceOrControl) {
					t.Fatalf("%s: bad allow_emails entry %q", sp.ID, e)
				}
			}
			for _, g := range a.AllowGroups {
				if g == "" || g != strings.TrimSpace(g) {
					t.Fatalf("%s: bad allow_groups entry %q", sp.ID, g)
				}
			}
		}
	})
}

func fuzzLoader(key, value string) *loader {
	return &loader{lookup: func(k string) (string, bool) {
		if k == key {
			return value, true
		}
		return "", false
	}}
}

// FuzzTrustedProxies: SYMBIONT_TRUSTED_PROXIES. Either a problem is
// recorded and nothing is returned, or every prefix is usable.
func FuzzTrustedProxies(f *testing.F) {
	for _, s := range []string{"", "10.0.0.0/8", "0.0.0.0/0, ::/0", "1.2.3.4,5.6.7.8", "fe80::1%x", "not-an-ip", ",,,", "10.0.0.0/8,"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		l := fuzzLoader(EnvTrustedProxies, s)
		ps := l.trustedProxies(EnvTrustedProxies)
		if len(l.problems) > 0 && ps != nil {
			t.Fatalf("returned %v despite problems %v", ps, l.problems)
		}
		for _, p := range ps {
			if !p.IsValid() || p != p.Masked() {
				t.Fatalf("bad prefix %v from %q", p, s)
			}
			if _, err := netip.ParsePrefix(p.String()); err != nil {
				t.Fatalf("prefix %v does not re-parse: %v", p, err)
			}
		}
		if _, ok := l.get(EnvTrustedProxies); ok && len(ps) == 0 && len(l.problems) == 0 {
			t.Fatalf("set value %q silently produced no proxies and no problem", s)
		}
	})
}

// FuzzDomains: SYMBIONT_ALLOWED_EMAIL_DOMAINS. Accepted entries are
// lower-case syntactically valid domain names, without duplicates.
func FuzzDomains(f *testing.F) {
	for _, s := range []string{"", "example.com", "@Example.COM, other.org", "a..b", "-a.com", "xn--bcher-kva.example", "b\u00fccher.example",
		",", "a.com,a.com", strings.Repeat("a", 64) + ".com", "exa mple.com"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		l := fuzzLoader(EnvAllowedEmailDomains, s)
		out := l.domains(EnvAllowedEmailDomains)
		if _, set := l.get(EnvAllowedEmailDomains); set && len(out) == 0 && len(l.problems) == 0 {
			t.Fatalf("set value %q silently produced no domains and no problem", s)
		}
		seen := map[string]bool{}
		for _, d := range out {
			if d != strings.ToLower(d) || !isDomainName(d) || seen[d] {
				t.Fatalf("bad or duplicate domain %q from %q", d, s)
			}
			seen[d] = true
		}
	})
}
