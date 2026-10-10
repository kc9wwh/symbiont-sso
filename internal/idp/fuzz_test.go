package idp

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// The AuthnRequest is attacker-controlled input to an unauthenticated
// endpoint. Whatever bytes arrive, the parser must either accept the request
// or return a *RequestError. It must never panic (crewjam panics on a
// missing Issuer, which preflight exists to prevent).

func FuzzValidRelayState(f *testing.F) {
	for _, s := range []string{"", "abc", strings.Repeat("a", MaxRelayStateBytes), strings.Repeat("a", MaxRelayStateBytes+1),
		"has space", "tab\t", "nul\x00", "del\x7f", "caf\u00e9", "https://evil.example.com/x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := ValidRelayState(s)
		// Independent restatement of the documented rule.
		want := len(s) <= MaxRelayStateBytes
		for i := 0; i < len(s) && want; i++ {
			want = s[i] >= 0x20 && s[i] <= 0x7e
		}
		if got != want {
			t.Fatalf("ValidRelayState(%q) = %v, want %v", s, got, want)
		}
		if got && !utf8.ValidString(s) {
			t.Fatalf("accepted non-UTF-8 RelayState %q", s)
		}
	})
}

// checkRequestError fails unless err is nil or a *RequestError with a
// category and a message.
func checkRequestError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	var re *RequestError
	if !errors.As(err, &re) {
		t.Fatalf("error is %T (%v), want *RequestError", err, err)
	}
	if re.Category == "" || re.Err == nil {
		t.Fatalf("incomplete RequestError: %+v", re)
	}
}

func FuzzPreflight(f *testing.F) {
	p := newTestIdP(f)
	f.Add([]byte(authnXML(adminEntityID, adminACS, "")))
	f.Add([]byte(authnXML(adminEntityID, "", ` AssertionConsumerServiceIndex="1"`)))
	f.Add([]byte(authnXML(adminEntityID, "", ` AssertionConsumerServiceIndex="-1"`)))
	f.Add([]byte(authnXML("", adminACS, "")))
	f.Add([]byte(authnXML("unknown.example.com", adminACS, "")))
	f.Add([]byte(authnXML(mdmEntityID, "https://evil.example.com/acs", "")))
	f.Add([]byte(`<AuthnRequest/>`))
	f.Add([]byte(`<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><AuthnRequest>&a;</AuthnRequest>`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxRequestBytes {
			t.Skip("callers enforce MaxRequestBytes before preflight")
		}
		ar, err := p.preflight(data)
		checkRequestError(t, err)
		if err == nil && (ar == nil || ar.Issuer == nil || ar.Issuer.Value == "") {
			t.Fatalf("preflight accepted a request without an Issuer: %+v", ar)
		}
	})
}

func FuzzParseXML(f *testing.F) {
	p := newTestIdP(f)
	f.Add([]byte(authnXML(adminEntityID, adminACS, "")), "")
	f.Add([]byte(authnXML(adminEntityID, "", "")), "state-1")
	f.Add([]byte(authnXML(mdmEntityID, mdmACS, ` ForceAuthn="true"`)), "")
	f.Add([]byte(authnXML("", "", "")), "")
	f.Add([]byte(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`), "x")
	f.Fuzz(func(t *testing.T, data []byte, relayState string) {
		if len(data) > MaxRequestBytes {
			t.Skip("callers enforce MaxRequestBytes before ParseXML")
		}
		r := httptest.NewRequest(http.MethodGet, testBase+SSOPath, nil)
		ar, err := p.ParseXML(r, data, relayState, time.Now())
		checkRequestError(t, err)
		if err != nil {
			return
		}
		if ar.SP == nil || ar.ACSURL() == "" || !ValidRelayState(ar.RelayState) {
			t.Fatalf("accepted request is incomplete: sp=%v acs=%q relay=%q", ar.SP, ar.ACSURL(), ar.RelayState)
		}
		// An accepted request may only ever be answered at an ACS URL the
		// operator configured for that service provider.
		allowed := false
		for _, u := range ar.SP.ACSURLs {
			allowed = allowed || u == ar.ACSURL()
		}
		if !allowed {
			t.Fatalf("ACS %q is not configured for %q (%v)", ar.ACSURL(), ar.SP.ID, ar.SP.ACSURLs)
		}
	})
}

func deflate(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// FuzzDecodeRequest drives the HTTP-Redirect (GET) and HTTP-POST decoders
// with arbitrary parameter values. Whatever the input, output is bounded by
// MaxRequestBytes and the RelayState rule holds.
func FuzzDecodeRequest(f *testing.F) {
	valid := authnXML(adminEntityID, adminACS, "")
	f.Add(base64.StdEncoding.EncodeToString(deflate(f, []byte(valid))), "rs", true)
	f.Add(base64.StdEncoding.EncodeToString([]byte(valid)), "rs", false)
	f.Add("", "", true)
	f.Add("!!!not-base64!!!", "", false)
	f.Add(base64.StdEncoding.EncodeToString(deflate(f, bytes.Repeat([]byte("A"), MaxRequestBytes+10))), "", true)
	f.Add(base64.StdEncoding.EncodeToString([]byte("garbage")), "caf\u00e9", true)
	f.Fuzz(func(t *testing.T, samlRequest, relayState string, get bool) {
		var r *http.Request
		if get {
			q := url.Values{"SAMLRequest": {samlRequest}, "RelayState": {relayState}}
			r = httptest.NewRequest(http.MethodGet, testBase+SSOPath+"?"+q.Encode(), nil)
		} else {
			r = rawPostRequest(samlRequest, relayState)
			r.Body = http.MaxBytesReader(httptest.NewRecorder(), r.Body, MaxRequestBytes)
		}
		xmlBuf, rs, err := DecodeRequest(r)
		checkRequestError(t, err)
		if err != nil {
			return
		}
		if len(xmlBuf) > MaxRequestBytes {
			t.Fatalf("decoded %d bytes, limit is %d", len(xmlBuf), MaxRequestBytes)
		}
		if !ValidRelayState(rs) {
			t.Fatalf("returned invalid RelayState %q", rs)
		}
	})
}
