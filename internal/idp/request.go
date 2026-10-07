package idp

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"

	"github.com/crewjam/saml"
)

// MaxRequestBytes bounds both the raw /sso request (POST body or query
// string) and the decoded AuthnRequest XML. Real AuthnRequests are ~1-2 KB.
const MaxRequestBytes = 64 << 10

// MaxRelayStateBytes is the SAML bindings limit on RelayState.
const MaxRelayStateBytes = 80

// Request error categories (used in logs; never shown verbatim to users).
const (
	CategoryTooLarge      = "request_too_large"
	CategoryMalformed     = "malformed_request"
	CategoryRelayState    = "invalid_relay_state"
	CategoryUnknownSP     = "unknown_service_provider"
	CategoryACSNotAllowed = "acs_not_allowed"
	CategoryInvalid       = "invalid_request"
)

// RequestError describes why an AuthnRequest was rejected.
type RequestError struct {
	Category string
	// EntityID is the claimed issuer, when known (for logging).
	EntityID string
	Err      error
}

func (e *RequestError) Error() string { return e.Category + ": " + e.Err.Error() }
func (e *RequestError) Unwrap() error { return e.Err }

func reqErr(category string, err error) *RequestError {
	return &RequestError{Category: category, Err: err}
}

// ValidRelayState reports whether s is acceptable as RelayState: at most 80
// bytes of printable ASCII. RelayState is opaque to the bridge and is only
// ever echoed back to the SP; it is never used as a redirect target.
func ValidRelayState(s string) bool {
	if len(s) > MaxRelayStateBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// decodeRequest extracts the raw AuthnRequest XML and RelayState from an
// HTTP-Redirect (GET) or HTTP-POST request, enforcing size limits before any
// XML parsing. POST bodies must already be wrapped in http.MaxBytesReader.
func decodeRequest(r *http.Request) (xmlBuf []byte, relayState string, err error) {
	var encoded string
	switch r.Method {
	case http.MethodGet:
		if len(r.URL.RawQuery) > MaxRequestBytes {
			return nil, "", reqErr(CategoryTooLarge, fmt.Errorf("query string exceeds %d bytes", MaxRequestBytes))
		}
		q := r.URL.Query()
		encoded, relayState = q.Get("SAMLRequest"), q.Get("RelayState")
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				return nil, "", reqErr(CategoryTooLarge, fmt.Errorf("body exceeds %d bytes", mbe.Limit))
			}
			return nil, "", reqErr(CategoryMalformed, fmt.Errorf("cannot parse form: %w", err))
		}
		encoded, relayState = r.PostForm.Get("SAMLRequest"), r.PostForm.Get("RelayState")
	default:
		return nil, "", reqErr(CategoryMalformed, fmt.Errorf("method %s not allowed", r.Method))
	}
	if encoded == "" {
		return nil, "", reqErr(CategoryMalformed, errors.New("missing SAMLRequest parameter"))
	}
	if !ValidRelayState(relayState) {
		return nil, "", reqErr(CategoryRelayState, fmt.Errorf("RelayState must be at most %d bytes of printable ASCII", MaxRelayStateBytes))
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, "", reqErr(CategoryMalformed, errors.New("SAMLRequest is not valid base64"))
	}
	if r.Method == http.MethodPost {
		xmlBuf = raw
	} else {
		// HTTP-Redirect binding: DEFLATE-compressed. Bound the inflated size
		// to defeat compression bombs.
		xmlBuf, err = io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(raw)), MaxRequestBytes+1))
		if err != nil {
			return nil, "", reqErr(CategoryMalformed, errors.New("SAMLRequest is not valid DEFLATE data"))
		}
	}
	if len(xmlBuf) > MaxRequestBytes {
		return nil, "", reqErr(CategoryTooLarge, fmt.Errorf("decoded AuthnRequest exceeds %d bytes", MaxRequestBytes))
	}
	return xmlBuf, relayState, nil
}

// preflight parses the (size-bounded) AuthnRequest just enough to reject
// inputs crewjam mishandles (a missing Issuer panics in
// IdpAuthnRequest.Validate) and to classify unknown-SP and unlisted-ACS
// errors precisely. crewjam's Validate then performs the full checks,
// including XML round-trip validation.
func (p *IdP) preflight(xmlBuf []byte) (*saml.AuthnRequest, error) {
	var ar saml.AuthnRequest
	if err := xml.Unmarshal(xmlBuf, &ar); err != nil {
		return nil, reqErr(CategoryMalformed, fmt.Errorf("cannot parse AuthnRequest XML: %w", err))
	}
	if ar.Issuer == nil || ar.Issuer.Value == "" {
		return nil, reqErr(CategoryMalformed, errors.New("AuthnRequest has no Issuer"))
	}
	sp, ok := p.sps.ByEntityID(ar.Issuer.Value)
	if !ok {
		return nil, &RequestError{Category: CategoryUnknownSP, EntityID: ar.Issuer.Value,
			Err: fmt.Errorf("no service provider with entity_id %q", ar.Issuer.Value)}
	}
	if u := ar.AssertionConsumerServiceURL; u != "" && !slices.Contains(sp.ACSURLs, u) {
		return nil, &RequestError{Category: CategoryACSNotAllowed, EntityID: sp.EntityID,
			Err: fmt.Errorf("AssertionConsumerServiceURL %q is not configured for service provider %q", u, sp.ID)}
	}
	if idx := ar.AssertionConsumerServiceIndex; idx != "" && ar.AssertionConsumerServiceURL == "" {
		if n, err := strconv.Atoi(idx); err != nil || n < 0 || n >= len(sp.ACSURLs) {
			return nil, &RequestError{Category: CategoryACSNotAllowed, EntityID: sp.EntityID,
				Err: fmt.Errorf("AssertionConsumerServiceIndex %q is not configured for service provider %q", idx, sp.ID)}
		}
	}
	return &ar, nil
}
