package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strconv"
	"strings"
	"time"

	"github.com/kc9wwh/symbiont-sso/internal/session"
)

// After the upstream login, the stored AuthnRequest is replayed to /sso by
// an auto-submitting form. crewjam rejects AuthnRequests whose IssueInstant
// is more than MaxIssueDelay (90s) old, which a passkey prompt easily
// exceeds, so the replay carries a signed token binding the request bytes
// to the time the bridge first received them. Validity is then judged at
// that time. Only requests that completed a real login get such a token.
const (
	replayField    = "SymbiontReplay"
	replayTokenTTL = 5 * time.Minute
)

func replayDigest(xml []byte) string {
	sum := sha256.Sum256(xml)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func replayToken(s *session.Signer, xml []byte, receivedAt, now time.Time) string {
	v := strconv.FormatInt(receivedAt.UnixNano(), 10) + "." + replayDigest(xml)
	return s.Sign(session.PurposeReplay, v, now.Add(replayTokenTTL))
}

// verifyReplay returns the original receipt time if token is a valid replay
// token for exactly these request bytes.
func verifyReplay(s *session.Signer, token string, xml []byte, now time.Time) (time.Time, bool) {
	v, err := s.Verify(session.PurposeReplay, token, now)
	if err != nil {
		return time.Time{}, false
	}
	ts, digest, ok := strings.Cut(v, ".")
	if !ok || subtle.ConstantTimeCompare([]byte(digest), []byte(replayDigest(xml))) != 1 {
		return time.Time{}, false
	}
	n, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, n).UTC(), true
}
