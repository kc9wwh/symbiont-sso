package server

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kc9wwh/symbiont-sso/internal/oidcrp"
	"github.com/kc9wwh/symbiont-sso/internal/session"
)

// CallbackPath is the OIDC redirect URI path.
const CallbackPath = "/oidc/callback"

const maxStateLen = 128

// Callback failure categories (logged; users see generic text).
const (
	catIdPError      = "idp_error"
	catMissingParams = "missing_code_or_state"
	catStateCookie   = "state_cookie_mismatch"
	catStateUnknown  = "state_unknown_or_expired"
	catSessionStore  = "session_store_failed"
	catReplayPending = "pending_request_invalid"
	catSPGone        = "service_provider_unknown"
	catUnknownKind   = "pending_kind_unknown"
	// catReauthNotPerformed: the SP demanded fresh authentication and the
	// provider did not prove it.
	catReauthNotPerformed = "reauthentication_not_performed"
	msgTryAgain           = "Please return to the application and sign in again."
	titleSignInFailed     = "Sign-in failed"
)

// handleCallback completes the upstream OIDC login. Only global checks
// (email presence, verification, domain allowlist) happen here; per-SP
// access policy is enforced when an assertion is issued.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	l := s.opts.Login
	q := r.URL.Query()
	state := q.Get("state")
	if state == "" || len(state) > maxStateLen {
		s.callbackFail(w, r, s.reqLog(r), catMissingParams, nil, http.StatusBadRequest)
		return
	}
	stateCookie := l.Cookies.StateName(state)
	l.Cookies.Clear(w, stateCookie)
	if !s.stateBoundToBrowser(r, stateCookie, state) {
		// Leave the pending entry alone: a forged callback must not be able
		// to cancel the real user's login.
		log := s.reqLog(r)
		if want := s.publicHost(); want != "" && !strings.EqualFold(r.Host, want) {
			// Cookies are host-only: a login started on another hostname
			// cannot complete here. Common misconfiguration; say so.
			log = log.With("hint", "the login was likely started via a different hostname than SYMBIONT_BASE_URL; "+
				"users must reach the bridge only at that URL", "request_host", r.Host, "base_url_host", want)
		}
		s.callbackFail(w, r, log, catStateCookie, nil, http.StatusBadRequest)
		return
	}
	// Consume the state before anything else so every outcome (including
	// IdP errors) makes it single-use.
	p, err := l.Pending.Take(r.Context(), state)
	if err != nil {
		s.callbackFail(w, r, s.reqLog(r), catStateUnknown, nil, http.StatusBadRequest)
		return
	}
	log := s.reqLog(r, "flow", string(p.Kind), "sp_id", p.SPID)

	if e := q.Get("error"); e != "" {
		log.WarnContext(r.Context(), "identity provider returned an error",
			"error_category", catIdPError, "idp_error", truncate(e, 64),
			"idp_error_description", truncate(q.Get("error_description"), 256))
		s.errorPage(w, r, http.StatusForbidden, titleSignInFailed,
			"The identity provider did not complete the sign-in. "+msgTryAgain)
		return
	}
	code := q.Get("code")
	if code == "" {
		s.callbackFail(w, r, log, catMissingParams, nil, http.StatusBadRequest)
		return
	}

	res, err := l.OIDC.Exchange(r.Context(), code, p.PKCEVerifier, p.Nonce)
	if err != nil {
		s.callbackFail(w, r, log, categoryOf(err), err, http.StatusBadGateway)
		return
	}
	ident, err := oidcrp.ExtractIdentity(res, l.Claims, l.Policy)
	if err != nil {
		s.identityFail(w, r, log, err)
		return
	}

	if p.ForceLogin && !reauthenticated(ident.AuthTime, p.CreatedAt) {
		s.callbackFail(w, r, log, catReauthNotPerformed,
			fmt.Errorf("auth_time %v is missing or older than the login request at %v", ident.AuthTime, p.CreatedAt),
			http.StatusForbidden)
		return
	}

	now := l.now()
	sess := session.Session{
		ID: session.NewID(), Subject: ident.Subject, Email: ident.Email, Name: ident.Name,
		Groups: ident.Groups, Claims: ident.Claims, AuthTime: ident.AuthTime,
		IssuedAt: now, ExpiresAt: now.Add(l.SessionTTL),
	}
	if err := l.Sessions.Create(r.Context(), sess); err != nil {
		s.callbackFail(w, r, log, catSessionStore, err, http.StatusServiceUnavailable)
		return
	}
	token := l.Signer.Sign(session.PurposeSession, sess.ID, sess.ExpiresAt)
	l.Cookies.Set(w, l.Cookies.SessionName(), token, now, sess.ExpiresAt)
	log.InfoContext(r.Context(), "upstream login succeeded", "sub", sess.Subject)

	s.resume(w, r, log, p)
}

// publicHost is the host[:port] of SYMBIONT_BASE_URL.
func (s *Server) publicHost() string {
	u, err := url.Parse(s.opts.IdP.SSOURL())
	if err != nil {
		return ""
	}
	return u.Host
}

// stateBoundToBrowser checks the signed state-binding cookie for state.
func (s *Server) stateBoundToBrowser(r *http.Request, cookieName, state string) bool {
	l := s.opts.Login
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	v, err := l.Signer.Verify(session.PurposeState, c.Value, l.now())
	return err == nil && subtle.ConstantTimeCompare([]byte(v), []byte(state)) == 1
}

// reauthSkew is the clock difference tolerated between the bridge and the
// identity provider when judging whether a login was fresh.
const reauthSkew = 60 * time.Second

// reauthenticated reports whether authTime proves the user authenticated
// after the login request began (allowing for clock skew). A missing
// auth_time proves nothing.
func reauthenticated(authTime, requested time.Time) bool {
	return !authTime.IsZero() && !authTime.Before(requested.Add(-reauthSkew))
}
