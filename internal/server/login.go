package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/kc9wwh/symbiont-sso/internal/idp"
	"github.com/kc9wwh/symbiont-sso/internal/oidcrp"
	"github.com/kc9wwh/symbiont-sso/internal/session"
)

// OIDCClient is the upstream relying party (implemented by *oidcrp.Client).
type OIDCClient interface {
	AuthCodeURL(state, nonce, verifier string) string
	Exchange(ctx context.Context, code, verifier, nonce string) (*oidcrp.Result, error)
}

// Login wires the upstream OIDC login into the SAML flows. All fields
// except Now are required.
type Login struct {
	OIDC       OIDCClient
	Pending    session.PendingStore
	Sessions   session.SessionStore
	Signer     *session.Signer
	Cookies    session.Cookies
	Claims     oidcrp.ClaimNames
	Policy     oidcrp.Policy
	SessionTTL time.Duration
	PendingTTL time.Duration
	Now        func() time.Time
}

func (l *Login) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

func (l *Login) validate() error {
	if l.OIDC == nil || l.Pending == nil || l.Sessions == nil || l.Signer == nil ||
		l.SessionTTL <= 0 || l.PendingTTL <= 0 {
		return errors.New("server: Login requires OIDC, Pending, Sessions, Signer, SessionTTL and PendingTTL")
	}
	return nil
}

// Reasons a session cookie did not yield a session (debug logging).
const (
	sessionNone     = "no_cookie"
	sessionInvalid  = "cookie_invalid"
	sessionExpired  = "cookie_expired"
	sessionNotFound = "session_not_found"
)

// currentSession resolves the bridge session from the session cookie.
func (s *Server) currentSession(r *http.Request) (*session.Session, string) {
	l := s.opts.Login
	c, err := r.Cookie(l.Cookies.SessionName())
	if err != nil {
		return nil, sessionNone
	}
	id, err := l.Signer.Verify(session.PurposeSession, c.Value, l.now())
	switch {
	case errors.Is(err, session.ErrExpiredToken):
		return nil, sessionExpired
	case err != nil:
		return nil, sessionInvalid
	}
	sess, err := l.Sessions.Get(r.Context(), id)
	if err != nil {
		return nil, sessionNotFound // expired server-side or evicted
	}
	return &sess, ""
}

func identityFromSession(sess *session.Session) *idp.Identity {
	return &idp.Identity{
		SessionID: sess.ID,
		Subject:   sess.Subject,
		Email:     sess.Email,
		Name:      sess.Name,
		Groups:    sess.Groups,
		Claims:    sess.Claims,
		AuthTime:  sess.AuthTime,
	}
}

// oidcSessions implements Sessions using the bridge session cookie and the
// upstream OIDC login.
type oidcSessions struct{ s *Server }

func (o oidcSessions) Identity(w http.ResponseWriter, r *http.Request, req *idp.AuthnRequest) *idp.Identity {
	s := o.s
	log := s.log.With("flow", string(session.KindSP), "sp_id", req.SP.ID)
	sess, reason := s.currentSession(r)
	if sess != nil {
		return identityFromSession(sess)
	}
	if req.Replayed {
		// We just completed a login and set the session cookie, but the
		// browser did not send it back. Starting another login would loop.
		log.WarnContext(r.Context(), "session cookie missing on replay",
			"error_category", "session_cookie_missing", "reason", reason)
		s.errorPage(w, r, http.StatusBadRequest, "Sign-in could not be completed",
			"Your browser did not keep the sign-in cookie. Make sure cookies are enabled for this site, then try again.")
		return nil
	}
	if reason != sessionNone {
		log.DebugContext(r.Context(), "session cookie not usable", "reason", reason)
	}
	s.startLogin(w, r, session.Pending{
		Kind:       session.KindSP,
		SPID:       req.SP.ID,
		RawRequest: req.RawXML,
		RelayState: req.RelayState,
		ReceivedAt: req.ReceivedAt,
	})
	return nil
}

// startLogin records a pending login, binds its state to this browser with
// a signed cookie, and redirects to the identity provider.
func (s *Server) startLogin(w http.ResponseWriter, r *http.Request, p session.Pending) {
	l := s.opts.Login
	state, nonce, verifier := session.NewID(), session.NewID(), oidcrp.NewVerifier()
	now := l.now()
	p.PKCEVerifier, p.Nonce, p.CreatedAt = verifier, nonce, now
	log := s.log.With("flow", string(p.Kind), "sp_id", p.SPID)

	if err := l.Pending.Put(r.Context(), state, p); err != nil {
		log.ErrorContext(r.Context(), "store pending login", "error", err)
		s.errorPage(w, r, http.StatusServiceUnavailable, "Sign-in unavailable",
			"Sign-in is temporarily unavailable. Please try again.")
		return
	}
	expires := now.Add(l.PendingTTL)
	l.Cookies.Set(w, l.Cookies.StateName(state), l.Signer.Sign(session.PurposeState, state, expires), now, expires)
	log.InfoContext(r.Context(), "redirecting to identity provider")
	http.Redirect(w, r, l.OIDC.AuthCodeURL(state, nonce, verifier), http.StatusFound)
}
