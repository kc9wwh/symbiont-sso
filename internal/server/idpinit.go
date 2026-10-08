package server

import (
	"encoding/base64"
	"net/http"
	"net/url"

	"github.com/kc9wwh/symbiont-sso/internal/session"
)

// LoginPathPrefix is the IdP-initiated login path prefix (/login/{sp_id}).
const LoginPathPrefix = "/login/"

// returnParam marks the redirect back from /oidc/callback. It carries a
// short-lived signed token naming the SP, so a request arriving without a
// session cookie can be recognised as "cookie dropped" instead of starting
// another upstream login (which would loop).
const returnParam = "return"

func loginPath(spID string) string { return LoginPathPrefix + spID }

func encodeStd(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// loginReturnURL is where the callback sends an IdP-initiated login.
func (s *Server) loginReturnURL(spID, relayState string) string {
	l := s.opts.Login
	q := url.Values{returnParam: {l.Signer.Sign(session.PurposeReplay, "login:"+spID, l.now().Add(replayTokenTTL))}}
	if relayState != "" {
		q.Set("RelayState", relayState)
	}
	return loginPath(spID) + "?" + q.Encode()
}

// handleLogin serves IdP-initiated SSO: GET /login/{sp_id}[?RelayState=].
// It shares the session lookup and the single enforcement point (issue)
// with /sso; only the request construction differs.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	spID := r.PathValue("sp_id")
	sp, ok := s.opts.IdP.SPs().ByID(spID)
	if !ok || !sp.IDPInitiatedEnabled {
		// Same response for unknown and disabled: no hint which.
		s.reqLog(r).DebugContext(r.Context(), "idp-initiated login not available", "flow", "idp", "requested_sp_id", truncate(spID, 64))
		s.errorPage(w, r, http.StatusNotFound, "Not found", "There is no sign-in link here.")
		return
	}
	log := s.reqLog(r, "flow", "idp", "sp_id", sp.ID, "sp_entity_id", sp.EntityID)

	req, err := s.opts.IdP.IdPInitiated(r, sp, r.URL.Query().Get("RelayState"))
	if err != nil {
		s.rejectSSO(w, r, err)
		return
	}
	if tok := r.URL.Query().Get(returnParam); tok != "" {
		v, err := s.opts.Login.Signer.Verify(session.PurposeReplay, tok, s.opts.Login.now())
		if err != nil || v != "login:"+sp.ID {
			log.WarnContext(r.Context(), "invalid login return token", "error_category", "replay_token_invalid")
			s.errorPage(w, r, http.StatusBadRequest, "Sign-in request rejected",
				"This sign-in link has expired. Please start again from your dashboard.")
			return
		}
		req.Replayed = true
	}
	identity := s.opts.Sessions.Identity(w, r, req)
	if identity == nil {
		return
	}
	s.issue(w, r, log, req, identity)
}
