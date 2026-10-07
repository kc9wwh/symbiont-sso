package server

import (
	"errors"
	"net/http"

	"github.com/kc9wwh/symbiont-sso/internal/idp"
	"github.com/kc9wwh/symbiont-sso/internal/web"
)

// Sessions resolves the authenticated identity for an SSO request, SP- or
// IdP-initiated (req.IDPInitiated).
//
// Identity returns the user's identity, or nil after it has fully handled
// the response itself (typically a redirect to the upstream OIDC login).
// It performs authentication only; authorization happens in Server.issue.
type Sessions interface {
	Identity(w http.ResponseWriter, r *http.Request, req *idp.AuthnRequest) *idp.Identity
}

// handleMetadata serves the IdP metadata document.
func (s *Server) handleMetadata(w http.ResponseWriter, r *http.Request) {
	b, err := s.opts.IdP.MetadataXML()
	if err != nil {
		s.log.ErrorContext(r.Context(), "render metadata", "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(b)
}

// handleSSO serves SP-initiated SSO for both the HTTP-Redirect (GET) and
// HTTP-POST bindings, plus the bridge's own post-login replay (POST with a
// signed replay token).
func (s *Server) handleSSO(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, idp.MaxRequestBytes)
	}
	xmlBuf, relayState, err := idp.DecodeRequest(r)
	if err != nil {
		s.rejectSSO(w, r, err)
		return
	}
	receivedAt, replayed := s.opts.IdP.Now(), false
	if tok := r.PostFormValue(replayField); tok != "" && s.opts.Login != nil {
		t, ok := verifyReplay(s.opts.Login.Signer, tok, xmlBuf, s.opts.Login.now())
		if !ok {
			s.log.WarnContext(r.Context(), "invalid replay token", "flow", "sp", "error_category", "replay_token_invalid")
			s.errorPage(w, r, http.StatusBadRequest, "Sign-in request rejected",
				"This sign-in link has expired. Please return to the application and sign in again.")
			return
		}
		receivedAt, replayed = t, true
	}
	req, err := s.opts.IdP.ParseXML(r, xmlBuf, relayState, receivedAt)
	if err != nil {
		s.rejectSSO(w, r, err)
		return
	}
	req.Replayed = replayed
	log := s.log.With("flow", "sp", "sp_id", req.SP.ID, "sp_entity_id", req.SP.EntityID)

	if s.opts.Sessions == nil {
		log.ErrorContext(r.Context(), "sso request valid but no session backend is configured")
		s.errorPage(w, r, http.StatusServiceUnavailable, "Sign-in unavailable",
			"Sign-in is not available right now. Please try again later.")
		return
	}
	identity := s.opts.Sessions.Identity(w, r, req)
	if identity == nil {
		return // Sessions wrote the response (e.g. redirect to the IdP)
	}
	s.issue(w, r, log, req, identity)
}

// rejectSSO logs a request validation failure in detail and shows a generic
// error page. AuthnRequest content is never echoed to the user.
func (s *Server) rejectSSO(w http.ResponseWriter, r *http.Request, err error) {
	var re *idp.RequestError
	if !errors.As(err, &re) {
		re = &idp.RequestError{Category: idp.CategoryInvalid, Err: err}
	}
	attrs := []any{"flow", "sp", "error_category", re.Category, "error", re.Err.Error()}
	if re.EntityID != "" {
		attrs = append(attrs, "sp_entity_id", re.EntityID)
		if sp, ok := s.opts.IdP.SPs().ByEntityID(re.EntityID); ok {
			attrs = append(attrs, "sp_id", sp.ID)
		}
	}
	s.log.WarnContext(r.Context(), "sso request rejected", attrs...)

	status, msg := http.StatusBadRequest, "The sign-in request from the application was invalid."
	switch re.Category {
	case idp.CategoryTooLarge:
		status = http.StatusRequestEntityTooLarge
	case idp.CategoryUnknownSP:
		msg = "The application that sent you here is not configured for sign-in. Contact your administrator."
	case idp.CategoryACSNotAllowed:
		msg = "The application asked to return to an address that is not configured. Contact your administrator."
	}
	s.errorPage(w, r, status, "Sign-in request rejected", msg)
}

func (s *Server) errorPage(w http.ResponseWriter, r *http.Request, status int, title, msg string) {
	web.WriteError(w, web.ErrorPage{Status: status, Title: title, Message: msg, RequestID: RequestID(r.Context())})
}
