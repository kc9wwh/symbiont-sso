package server

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/kc9wwh/symbiont-sso/internal/idp"
	"github.com/kc9wwh/symbiont-sso/internal/web"
)

// Sessions resolves the authenticated identity for an SSO request.
//
// Identity returns the user's identity, or nil after it has fully handled
// the response itself (typically a redirect to the upstream OIDC login).
// Phase 2 uses a fixed test identity; phase 3 supplies the cookie-backed
// implementation.
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
// HTTP-POST bindings.
func (s *Server) handleSSO(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, idp.MaxRequestBytes)
	}
	req, err := s.opts.IdP.ParseRequest(r)
	if err != nil {
		s.rejectSSO(w, r, err)
		return
	}
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
	s.respond(w, r, log, req, identity)
}

// respond issues the signed SAML Response and renders the auto-POST page.
func (s *Server) respond(w http.ResponseWriter, r *http.Request, log *slog.Logger, req *idp.AuthnRequest, id *idp.Identity) {
	form, err := s.opts.IdP.Respond(req, id)
	if err != nil {
		if errors.Is(err, idp.ErrNoEmail) {
			log.WarnContext(r.Context(), "sso rejected", "error_category", "missing_email")
			s.errorPage(w, r, http.StatusForbidden, "Sign-in failed",
				"Your account has no email address, which is required to sign in.")
			return
		}
		log.ErrorContext(r.Context(), "issue saml response", "error_category", "assertion_failed", "error", err)
		s.errorPage(w, r, http.StatusInternalServerError, "Sign-in failed",
			"Something went wrong while signing you in. Please try again.")
		return
	}
	origin, err := web.Origin(form.Action)
	if err != nil {
		log.ErrorContext(r.Context(), "invalid ACS URL", "error", err)
		s.errorPage(w, r, http.StatusInternalServerError, "Sign-in failed", "The application is misconfigured.")
		return
	}
	fields := []web.Field{{Name: "SAMLResponse", Value: form.SAMLResponse}}
	if form.RelayState != "" {
		fields = append(fields, web.Field{Name: "RelayState", Value: form.RelayState})
	}
	page := web.PostFormPage{
		Action:     form.Action,
		FormAction: origin,
		Fields:     fields,
		Title:      "Signing you in to " + req.SP.DisplayName + "…",
	}
	if err := web.WritePostForm(w, page); err != nil {
		log.ErrorContext(r.Context(), "write saml response page", "error", err)
		return
	}
	log.InfoContext(r.Context(), "sso success", "email", id.Email, "acs_url", form.Action)
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
