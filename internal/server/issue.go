package server

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/kc9wwh/symbiont-sso/internal/access"
	"github.com/kc9wwh/symbiont-sso/internal/idp"
	"github.com/kc9wwh/symbiont-sso/internal/mapping"
	"github.com/kc9wwh/symbiont-sso/internal/web"
)

// issue is the single enforcement point for every assertion, SP- or
// IdP-initiated: the target SP's access policy, then its attribute mapping
// and Fleet role validation, then signing and the CSP-hashed POST page.
//
// A denied user gets a 403 page and no assertion. The bridge session is
// deliberately kept (the user may be allowed on other SPs), and the user is
// never sent back to the IdP, so there is no redirect loop.
func (s *Server) issue(w http.ResponseWriter, r *http.Request, log *slog.Logger, req *idp.AuthnRequest, id *idp.Identity) {
	sp := req.SP
	dec, err := access.Decide(sp, access.Subject{Email: id.Email, Groups: id.Groups, Claims: id.Claims})
	if !dec.Allowed {
		log.WarnContext(r.Context(), "access denied", "email", id.Email, "reason", dec.Reason)
		s.errorPage(w, r, http.StatusForbidden, "Access denied",
			"You don't have access to "+sp.DisplayName+". If you think this is a mistake, contact your administrator.")
		return
	}
	if err != nil {
		var me *mapping.Error
		if errors.As(err, &me) {
			attrs := []any{"email", id.Email, "error_category", me.Category, "reason", me.Message}
			if me.Attribute != "" {
				// Names only. For passthrough the attribute name is the claim name.
				attrs = append(attrs, "attribute", me.Attribute, "attribute_source", string(me.Source))
				if me.Source == mapping.SourcePassthrough {
					attrs = append(attrs, "claim", me.Attribute)
				}
			}
			log.WarnContext(r.Context(), "assertion refused", attrs...)
			s.errorPage(w, r, http.StatusForbidden, "Sign-in refused", me.Message+".")
			return
		}
		log.ErrorContext(r.Context(), "attribute mapping failed", "error", err)
		s.errorPage(w, r, http.StatusInternalServerError, "Sign-in failed", "Something went wrong while signing you in.")
		return
	}
	for _, n := range dec.Mapping.Notes {
		log.DebugContext(r.Context(), "attribute mapping", "detail", n)
	}
	attrs := make([]idp.Attribute, len(dec.Mapping.Attributes))
	for i, a := range dec.Mapping.Attributes {
		attrs[i] = idp.Attribute{Name: a.Name, Value: a.Value}
	}

	form, err := s.opts.IdP.Respond(req, id, attrs)
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
		Title:      "Signing you in to " + sp.DisplayName + "…",
	}
	if err := web.WritePostForm(w, page); err != nil {
		log.ErrorContext(r.Context(), "write saml response page", "error", err)
		return
	}
	log.InfoContext(r.Context(), "sso success", "sub", id.Subject, "acs_url", form.Action,
		"fleet_role_attributes", mapping.RoleAttributeNames(dec.Mapping.Attributes))
}
