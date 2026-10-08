package server

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/kc9wwh/symbiont-sso/internal/idp"
	"github.com/kc9wwh/symbiont-sso/internal/oidcrp"
	"github.com/kc9wwh/symbiont-sso/internal/session"
	"github.com/kc9wwh/symbiont-sso/internal/web"
)

// resume continues the flow that started the login.
func (s *Server) resume(w http.ResponseWriter, r *http.Request, log *slog.Logger, p session.Pending) {
	switch p.Kind {
	case session.KindSP:
		if _, ok := s.opts.IdP.SPs().ByID(p.SPID); !ok || len(p.RawRequest) == 0 {
			s.callbackFail(w, r, log, catReplayPending, nil, http.StatusBadRequest)
			return
		}
		l := s.opts.Login
		fields := []web.Field{
			{Name: "SAMLRequest", Value: encodeStd(p.RawRequest)},
			{Name: replayField, Value: replayToken(l.Signer, p.RawRequest, p.ReceivedAt, l.now())},
		}
		if p.RelayState != "" {
			fields = append(fields, web.Field{Name: "RelayState", Value: p.RelayState})
		}
		err := web.WritePostForm(w, web.PostFormPage{
			Action: idp.SSOPath, FormAction: "'self'", Fields: fields, Title: "Continuing sign-in…",
		})
		if err != nil {
			log.ErrorContext(r.Context(), "write replay page", "error", err)
		}
	case session.KindIDP:
		sp, ok := s.opts.IdP.SPs().ByID(p.SPID)
		if !ok || !sp.IDPInitiatedEnabled {
			s.callbackFail(w, r, log, catSPGone, nil, http.StatusNotFound)
			return
		}
		http.Redirect(w, r, s.loginReturnURL(sp.ID, p.RelayState), http.StatusFound)
	default:
		s.callbackFail(w, r, log, catUnknownKind, nil, http.StatusBadRequest)
	}
}

// callbackFail logs a categorized failure (details at debug only, since
// upstream errors may echo request data) and shows a generic page.
func (s *Server) callbackFail(w http.ResponseWriter, r *http.Request, log *slog.Logger, category string, err error, status int) {
	log.WarnContext(r.Context(), "oidc callback failed", "error_category", category)
	if err != nil {
		log.DebugContext(r.Context(), "oidc callback failure detail", "error_category", category, "error", err.Error())
	}
	s.errorPage(w, r, status, titleSignInFailed, "Something went wrong while signing you in. "+msgTryAgain)
}

// identityFail handles global identity policy rejections with specific,
// non-sensitive messages.
func (s *Server) identityFail(w http.ResponseWriter, r *http.Request, log *slog.Logger, err error) {
	cat := categoryOf(err)
	log.WarnContext(r.Context(), "sign-in rejected", "error_category", cat, "reason", err.Error())
	msg := "Your account is not allowed to sign in here."
	switch cat {
	case oidcrp.CategoryMissingEmail:
		msg = "Your account has no email address, which is required to sign in."
	case oidcrp.CategoryEmailUnverified:
		msg = "Your email address has not been verified with the identity provider."
	case oidcrp.CategoryDomainNotAllowed:
		msg = "Accounts with your email domain are not allowed to sign in."
	case oidcrp.CategoryBadGroups:
		msg = "Your account's group information could not be read. Contact your administrator."
	}
	s.errorPage(w, r, http.StatusForbidden, titleSignInFailed, msg)
}

func categoryOf(err error) string {
	var oe *oidcrp.Error
	if errors.As(err, &oe) {
		return oe.Category
	}
	return "internal_error"
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
