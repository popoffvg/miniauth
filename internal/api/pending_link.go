package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/popoffvg/miniauth/internal/identitylink"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/users"
)

// pendingLinkCookieName binds a pending link to the browser. The database stores its SHA-256.
const pendingLinkCookieName = "__Host-id_pending_link"

// linkingFactor is the factor a completed login MUST hold before a pending link becomes an identity of its user.
const linkingFactor = loginflow.FactorPassword

// rememberPendingLink stores the unknown account and asks, with message, for a password login in this browser.
func (s *service) rememberPendingLink(w http.ResponseWriter, r *http.Request, account users.ExternalAccount, collected loginflow.Factors, message pageMessage) {
	secret, err := s.links.Remember(r.Context(), account)
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: remember pending link", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgLoginFailed)
		return
	}
	http.SetCookie(w, hostCookie(pendingLinkCookieName, secret.CookieValue(), identitylink.LinkTTL, time.Now()))
	s.renderSteps(w, r, http.StatusOK, collected, message)
}

// linkPendingIdentity makes the pending link of this browser an identity of userID.
// A failed link does not fail the login: the session already started.
func (s *service) linkPendingIdentity(w http.ResponseWriter, r *http.Request, userID users.ID, collected loginflow.Factors) {
	if s.links == nil || !collected.Has(linkingFactor) {
		return
	}
	cookie, err := r.Cookie(pendingLinkCookieName)
	if err != nil {
		return
	}
	http.SetCookie(w, expiredHostCookie(pendingLinkCookieName))
	secret, err := identitylink.ParseLinkSecret(cookie.Value)
	if err != nil {
		return
	}
	account, err := s.links.Complete(r.Context(), secret, userID)
	logger := loggerFrom(r.Context())
	switch {
	case errors.Is(err, identitylink.ErrNotFound):
	case errors.Is(err, identitylink.ErrAccountTaken):
		logger.WarnContext(r.Context(), "miniauth: pending link refused", "user", userID.String(), "err", err)
	case err != nil:
		logger.ErrorContext(r.Context(), "miniauth: link identity", "err", err)
	default:
		logger.InfoContext(r.Context(), "miniauth: identity linked", "user", userID.String(), "kind", account.Kind.String())
	}
}
