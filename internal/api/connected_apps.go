package api

import (
	"errors"
	"net/http"

	"github.com/popoffvg/miniauth/internal/oauth"
)

// appsPath holds the connected apps of the token page. The list itself is on the token page.
const appsPath = tokensPath + "/apps"

const msgAppNotFound pageMessage = "The app is not connected."

// appRevokeRequest documents the path of POST /tokens/apps/{id}/revoke.
type appRevokeRequest struct {
	ID string `path:"id" format:"uuid"`
}

// revokeApp ends a consent of the session user and every token issued under it.
func (s *service) revokeApp(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		renderDenied(w, r, http.StatusForbidden, msgCrossOrigin)
		return
	}
	if s.oauth == nil {
		renderDenied(w, r, http.StatusServiceUnavailable, msgOAuthUnavailable)
		return
	}
	user, _, ok := s.tokenPageUser(w, r)
	if !ok {
		return
	}
	id, err := oauth.ParseConsentID(r.PathValue("id"))
	if err == nil {
		err = s.oauth.RevokeConsent(r.Context(), user.ID, id)
	}
	if errors.Is(err, oauth.ErrConsentNotFound) {
		s.renderTokens(w, r, http.StatusNotFound, user, msgAppNotFound)
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: revoke app", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgTokenFailed)
		return
	}
	http.Redirect(w, r, s.publicURL.Origin()+withDone(tokensPath, doneAppRevoked), http.StatusSeeOther)
}
