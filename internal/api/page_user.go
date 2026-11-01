package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
	"github.com/popoffvg/miniauth/internal/views"
)

// browserPageUser returns the active user of the browser session.
// With no session, or with a missing or disabled user, it redirects to the login page, which returns to returnPath.
// It returns false after it wrote a reply. failed is the message of a store error.
// returnPath can carry a query. The log gets the path only.
func (s *service) browserPageUser(w http.ResponseWriter, r *http.Request, returnPath string, failed views.Message) (users.User, sessions.Session, bool) {
	toLogin := s.publicURL.Login(s.publicURL.Origin() + returnPath)
	logPath, _, _ := strings.Cut(returnPath, "?")
	session, err := s.openBrowserSession(w, r)
	if errors.Is(err, sessions.ErrNotFound) {
		http.Redirect(w, r, toLogin, http.StatusSeeOther)
		return users.User{}, sessions.Session{}, false
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: page session", "path", logPath, "err", err)
		renderDenied(w, r, http.StatusInternalServerError, failed)
		return users.User{}, sessions.Session{}, false
	}
	user, err := s.accounts.Find(r.Context(), session.UserID)
	if errors.Is(err, users.ErrNotFound) || err == nil && user.Disabled() {
		http.Redirect(w, r, toLogin, http.StatusSeeOther)
		return users.User{}, sessions.Session{}, false
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: page session", "path", logPath, "err", err)
		renderDenied(w, r, http.StatusInternalServerError, failed)
		return users.User{}, sessions.Session{}, false
	}
	return user, session, true
}
