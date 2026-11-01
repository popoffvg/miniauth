package api

import (
	"net/http"
	"slices"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

// adminPageUser returns the session user of an admin page when the user is in groups.Admins.
// It returns false after it wrote a reply: a login redirect that returns to returnPath, 403 with refused
// for any other user, or an error page with failed.
func (s *service) adminPageUser(w http.ResponseWriter, r *http.Request, returnPath string, failed, refused pageMessage) (users.User, sessions.Session, bool) {
	user, session, ok := s.browserPageUser(w, r, returnPath, failed)
	if !ok {
		return users.User{}, sessions.Session{}, false
	}
	names, err := s.groups.List(r.Context(), user.ID)
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: admin page", "path", returnPath, "err", err)
		renderDenied(w, r, http.StatusInternalServerError, failed)
		return users.User{}, sessions.Session{}, false
	}
	if !slices.Contains(names, groups.Admins()) {
		renderDenied(w, r, http.StatusForbidden, refused)
		return users.User{}, sessions.Session{}, false
	}
	return user, session, true
}
