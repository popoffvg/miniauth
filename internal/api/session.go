package api

import (
	"errors"
	"net/http"

	"github.com/popoffvg/miniauth/internal/sessions"
)

func (s *service) logout(w http.ResponseWriter, r *http.Request) {
	for _, id := range sessions.IDsFromRequest(r) {
		if err := s.browser.Logout(r.Context(), id); err != nil {
			loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: logout", "err", err)
			writeProblem(w, http.StatusInternalServerError, "The session was not deleted.")
			return
		}
	}
	sessions.ClearCookie(w, s.domain)
	w.WriteHeader(http.StatusNoContent)
}

func (s *service) logoutEverywhere(w http.ResponseWriter, r *http.Request) {
	deleted := false
	for _, id := range sessions.IDsFromRequest(r) {
		err := s.browser.LogoutEverywhere(r.Context(), id)
		if errors.Is(err, sessions.ErrNotFound) {
			continue
		}
		if err != nil {
			loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: logout everywhere", "err", err)
			writeProblem(w, http.StatusInternalServerError, "The sessions were not deleted.")
			return
		}
		deleted = true
	}
	sessions.ClearCookie(w, s.domain)
	if !deleted {
		writeProblem(w, http.StatusUnauthorized, "The session is not valid.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
