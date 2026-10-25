package api

import (
	"errors"
	"net/http"

	"github.com/popoffvg/miniauth/internal/sessions"
)

func (s *service) logout(w http.ResponseWriter, r *http.Request) {
	if s.browser == nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: logout", "err", errors.New("api: session service is missing"))
		writeProblem(w, http.StatusInternalServerError, "The session was not deleted.")
		return
	}
	if id, err := sessions.FromRequest(r); err == nil {
		if err = s.browser.Logout(r.Context(), id); err != nil {
			loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: logout", "err", err)
			writeProblem(w, http.StatusInternalServerError, "The session was not deleted.")
			return
		}
	}
	sessions.ClearCookie(w, s.domain)
	w.WriteHeader(http.StatusNoContent)
}

func (s *service) logoutEverywhere(w http.ResponseWriter, r *http.Request) {
	if s.browser == nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: logout everywhere", "err", errors.New("api: session service is missing"))
		writeProblem(w, http.StatusInternalServerError, "The sessions were not deleted.")
		return
	}
	id, err := sessions.FromRequest(r)
	if err != nil {
		sessions.ClearCookie(w, s.domain)
		writeProblem(w, http.StatusUnauthorized, "The session is not valid.")
		return
	}
	if err = s.browser.LogoutEverywhere(r.Context(), id); err != nil {
		if errors.Is(err, sessions.ErrNotFound) {
			sessions.ClearCookie(w, s.domain)
			writeProblem(w, http.StatusUnauthorized, "The session is not valid.")
			return
		}
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: logout everywhere", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The sessions were not deleted.")
		return
	}
	sessions.ClearCookie(w, s.domain)
	w.WriteHeader(http.StatusNoContent)
}
