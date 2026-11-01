package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/popoffvg/miniauth/internal/devices"
	"github.com/popoffvg/miniauth/internal/providers/passkey"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

const sessionsPagePath = "/sessions"

// sessionsPageCSP allows no script. The forms post to this origin only, and no page may frame this one.
const sessionsPageCSP = "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// deviceRequest documents the path parameter. The value is the device id, never the cookie.
type deviceRequest struct {
	Device string `path:"device" format:"uuid"`
}

// sessionsPageRequest documents the query of GET /sessions.
type sessionsPageRequest struct {
	Done string `query:"done" description:"The result of the last change. The page shows a fixed message for a known value and ignores any other value."`
}

// ShowPasskeys is false when the router has no passkey service.
type sessionsPageView struct {
	Shell        shellView
	Notice       pageMessage
	Devices      []deviceView
	Passkeys     []passkey.Passkey
	ShowPasskeys bool
	TwoStep      twoStepView
}

type deviceView struct {
	ID        devices.ID
	Name      devices.Name
	FirstSeen time.Time
	LastSeen  time.Time
	IsCurrent bool
}

func (s *service) sessionsPage(w http.ResponseWriter, r *http.Request) {
	session, err := s.openBrowserSession(r)
	if errors.Is(err, sessions.ErrNotFound) {
		s.sessionsPageLogin(w, r)
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: sessions page", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The devices were not loaded.")
		return
	}
	list, err := s.browser.Devices(r.Context(), session.UserID)
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: sessions page", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The devices were not loaded.")
		return
	}
	twoStep, err := s.twoStepView(r, session.UserID)
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: sessions page", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The devices were not loaded.")
		return
	}
	user, err := s.accounts.Find(r.Context(), session.UserID)
	if errors.Is(err, users.ErrNotFound) {
		s.sessionsPageLogin(w, r)
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: sessions page", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The devices were not loaded.")
		return
	}
	view := sessionsPageView{
		Shell:   s.shellFor(r, user, sessionsPagePath),
		Notice:  doneNotice(r),
		Devices: make([]deviceView, 0, len(list)),
		TwoStep: twoStep,
	}
	for _, device := range list {
		view.Devices = append(view.Devices, deviceView{
			ID:        device.ID,
			Name:      device.Name,
			FirstSeen: device.FirstSeen.UTC(),
			LastSeen:  device.LastSeen.UTC(),
			IsCurrent: session.DeviceID != (devices.ID{}) && device.ID == session.DeviceID,
		})
	}
	if s.passkeys != nil {
		view.ShowPasskeys = true
		if view.Passkeys, err = s.passkeys.List(r.Context(), session.UserID); err != nil {
			loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: sessions page", "err", err)
			writeProblem(w, http.StatusInternalServerError, "The passkeys were not loaded.")
			return
		}
	}
	w.Header().Set("Referrer-Policy", "no-referrer")
	writePage(w, r, http.StatusOK, securityPage(view), sessionsPageCSP)
}

// sessionsPageLogin sends a browser to the login page with this page as the return URL.
func (s *service) sessionsPageLogin(w http.ResponseWriter, r *http.Request) {
	if sessionCookiePresent(r) {
		sessions.ClearCookie(w, s.domain)
	}
	if !browserRequest(r) {
		writeProblem(w, http.StatusUnauthorized, "The session is not valid.")
		return
	}
	returnTo := ""
	if origin := s.publicURL.Origin(); origin != "" {
		returnTo = origin + sessionsPagePath
	}
	w.Header().Set("Location", s.publicURL.Login(returnTo))
	w.WriteHeader(http.StatusFound)
}

func (s *service) signOutDevice(w http.ResponseWriter, r *http.Request) {
	s.changeDevice(w, r, s.browser.SignOutDevice, doneSignedOut)
}

func (s *service) forgetDevice(w http.ResponseWriter, r *http.Request) {
	s.changeDevice(w, r, s.browser.ForgetDevice, doneForgotten)
}

// changeDevice runs change for a device of the session user and redirects to the sessions page.
// The Origin check comes first, so a cross-site form learns nothing about the session.
func (s *service) changeDevice(w http.ResponseWriter, r *http.Request, change func(context.Context, users.ID, devices.ID) error, done doneFlag) {
	if !s.sameOrigin(r) {
		writeProblem(w, http.StatusForbidden, "The request origin is not allowed.")
		return
	}
	session, err := s.openBrowserSession(r)
	if errors.Is(err, sessions.ErrNotFound) {
		writeProblem(w, http.StatusUnauthorized, "The session is not valid.")
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: change device", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The device was not changed.")
		return
	}
	deviceID, err := devices.ParseID(r.PathValue("device"))
	if err == nil {
		err = change(r.Context(), session.UserID, deviceID)
	}
	if errors.Is(err, devices.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "The device is not found.")
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: change device", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The device was not changed.")
		return
	}
	if deviceID == session.DeviceID {
		sessions.ClearCookie(w, s.domain)
	}
	w.Header().Set("Location", withDone(sessionsPagePath, done))
	w.WriteHeader(http.StatusSeeOther)
}
