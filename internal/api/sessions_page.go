package api

import (
	"context"
	_ "embed"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/popoffvg/miniauth/internal/devices"
	"github.com/popoffvg/miniauth/internal/passkeystep"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

const sessionsPagePath = "/sessions"

// sessionsPageCSP allows no script. The forms post to this origin only, and no page may frame this one.
const sessionsPageCSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

//go:embed sessions_page.html
var sessionsPageHTML string

var sessionsPageTemplate = template.Must(template.New("sessions").Parse(sessionsPageHTML))

// deviceRequest documents the path parameter. The value is the device id, never the cookie.
type deviceRequest struct {
	Device string `path:"device" format:"uuid"`
}

// ShowPasskeys is false when the router has no passkey service.
type sessionsPageView struct {
	Devices      []deviceView
	Passkeys     []passkeystep.Passkey
	ShowPasskeys bool
}

type deviceView struct {
	ID        devices.ID
	Name      devices.Name
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
	view := sessionsPageView{Devices: make([]deviceView, 0, len(list))}
	for _, device := range list {
		view.Devices = append(view.Devices, deviceView{
			ID:        device.ID,
			Name:      device.Name,
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
	var page strings.Builder
	if err = sessionsPageTemplate.Execute(&page, view); err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: sessions page", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The devices were not loaded.")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", sessionsPageCSP)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(page.String()))
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
	s.changeDevice(w, r, s.browser.SignOutDevice)
}

func (s *service) forgetDevice(w http.ResponseWriter, r *http.Request) {
	s.changeDevice(w, r, s.browser.ForgetDevice)
}

// changeDevice runs change for a device of the session user and redirects to the sessions page.
// The Origin check comes first, so a cross-site form learns nothing about the session.
func (s *service) changeDevice(w http.ResponseWriter, r *http.Request, change func(context.Context, users.ID, devices.ID) error) {
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
	w.Header().Set("Location", sessionsPagePath)
	w.WriteHeader(http.StatusSeeOther)
}
