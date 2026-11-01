package api

import (
	"errors"
	"net/http"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/providers/totp"
	"github.com/popoffvg/miniauth/internal/users"
	"github.com/popoffvg/miniauth/internal/views"
)

const (
	totpEnrollPath  = views.TOTPEnrollPath
	totpConfirmPath = views.TOTPConfirmPath
	totpDisablePath = views.TOTPDisablePath
)

const (
	msgTwoStepUnavailable views.Message = "Two-step login is not available."
	msgTwoStepStepUp      views.Message = "Enter your password again to change two-step login."
	msgTwoStepExpired     views.Message = "The two-step login setup expired. Start it again from your devices page."
	msgTwoStepFailed      views.Message = "The two-step login change failed. Try again."
	msgWrongCode          views.Message = "The code is wrong or was used before."
)

// WithTOTP serves the TOTP step, the recovery code step, and TOTP enrollment.
// The password step MUST report the users of totp as needing a second factor.
func WithTOTP(totp *totp.Service) RouterOption {
	return func(s *service) {
		s.totp = totp
	}
}

// enrollTOTP makes a TOTP secret and shows it with a QR code.
// An AuthAt older than sessions.StepUpAfter starts a step-up first.
func (s *service) enrollTOTP(w http.ResponseWriter, r *http.Request) {
	user, ok := s.twoStepUser(w, r)
	if !ok {
		return
	}
	if !s.totp.EnrollmentOn() {
		renderDenied(w, r, http.StatusServiceUnavailable, msgTwoStepUnavailable)
		return
	}
	enrollment, err := s.totp.Begin(r.Context(), user)
	if err != nil {
		s.twoStepFailed(w, r, err)
		return
	}
	s.renderEnrollment(w, r, user, enrollment, "")
}

// confirmTOTP turns on TOTP when the code matches, and shows the recovery codes once.
func (s *service) confirmTOTP(w http.ResponseWriter, r *http.Request) {
	user, ok := s.twoStepUser(w, r)
	if !ok {
		return
	}
	code, err := totp.ParseCode(r.PostForm.Get("code"))
	var codes []totp.RecoveryCode
	if err == nil {
		codes, err = s.totp.Confirm(r.Context(), user.ID, code)
	}
	switch {
	case errors.Is(err, totp.ErrInvalidCode), errors.Is(err, totp.ErrWrongCode):
		enrollment, pendingErr := s.totp.Pending(r.Context(), user)
		if pendingErr != nil {
			s.twoStepFailed(w, r, pendingErr)
			return
		}
		s.renderEnrollment(w, r, user, enrollment, msgWrongCode)
		return
	case err != nil:
		s.twoStepFailed(w, r, err)
		return
	}
	// The codes are in this body only. They MUST NOT reach a URL, a log, or a cache.
	w.Header().Set("Cache-Control", "no-store")
	renderPage(w, r, http.StatusOK, views.PageRecoveryCodes, views.Page{Shell: s.shellFor(r, user, sessionsPagePath), RecoveryCodes: codes})
}

// disableTOTP turns off TOTP and deletes the recovery codes.
func (s *service) disableTOTP(w http.ResponseWriter, r *http.Request) {
	user, ok := s.twoStepUser(w, r)
	if !ok {
		return
	}
	if err := s.totp.Disable(r.Context(), user.ID); err != nil {
		s.twoStepFailed(w, r, err)
		return
	}
	http.Redirect(w, r, withDone(sessionsPagePath, doneTwoStepOff), http.StatusSeeOther)
}

// twoStepUser runs the checks of a two-step login form POST and returns the session user.
// A login older than sessions.StepUpAfter starts a step-up that returns to the sessions page.
// It returns false after it wrote a reply.
func (s *service) twoStepUser(w http.ResponseWriter, r *http.Request) (users.User, bool) {
	if !s.sameOrigin(r) {
		renderDenied(w, r, http.StatusForbidden, msgCrossOrigin)
		return users.User{}, false
	}
	if s.totp == nil || s.flows == nil || s.passwords == nil {
		renderDenied(w, r, http.StatusServiceUnavailable, msgTwoStepUnavailable)
		return users.User{}, false
	}
	user, session, ok := s.browserPageUser(w, r, sessionsPagePath, msgTwoStepFailed)
	if !ok {
		return users.User{}, false
	}
	if !s.browser.AuthRecent(session) {
		s.askStepUp(w, r, user, loginflow.ReturnURL(s.publicURL.Origin()+sessionsPagePath), msgTwoStepStepUp)
		return users.User{}, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginFormBody)
	if r.ParseForm() != nil {
		renderDenied(w, r, http.StatusBadRequest, msgBadForm)
		return users.User{}, false
	}
	return user, true
}

// twoStepView reads the two-step login state of userID for the sessions page.
func (s *service) twoStepView(r *http.Request, userID users.ID) (views.TwoStep, error) {
	if s.totp == nil {
		return views.TwoStep{}, nil
	}
	on, err := s.totp.HasSecondFactor(r.Context(), userID)
	if err != nil {
		return views.TwoStep{}, err
	}
	return views.TwoStep{Shown: true, On: on, CanEnroll: !on && s.totp.EnrollmentOn()}, nil
}

func (s *service) renderEnrollment(w http.ResponseWriter, r *http.Request, user users.User, enrollment totp.Enrollment, message views.Message) {
	image, err := views.NewQRImage(enrollment.URI)
	if err != nil {
		s.twoStepFailed(w, r, err)
		return
	}
	// The secret is in this body only. It MUST NOT reach a URL, a log, or a cache.
	w.Header().Set("Cache-Control", "no-store")
	renderPage(w, r, http.StatusOK, views.PageTOTPEnroll, views.Page{Shell: s.shellFor(r, user, sessionsPagePath), Message: message, Enrollment: &views.Enrollment{Secret: enrollment.Secret, QR: image}})
}

// twoStepFailed answers an error of an enrollment step.
func (s *service) twoStepFailed(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, totp.ErrEnrolled):
		http.Redirect(w, r, sessionsPagePath, http.StatusSeeOther)
	case errors.Is(err, totp.ErrNoEnrollment):
		renderDenied(w, r, http.StatusBadRequest, msgTwoStepExpired)
	case errors.Is(err, totp.ErrKeyMissing):
		renderDenied(w, r, http.StatusServiceUnavailable, msgTwoStepUnavailable)
	default:
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: two-step login", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgTwoStepFailed)
	}
}
