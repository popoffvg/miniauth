package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/popoffvg/sfsm"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/providers/password"
	"github.com/popoffvg/miniauth/internal/providers/totp"
	"github.com/popoffvg/miniauth/internal/users"
	"github.com/popoffvg/miniauth/internal/views"
)

// maxLoginFormBody is large enough for the longest login and password, form-encoded.
const maxLoginFormBody = 16 << 10

// loginPageRequest documents the query of GET /login.
type loginPageRequest struct {
	Return string `query:"return" description:"The page to open after the login. An https URL under the cookie domain. Any other value opens the default page."`
}

// loginFormRequest documents the form of POST /login.
type loginFormRequest struct {
	Login    string `formData:"login" required:"true" minLength:"1" maxLength:"64"`
	Password string `formData:"password" required:"true" minLength:"1" maxLength:"1024" format:"password"`
}

// htmlPage documents an HTML body.
type htmlPage string

// loginPage starts a login flow and shows the form of its first step.
func (s *service) loginPage(w http.ResponseWriter, r *http.Request) {
	if s.flows == nil || s.passwords == nil {
		renderDenied(w, r, http.StatusServiceUnavailable, msgLoginUnavailable)
		return
	}
	returnURL := ParseReturnURL(r.URL.Query().Get("return"), s.domain, s.publicURL)
	id, secret, err := s.flows.Start(r.Context(), returnURL)
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: start login", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgLoginFailed)
		return
	}
	setFlowCookie(w, id, secret, time.Now())
	s.renderSteps(w, r, http.StatusOK, loginflow.LoginFlow{}, "")
}

// login runs the password step of the flow in the flow cookie.
// A complete flow starts a session and redirects to the return URL of the flow.
func (s *service) login(w http.ResponseWriter, r *http.Request) {
	machine, ip, ok := s.openLoginForm(w, r, s.passwords != nil)
	if !ok {
		return
	}
	defer func() { _ = machine.Close() }()
	if machine.Get().Kind == loginflow.KindStepUp {
		s.stepUp(w, r, machine, ip)
		return
	}

	retry := func(status int, message views.Message) {
		s.renderSteps(w, r, status, machine.Get(), message)
	}
	login, loginErr := users.ParseLogin(r.PostForm.Get("login"))
	userPassword, passwordErr := users.NewPassword(r.PostForm.Get("password"))
	if loginErr != nil || passwordErr != nil {
		retry(http.StatusOK, msgWrongCredentials)
		return
	}
	userID, err := s.passwords.Verify(r.Context(), machine, login, userPassword, ip)
	if stepFailed(w, r, err, retry) {
		return
	}
	s.finishStep(w, r, userID, machine.Get())
}

// openLoginForm runs the checks of a login form POST and opens the flow in the flow cookie.
// available is false when the step service is missing.
// It returns false after it wrote a reply. Else the caller MUST close the machine.
func (s *service) openLoginForm(w http.ResponseWriter, r *http.Request, available bool) (loginMachine, password.ClientIP, bool) {
	if !s.sameOrigin(r) {
		renderDenied(w, r, http.StatusForbidden, msgCrossOrigin)
		return nil, password.ClientIP{}, false
	}
	if s.flows == nil || !available {
		renderDenied(w, r, http.StatusServiceUnavailable, msgLoginUnavailable)
		return nil, password.ClientIP{}, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginFormBody)
	if r.ParseForm() != nil {
		renderDenied(w, r, http.StatusBadRequest, msgBadForm)
		return nil, password.ClientIP{}, false
	}
	ip, err := clientIP(r)
	if err != nil {
		renderDenied(w, r, http.StatusBadRequest, msgBadForm)
		return nil, password.ClientIP{}, false
	}
	machine, ok := s.openFlow(w, r)
	return machine, ip, ok
}

// openFlow opens the flow in the flow cookie. It returns false after it wrote a reply.
func (s *service) openFlow(w http.ResponseWriter, r *http.Request) (loginMachine, bool) {
	id, secret, err := flowFromRequest(r)
	if err != nil {
		renderDenied(w, r, http.StatusBadRequest, msgFlowExpired)
		return nil, false
	}
	machine, err := s.flows.Open(r.Context(), id, secret)
	if errors.Is(err, loginflow.ErrFlowNotFound) {
		clearFlowCookie(w)
		renderDenied(w, r, http.StatusBadRequest, msgFlowExpired)
		return nil, false
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: open login", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgLoginFailed)
		return nil, false
	}
	return machine, true
}

// stepFailed answers the error of a login step and reports whether it wrote a reply.
// retry shows the form of the step again with a message.
func stepFailed(w http.ResponseWriter, r *http.Request, err error, retry func(status int, message views.Message)) bool {
	var tooSoon *password.TooSoonError
	switch {
	case err == nil:
		return false
	case errors.Is(err, password.ErrWrongCredentials):
		retry(http.StatusOK, msgWrongCredentials)
	case errors.Is(err, totp.ErrWrongCode), errors.Is(err, totp.ErrInvalidCode):
		retry(http.StatusOK, msgWrongCode)
	case errors.Is(err, totp.ErrKeyMissing):
		renderDenied(w, r, http.StatusServiceUnavailable, msgLoginUnavailable)
	case errors.As(err, &tooSoon):
		w.Header().Set("Retry-After", retryAfter(tooSoon.RetryAt))
		retry(http.StatusTooManyRequests, msgTooSoon)
	case errors.Is(err, sfsm.ErrStaleState), errors.Is(err, loginflow.ErrNoTransition):
		clearFlowCookie(w)
		renderDenied(w, r, http.StatusBadRequest, msgFlowExpired)
	default:
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: login step", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgLoginFailed)
	}
	return true
}

// finishStep shows the open steps until the flow is complete.
func (s *service) finishStep(w http.ResponseWriter, r *http.Request, userID users.ID, flow loginflow.LoginFlow) {
	if !flow.State.Final() {
		s.renderSteps(w, r, http.StatusOK, flow, "")
		return
	}
	clearFlowCookie(w)
	if flow.State != loginflow.StateComplete {
		renderDenied(w, r, http.StatusBadRequest, msgFlowExpired)
		return
	}
	if err := s.startBrowserSession(w, r, userID, flow.Factors); err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: start session", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgLoginFailed)
		return
	}
	if confirm := s.linkConfirmURL(r, flow.Factors, flow.ReturnURL); confirm != "" {
		http.Redirect(w, r, confirm, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, flow.ReturnURL.String(), http.StatusSeeOther)
}

// startBrowserSession is the one place a login starts a session.
// It sets the session cookie and the device cookie, and replaces the session of that device.
func (s *service) startBrowserSession(w http.ResponseWriter, r *http.Request, userID users.ID, factors loginflow.Factors) error {
	_, _, err := s.browser.StartOnDevice(r.Context(), w, r, s.domain, userID, factors)
	return err
}

// sameOrigin is the CSRF check of a form POST. Origin MUST be the public origin.
// A missing Origin fails, and so does every POST when the public URL is not configured.
func (s *service) sameOrigin(r *http.Request) bool {
	origin := s.publicURL.Origin()
	return origin != "" && strings.EqualFold(r.Header.Get("Origin"), origin)
}

// retryAfter is the Retry-After value in whole seconds, at least 1.
func retryAfter(at time.Time) string {
	seconds := int(time.Until(at).Seconds()) + 1
	return strconv.Itoa(max(seconds, 1))
}
