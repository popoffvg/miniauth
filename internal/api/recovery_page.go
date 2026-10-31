package api

import (
	"errors"
	"net/http"

	"github.com/popoffvg/miniauth/internal/passwordstep"
	"github.com/popoffvg/miniauth/internal/recovery"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

// maxRecoveryFormBody is large enough for the token and the longest password, form-encoded.
const maxRecoveryFormBody = 16 << 10

// recoverFormRequest documents the form of POST /recover.
type recoverFormRequest struct {
	Email string `formData:"email" required:"true" minLength:"1" maxLength:"64" format:"email"`
}

// resetPageRequest documents the path of GET /recover/{token}.
type resetPageRequest struct {
	Token string `path:"token" required:"true" minLength:"43" maxLength:"43"`
}

// resetFormRequest documents the form of POST /recover/reset.
type resetFormRequest struct {
	Token    string `formData:"token" required:"true" minLength:"43" maxLength:"43"`
	Password string `formData:"password" required:"true" minLength:"1" maxLength:"1024" format:"password"`
}

// WithRecovery serves password recovery. Without it, the recovery routes answer 503 and the login page hides the link.
func WithRecovery(svc *recovery.Service) RouterOption {
	return func(s *service) {
		s.recovery = svc
	}
}

// recoverPage asks for the address.
func (s *service) recoverPage(w http.ResponseWriter, r *http.Request) {
	if s.recovery == nil {
		renderDenied(w, r, http.StatusServiceUnavailable, msgRecoveryOff)
		return
	}
	renderPage(w, r, http.StatusOK, pageRecover, pageView{})
}

// requestRecovery queues a reset link. A known, an unknown, and a malformed address get the same reply.
func (s *service) requestRecovery(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		renderDenied(w, r, http.StatusForbidden, msgCrossOrigin)
		return
	}
	if s.recovery == nil {
		renderDenied(w, r, http.StatusServiceUnavailable, msgRecoveryOff)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRecoveryFormBody)
	if r.ParseForm() != nil {
		renderPage(w, r, http.StatusBadRequest, pageRecover, pageView{Message: msgBadForm})
		return
	}
	ip, err := clientIP(r)
	if err != nil {
		renderPage(w, r, http.StatusBadRequest, pageRecover, pageView{Message: msgBadForm})
		return
	}
	email, err := users.ParseEmail(r.PostForm.Get("email"))
	if err != nil {
		renderPage(w, r, http.StatusOK, pageRecoverSent, pageView{Message: msgRecoverySent})
		return
	}
	err = s.recovery.Request(r.Context(), email, ip)
	var tooSoon *passwordstep.TooSoonError
	switch {
	case errors.As(err, &tooSoon):
		w.Header().Set("Retry-After", retryAfter(tooSoon.RetryAt))
		renderPage(w, r, http.StatusTooManyRequests, pageRecover, pageView{Message: msgTooSoon})
		return
	case errors.Is(err, recovery.ErrQueueFull):
		loggerFrom(r.Context()).WarnContext(r.Context(), "miniauth: recovery request", "err", err)
	case err != nil:
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: recovery request", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgRecoveryFailed)
		return
	}
	renderPage(w, r, http.StatusOK, pageRecoverSent, pageView{Message: msgRecoverySent})
}

// resetPage asks for the new password. The token moves from the URL to a hidden form field.
func (s *service) resetPage(w http.ResponseWriter, r *http.Request) {
	hideResetLink(w)
	if s.recovery == nil {
		renderDenied(w, r, http.StatusServiceUnavailable, msgRecoveryOff)
		return
	}
	token, err := recovery.ParseToken(r.PathValue("token"))
	if err != nil {
		renderDenied(w, r, http.StatusBadRequest, msgResetLinkInvalid)
		return
	}
	err = s.recovery.Check(r.Context(), token)
	if errors.Is(err, recovery.ErrInvalidToken) {
		renderDenied(w, r, http.StatusBadRequest, msgResetLinkInvalid)
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: reset page", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgRecoveryFailed)
		return
	}
	renderPage(w, r, http.StatusOK, pageReset, pageView{ResetToken: token})
}

// reset sets the new password and signs the user out everywhere.
func (s *service) reset(w http.ResponseWriter, r *http.Request) {
	hideResetLink(w)
	if !s.sameOrigin(r) {
		renderDenied(w, r, http.StatusForbidden, msgCrossOrigin)
		return
	}
	if s.recovery == nil {
		renderDenied(w, r, http.StatusServiceUnavailable, msgRecoveryOff)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRecoveryFormBody)
	if r.ParseForm() != nil {
		renderDenied(w, r, http.StatusBadRequest, msgBadForm)
		return
	}
	token, err := recovery.ParseToken(r.PostForm.Get("token"))
	if err != nil {
		renderDenied(w, r, http.StatusBadRequest, msgResetLinkInvalid)
		return
	}
	password, err := users.NewPassword(r.PostForm.Get("password"))
	if err != nil {
		renderPage(w, r, http.StatusBadRequest, pageReset, pageView{Message: msgNewPasswordInvalid, ResetToken: token})
		return
	}
	err = s.recovery.Reset(r.Context(), token, password)
	if errors.Is(err, recovery.ErrQueueFull) {
		loggerFrom(r.Context()).WarnContext(r.Context(), "miniauth: reset password", "err", err)
		err = nil
	}
	if errors.Is(err, recovery.ErrInvalidToken) {
		renderDenied(w, r, http.StatusBadRequest, msgResetLinkInvalid)
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: reset password", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgRecoveryFailed)
		return
	}
	sessions.ClearCookie(w, s.domain)
	renderPage(w, r, http.StatusOK, pageResetDone, pageView{})
}

// hideResetLink keeps the URL with the token out of a Referer header and out of a cache.
func hideResetLink(w http.ResponseWriter) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
}
