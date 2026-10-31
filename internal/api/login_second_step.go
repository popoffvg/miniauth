package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/passwordstep"
	"github.com/popoffvg/miniauth/internal/totpstep"
	"github.com/popoffvg/miniauth/internal/users"
)

// codeFormRequest documents the form of POST /login/totp and POST /sessions/totp/confirm.
type codeFormRequest struct {
	Code string `formData:"code" required:"true" minLength:"6" maxLength:"16" description:"6 digits from the authenticator app."`
}

// recoveryFormRequest documents the form of POST /login/recovery-code.
type recoveryFormRequest struct {
	Code string `formData:"code" required:"true" minLength:"16" maxLength:"32" description:"One recovery code. Case, spaces, and dashes are ignored."`
}

// totpOffered reports whether the TOTP step and the recovery code step are served.
func (s *service) totpOffered() bool {
	return s.totp != nil
}

// stepPage shows the form of the step of factor when the flow in the flow cookie has it open.
// Else it shows the open steps of the flow.
func (s *service) stepPage(factor loginflow.Factor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.flows == nil || s.totp == nil {
			renderDenied(w, r, http.StatusServiceUnavailable, msgLoginUnavailable)
			return
		}
		machine, ok := s.openFlow(w, r)
		if !ok {
			return
		}
		defer func() { _ = machine.Close() }()
		flow := machine.Get()
		if _, open := findStep(s.openSteps(flow), factor); !open {
			factor = 0
		}
		s.renderStep(w, r, http.StatusOK, flow, factor, "")
	}
}

// loginTOTP checks a TOTP code for the user of the flow in the flow cookie.
func (s *service) loginTOTP(w http.ResponseWriter, r *http.Request) {
	s.secondStep(w, r, loginflow.FactorTOTP, func(ctx context.Context, machine loginMachine, user users.User, ip passwordstep.ClientIP) error {
		code, err := totpstep.ParseCode(r.PostForm.Get("code"))
		if err != nil {
			return err
		}
		return s.totp.VerifyCode(ctx, machine, user, code, ip)
	})
}

// loginRecoveryCode spends a recovery code of the user of the flow in the flow cookie.
func (s *service) loginRecoveryCode(w http.ResponseWriter, r *http.Request) {
	s.secondStep(w, r, loginflow.FactorRecovery, func(ctx context.Context, machine loginMachine, user users.User, ip passwordstep.ClientIP) error {
		code, err := totpstep.ParseRecoveryCode(r.PostForm.Get("code"))
		if err != nil {
			return err
		}
		return s.totp.VerifyRecoveryCode(ctx, machine, user, code, ip)
	})
}

// secondStep runs verify for the step of factor after the password of a user with TOTP.
// A complete flow starts a session and redirects to the return URL of the flow.
func (s *service) secondStep(w http.ResponseWriter, r *http.Request, factor loginflow.Factor, verify func(context.Context, loginMachine, users.User, passwordstep.ClientIP) error) {
	machine, ip, ok := s.openLoginForm(w, r, s.totp != nil)
	if !ok {
		return
	}
	defer func() { _ = machine.Close() }()
	flow := machine.Get()
	if _, open := findStep(s.openSteps(flow), factor); flow.Kind != loginflow.KindLogin || flow.UserID == (users.ID{}) || !open {
		s.renderSteps(w, r, http.StatusBadRequest, flow, "")
		return
	}
	user, err := s.accounts.Find(r.Context(), flow.UserID)
	if errors.Is(err, users.ErrNotFound) || err == nil && user.Disabled() {
		clearFlowCookie(w)
		renderDenied(w, r, http.StatusBadRequest, msgFlowExpired)
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: second step", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgLoginFailed)
		return
	}
	retry := func(status int, message pageMessage) {
		s.renderStep(w, r, status, flow, factor, message)
	}
	if stepFailed(w, r, verify(r.Context(), machine, user, ip), retry) {
		return
	}
	s.finishStep(w, r, user.ID, machine.Get())
}
