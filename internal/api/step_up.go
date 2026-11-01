package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/popoffvg/sfsm"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/providers/password"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

// loginMachine is an open login flow from loginflow.LoginFlows.Open.
type loginMachine = *sfsm.PersistedSFSM[loginflow.FlowID, loginflow.LoginFlow, loginflow.Event]

// askStepUp starts a step-up flow for user and shows the password form.
// After the step-up the browser returns to returnTo.
func (s *service) askStepUp(w http.ResponseWriter, r *http.Request, user users.User, returnTo loginflow.ReturnURL, message pageMessage) {
	id, secret, err := s.flows.StartStepUp(r.Context(), user.ID, returnTo)
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: start step-up", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgLoginFailed)
		return
	}
	setFlowCookie(w, id, secret, time.Now())
	renderPage(w, r, http.StatusOK, pageStepUp, pageView{Login: user.Login, Prompt: message})
}

// stepUp checks the password of the flow user. The login in the form is not read,
// so a password of another login cannot pass. A complete flow renews AuthAt of the session.
func (s *service) stepUp(w http.ResponseWriter, r *http.Request, machine loginMachine, ip password.ClientIP) {
	flow := machine.Get()
	user, err := s.accounts.Find(r.Context(), flow.UserID)
	if errors.Is(err, users.ErrNotFound) || err == nil && user.Disabled() {
		clearFlowCookie(w)
		renderDenied(w, r, http.StatusBadRequest, msgFlowExpired)
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: step-up", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgLoginFailed)
		return
	}
	retry := func(status int, message pageMessage) {
		renderPage(w, r, status, pageStepUp, pageView{Login: user.Login, Message: message})
	}
	userPassword, err := users.NewPassword(r.PostForm.Get("password"))
	if err != nil {
		retry(http.StatusOK, msgWrongCredentials)
		return
	}
	userID, err := s.passwords.Verify(r.Context(), machine, user.Login, userPassword, ip)
	if stepFailed(w, r, err, retry) {
		return
	}
	flow = machine.Get()
	if !flow.State.Final() {
		s.renderSteps(w, r, http.StatusOK, flow, "")
		return
	}
	clearFlowCookie(w)
	if flow.State != loginflow.StateComplete || userID != flow.UserID {
		renderDenied(w, r, http.StatusBadRequest, msgFlowExpired)
		return
	}
	confirmed, err := s.confirmAuth(r, userID)
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: step-up", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgLoginFailed)
		return
	}
	if !confirmed {
		http.Redirect(w, r, s.publicURL.Login(flow.ReturnURL.String()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, flow.ReturnURL.String(), http.StatusSeeOther)
}

// confirmAuth renews AuthAt of the first session of the request that belongs to userID.
// It reports false when the request has no such session.
func (s *service) confirmAuth(r *http.Request, userID users.ID) (bool, error) {
	for _, id := range sessions.IDsFromRequest(r) {
		_, err := s.browser.ConfirmAuth(r.Context(), id, userID)
		if errors.Is(err, sessions.ErrNotFound) {
			continue
		}
		if err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}
