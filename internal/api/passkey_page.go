package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/providers/passkey"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
	"github.com/popoffvg/miniauth/internal/views"
)

// passkeysPath is where a signed-in user adds a passkey. The step-up returns to passkeyNewPath.
const (
	passkeysPath   = views.PasskeysPath
	passkeyNewPath = views.PasskeyNewPath
)

const (
	msgPasskeyStepUp   views.Message = "Enter your password again to change your passkeys."
	msgPasskeyNotFound views.Message = "The passkey is not found."
	msgPasskeyFailed   views.Message = "The passkey operation failed. Try again."
	msgPasskeyName                   = "The name must have 1 to 64 characters."
	msgPasskeyNoStepUp               = "Your sign-in is too old. Open the page again and confirm your password."
	msgPasskeyTaken                  = "This passkey is already stored."
	msgSessionNotValid               = "The session is not valid."
)

// passkeyAddRequest is the body of POST /passkeys.
type passkeyAddRequest struct {
	Name       string            `json:"name" required:"true" minLength:"1" maxLength:"64"`
	Credential passkeyCredential `json:"credential" required:"true"`
}

// passkeyAddBody reads the credential as raw JSON for the webauthn parser.
type passkeyAddBody struct {
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
}

// passkeyDeleteRequest documents the path of POST /passkeys/{id}/delete.
type passkeyDeleteRequest struct {
	ID string `path:"id" format:"uuid"`
}

// passkeyNewPage shows the form that adds a passkey.
// An AuthAt older than sessions.StepUpAfter asks for the password first and returns here.
func (s *service) passkeyNewPage(w http.ResponseWriter, r *http.Request) {
	if s.passkeys == nil || s.flows == nil || s.passwords == nil {
		renderDenied(w, r, http.StatusServiceUnavailable, msgPasskeyUnavailable)
		return
	}
	user, session, ok := s.browserPageUser(w, r, passkeyNewPath, msgPasskeyFailed)
	if !ok {
		return
	}
	if !s.browser.AuthRecent(session) {
		s.askStepUp(w, r, user, loginflow.ReturnURL(s.publicURL.Origin()+passkeyNewPath), msgPasskeyStepUp)
		return
	}
	renderPage(w, r, http.StatusOK, views.PageAddKey, views.Page{Shell: s.shellFor(r, user, sessionsPagePath), Script: true})
}

// passkeyAddOptions starts a step-up flow of the session user that carries the registration challenge.
// The flow is never completed by a factor: POST /passkeys cancels it.
func (s *service) passkeyAddOptions(w http.ResponseWriter, r *http.Request) {
	user, ok := s.passkeyOwner(w, r)
	if !ok {
		return
	}
	id, secret, err := s.flows.StartStepUp(r.Context(), user.ID, loginflow.ReturnURL(s.publicURL.Origin()+sessionsPagePath))
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: passkey options", "err", err)
		writeProblem(w, http.StatusInternalServerError, string(msgPasskeyFailed))
		return
	}
	options, err := s.passkeys.BeginRegistration(r.Context(), id, user)
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: passkey options", "err", err)
		writeProblem(w, http.StatusInternalServerError, string(msgPasskeyFailed))
		return
	}
	setFlowCookie(w, id, secret, time.Now())
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, options)
}

// passkeyAdd checks the new credential against the challenge of the flow cookie and stores it.
func (s *service) passkeyAdd(w http.ResponseWriter, r *http.Request) {
	user, ok := s.passkeyOwner(w, r)
	if !ok {
		return
	}
	body, err := decodeJSON[passkeyAddBody](w, r, maxPasskeyBody)
	if err != nil {
		writeDecodeError(w, err)
		return
	}
	name, err := passkey.ParseName(body.Name)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, msgPasskeyName)
		return
	}
	id, secret, err := flowFromRequest(r)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, string(msgFlowExpired))
		return
	}
	machine, err := s.flows.Open(r.Context(), id, secret)
	if errors.Is(err, loginflow.ErrFlowNotFound) {
		clearFlowCookie(w)
		writeProblem(w, http.StatusBadRequest, string(msgFlowExpired))
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: passkey add", "err", err)
		writeProblem(w, http.StatusInternalServerError, string(msgPasskeyFailed))
		return
	}
	defer func() { _ = machine.Close() }()
	flow := machine.Get()
	if flow.Kind != loginflow.KindStepUp || flow.UserID != user.ID {
		writeProblem(w, http.StatusBadRequest, string(msgFlowExpired))
		return
	}
	_, err = s.passkeys.Register(r.Context(), flow.ID, user, name, passkey.AttestationResponse(body.Credential))
	switch {
	case errors.Is(err, passkey.ErrDuplicate):
		writeProblem(w, http.StatusConflict, msgPasskeyTaken)
		return
	case passkeyRefused(err):
		writeProblem(w, http.StatusBadRequest, msgPasskeyRefused)
		return
	case err != nil:
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: passkey add", "err", err)
		writeProblem(w, http.StatusInternalServerError, string(msgPasskeyFailed))
		return
	}
	if err := machine.Apply(r.Context(), loginflow.Event{Kind: loginflow.EventCancel}); err != nil {
		loggerFrom(r.Context()).WarnContext(r.Context(), "miniauth: cancel passkey flow", "err", err)
	}
	clearFlowCookie(w)
	writeJSON(w, http.StatusCreated, passkeyDone{Location: s.publicURL.Origin() + sessionsPagePath})
}

// passkeyOwner is the session user of a JSON ceremony route whose login is newer than sessions.StepUpAfter.
// It returns false after it wrote a problem reply.
func (s *service) passkeyOwner(w http.ResponseWriter, r *http.Request) (users.User, bool) {
	if !s.sameOrigin(r) {
		writeProblem(w, http.StatusForbidden, string(msgCrossOrigin))
		return users.User{}, false
	}
	if s.passkeys == nil || s.flows == nil {
		writeProblem(w, http.StatusServiceUnavailable, msgPasskeyUnavailable)
		return users.User{}, false
	}
	session, err := s.openBrowserSession(r)
	if errors.Is(err, sessions.ErrNotFound) {
		writeProblem(w, http.StatusUnauthorized, msgSessionNotValid)
		return users.User{}, false
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: passkey owner", "err", err)
		writeProblem(w, http.StatusInternalServerError, string(msgPasskeyFailed))
		return users.User{}, false
	}
	user, err := s.accounts.Find(r.Context(), session.UserID)
	if errors.Is(err, users.ErrNotFound) || err == nil && user.Disabled() {
		writeProblem(w, http.StatusUnauthorized, msgSessionNotValid)
		return users.User{}, false
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: passkey owner", "err", err)
		writeProblem(w, http.StatusInternalServerError, string(msgPasskeyFailed))
		return users.User{}, false
	}
	if !s.browser.AuthRecent(session) {
		writeProblem(w, http.StatusForbidden, msgPasskeyNoStepUp)
		return users.User{}, false
	}
	return user, true
}

// deletePasskey removes one passkey of the session user and redirects to the sessions page.
// A login older than sessions.StepUpAfter asks for the password first. A passkey of another user is 404.
func (s *service) deletePasskey(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		renderDenied(w, r, http.StatusForbidden, msgCrossOrigin)
		return
	}
	if s.passkeys == nil || s.flows == nil || s.passwords == nil {
		renderDenied(w, r, http.StatusServiceUnavailable, msgPasskeyUnavailable)
		return
	}
	user, session, ok := s.browserPageUser(w, r, sessionsPagePath, msgPasskeyFailed)
	if !ok {
		return
	}
	if !s.browser.AuthRecent(session) {
		s.askStepUp(w, r, user, loginflow.ReturnURL(s.publicURL.Origin()+sessionsPagePath), msgPasskeyStepUp)
		return
	}
	id, err := passkey.ParseID(r.PathValue("id"))
	if err == nil {
		err = s.passkeys.Delete(r.Context(), user.ID, id)
	}
	if errors.Is(err, passkey.ErrNotFound) {
		renderDenied(w, r, http.StatusNotFound, msgPasskeyNotFound)
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: delete passkey", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgPasskeyFailed)
		return
	}
	http.Redirect(w, r, s.publicURL.Origin()+withDone(sessionsPagePath, donePasskeyDeleted), http.StatusSeeOther)
}
