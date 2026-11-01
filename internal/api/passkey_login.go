package api

import (
	_ "embed"
	"errors"
	"io"
	"net/http"

	"github.com/popoffvg/sfsm"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/providers/passkey"
)

const (
	passkeyLoginPath  = "/login/passkey"
	passkeyScriptPath = "/assets/passkey.js"
	// maxPasskeyBody is large enough for one WebAuthn credential JSON with a name.
	maxPasskeyBody = 64 << 10
)

const (
	msgPasskeyUnavailable = "Passkeys are not available."
	msgPasskeyRefused     = "The passkey was not accepted."
)

//go:embed assets/passkey.js
var passkeyScript []byte

// passkeyOptions documents the reply of an options route: the argument of navigator.credentials.get or create.
type passkeyOptions struct {
	PublicKey map[string]any `json:"publicKey" description:"PublicKeyCredentialRequestOptions or PublicKeyCredentialCreationOptions. Byte fields are base64url."`
}

// passkeyCredential documents the PublicKeyCredential JSON a browser posts. Byte fields are base64url.
type passkeyCredential struct {
	ID       string         `json:"id"`
	RawID    string         `json:"rawId"`
	Type     string         `json:"type" enum:"public-key"`
	Response map[string]any `json:"response"`
}

// passkeyDone is the page the script opens after a ceremony.
type passkeyDone struct {
	Location string `json:"location" format:"uri"`
}

// servePasskeyScript serves the one script of the service.
func servePasskeyScript(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(passkeyScript)
}

// passkeyLoginOptions stores a new challenge on the login flow in the flow cookie.
func (s *service) passkeyLoginOptions(w http.ResponseWriter, r *http.Request) {
	machine, ok := s.openPasskeyLogin(w, r)
	if !ok {
		return
	}
	defer func() { _ = machine.Close() }()
	options, err := s.passkeys.BeginLogin(r.Context(), machine.Get().ID)
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: passkey login options", "err", err)
		writeProblem(w, http.StatusInternalServerError, string(msgLoginFailed))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, options)
}

// passkeyLogin runs the passkey step of the login flow in the flow cookie.
// A passkey with user verification completes the flow alone, so the reply starts a session.
func (s *service) passkeyLogin(w http.ResponseWriter, r *http.Request) {
	machine, ok := s.openPasskeyLogin(w, r)
	if !ok {
		return
	}
	defer func() { _ = machine.Close() }()
	response, ok := readPasskeyBody(w, r)
	if !ok {
		return
	}
	userID, err := s.passkeys.Verify(r.Context(), machine, passkey.AssertionResponse(response))
	switch {
	case errors.Is(err, passkey.ErrClonedAuthenticator):
		loggerFrom(r.Context()).WarnContext(r.Context(), "miniauth: passkey counter did not increase")
		writeProblem(w, http.StatusBadRequest, msgPasskeyRefused)
		return
	case passkeyRefused(err):
		writeProblem(w, http.StatusBadRequest, msgPasskeyRefused)
		return
	case errors.Is(err, sfsm.ErrStaleState), errors.Is(err, loginflow.ErrNoTransition):
		clearFlowCookie(w)
		writeProblem(w, http.StatusBadRequest, string(msgFlowExpired))
		return
	case err != nil:
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: passkey step", "err", err)
		writeProblem(w, http.StatusInternalServerError, string(msgLoginFailed))
		return
	}
	flow := machine.Get()
	clearFlowCookie(w)
	if flow.State != loginflow.StateComplete {
		writeProblem(w, http.StatusBadRequest, string(msgFlowExpired))
		return
	}
	if err := s.startBrowserSession(w, r, userID, flow.Factors); err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: start session", "err", err)
		writeProblem(w, http.StatusInternalServerError, string(msgLoginFailed))
		return
	}
	writeJSON(w, http.StatusOK, passkeyDone{Location: flow.ReturnURL.String()})
}

// openPasskeyLogin checks the origin and opens the login flow of the flow cookie.
// It returns false after it wrote a problem reply.
func (s *service) openPasskeyLogin(w http.ResponseWriter, r *http.Request) (loginMachine, bool) {
	if !s.sameOrigin(r) {
		writeProblem(w, http.StatusForbidden, string(msgCrossOrigin))
		return nil, false
	}
	if s.flows == nil || s.passkeys == nil {
		writeProblem(w, http.StatusServiceUnavailable, msgPasskeyUnavailable)
		return nil, false
	}
	id, secret, err := flowFromRequest(r)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, string(msgFlowExpired))
		return nil, false
	}
	machine, err := s.flows.Open(r.Context(), id, secret)
	if errors.Is(err, loginflow.ErrFlowNotFound) {
		clearFlowCookie(w)
		writeProblem(w, http.StatusBadRequest, string(msgFlowExpired))
		return nil, false
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: open login", "err", err)
		writeProblem(w, http.StatusInternalServerError, string(msgLoginFailed))
		return nil, false
	}
	if machine.Get().Kind != loginflow.KindLogin {
		_ = machine.Close()
		writeProblem(w, http.StatusBadRequest, string(msgFlowExpired))
		return nil, false
	}
	return machine, true
}

// readPasskeyBody reads the JSON body of a ceremony. It returns false after it wrote a problem reply.
func readPasskeyBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if !jsonContentType(r.Header.Get("Content-Type")) {
		writeDecodeError(w, errUnsupportedMedia)
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPasskeyBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeDecodeError(w, errTooLarge)
			return nil, false
		}
		writeDecodeError(w, errBadJSON)
		return nil, false
	}
	return body, true
}

// passkeyRefused reports whether err is a ceremony the user can try again.
// Each case shares one message, so a reply does not tell which credentials exist.
func passkeyRefused(err error) bool {
	return errors.Is(err, passkey.ErrCeremony) ||
		errors.Is(err, loginflow.ErrChallengeNotFound) ||
		errors.Is(err, passkey.ErrUserNotVerified) ||
		errors.Is(err, passkey.ErrUnknownCredential) ||
		errors.Is(err, passkey.ErrDuplicate)
}

// WithPasskeys serves the passkey step and the passkey routes. Without them, those routes answer 503.
func WithPasskeys(passkeys *passkey.Service) RouterOption {
	return func(s *service) {
		s.passkeys = passkeys
	}
}

func (s *service) passkeyOffered() bool {
	return s.passkeys != nil
}
