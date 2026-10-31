package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/popoffvg/sfsm"

	"github.com/popoffvg/miniauth/internal/googlestep"
	"github.com/popoffvg/miniauth/internal/identitylink"
	"github.com/popoffvg/miniauth/internal/loginflow"
)

const (
	googleLoginPath = "/login/google"
	// GoogleCallbackPath is the path of the Google redirect URL. The OAuth client MUST list
	// MINIAUTH_PUBLIC_URL + GoogleCallbackPath as an allowed redirect URI.
	GoogleCallbackPath = "/login/google/callback"
	// googleVerifierCookieName holds the PKCE verifier between the redirect and the callback.
	googleVerifierCookieName = "__Host-id_google_verifier"
)

// googleCallbackRequest documents the query of GET /login/google/callback.
type googleCallbackRequest struct {
	Code  string `query:"code" description:"The authorization code from Google."`
	State string `query:"state" description:"The state that POST /login/google sent to Google."`
}

// WithGoogle offers the Google step on the login page while the step is available.
// links keeps an unknown Google account until a password login in the same browser.
func WithGoogle(step *googlestep.Step, links *identitylink.Service) RouterOption {
	return func(s *service) {
		s.google = step
		s.links = links
	}
}

func (s *service) googleOffered() bool {
	return s.google != nil && s.links != nil && s.google.Available()
}

// googleLogin stores the challenge of the flow in the flow cookie and redirects to Google.
func (s *service) googleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		renderDenied(w, r, http.StatusForbidden, msgCrossOrigin)
		return
	}
	if s.flows == nil || !s.googleOffered() {
		renderDenied(w, r, http.StatusServiceUnavailable, msgGoogleUnavailable)
		return
	}
	id, secret, err := flowFromRequest(r)
	if err != nil {
		renderDenied(w, r, http.StatusBadRequest, msgFlowExpired)
		return
	}
	machine, err := s.flows.Open(r.Context(), id, secret)
	if errors.Is(err, loginflow.ErrFlowNotFound) {
		clearFlowCookie(w)
		renderDenied(w, r, http.StatusBadRequest, msgFlowExpired)
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: open login", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgLoginFailed)
		return
	}
	_ = machine.Close()
	authURL, verifier, err := s.google.Begin(r.Context(), id)
	switch {
	case errors.Is(err, loginflow.ErrFlowNotFound):
		clearFlowCookie(w)
		renderDenied(w, r, http.StatusBadRequest, msgFlowExpired)
		return
	case errors.Is(err, googlestep.ErrUnavailable):
		renderDenied(w, r, http.StatusServiceUnavailable, msgGoogleUnavailable)
		return
	case err != nil:
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: google step", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgLoginFailed)
		return
	}
	http.SetCookie(w, hostCookie(googleVerifierCookieName, verifier.CookieValue(), loginflow.FlowTTL, time.Now()))
	http.Redirect(w, r, string(authURL), http.StatusSeeOther)
}

// googleCallback checks the Google reply for the flow in the flow cookie.
// A linked account completes the step. An unknown account starts no session: it becomes a pending link.
func (s *service) googleCallback(w http.ResponseWriter, r *http.Request) {
	if s.flows == nil || s.google == nil || s.links == nil {
		renderDenied(w, r, http.StatusServiceUnavailable, msgGoogleUnavailable)
		return
	}
	id, secret, err := flowFromRequest(r)
	if err != nil {
		renderDenied(w, r, http.StatusBadRequest, msgFlowExpired)
		return
	}
	verifier, err := googleVerifierFromRequest(r)
	http.SetCookie(w, expiredHostCookie(googleVerifierCookieName))
	if err != nil {
		renderDenied(w, r, http.StatusBadRequest, msgGoogleFailed)
		return
	}
	machine, err := s.flows.Open(r.Context(), id, secret)
	if errors.Is(err, loginflow.ErrFlowNotFound) {
		clearFlowCookie(w)
		renderDenied(w, r, http.StatusBadRequest, msgFlowExpired)
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: open login", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgLoginFailed)
		return
	}
	defer func() { _ = machine.Close() }()

	query := r.URL.Query()
	outcome, err := s.google.Finish(r.Context(), machine, id, verifier, googlestep.State(query.Get("state")), googlestep.Code(query.Get("code")))
	switch {
	case errors.Is(err, googlestep.ErrBadCallback), errors.Is(err, googlestep.ErrBadToken):
		s.renderSteps(w, r, http.StatusBadRequest, machine.Get().Factors, msgGoogleFailed)
		return
	case errors.Is(err, googlestep.ErrUnavailable):
		renderDenied(w, r, http.StatusServiceUnavailable, msgGoogleUnavailable)
		return
	case errors.Is(err, sfsm.ErrStaleState), errors.Is(err, loginflow.ErrNoTransition):
		clearFlowCookie(w)
		renderDenied(w, r, http.StatusBadRequest, msgFlowExpired)
		return
	case err != nil:
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: google step", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgLoginFailed)
		return
	}
	if !outcome.Linked() {
		s.rememberPendingLink(w, r, outcome.Unlinked, machine.Get().Factors, msgLinkGoogle)
		return
	}
	s.finishStep(w, r, outcome.UserID, machine.Get())
}

// googleVerifierFromRequest reads the verifier cookie. The error MUST NOT contain the cookie value.
func googleVerifierFromRequest(r *http.Request) (googlestep.Verifier, error) {
	cookie, err := r.Cookie(googleVerifierCookieName)
	if err != nil {
		return googlestep.Verifier{}, googlestep.ErrBadCallback
	}
	return googlestep.ParseVerifier(cookie.Value)
}
