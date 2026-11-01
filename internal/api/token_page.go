package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

// tokensPath is the token page. The step-up returns here.
const tokensPath = "/tokens"

// maxTokenFormBody is large enough for a name, many scopes, and a date, form-encoded.
const maxTokenFormBody = 64 << 10

// expiryDateLayout is the value of an HTML date input.
const expiryDateLayout = "2006-01-02"

const (
	msgTokensUnavailable pageMessage = "Personal access tokens are not available."
	msgTokenStepUp       pageMessage = "Enter your password again to make a token."
	msgTokenName         pageMessage = "The name must have 1 to 64 characters."
	msgScopeNotValid     pageMessage = "Each scope must be an http or https URL with no query."
	msgExpiryNotValid    pageMessage = "The expiry must be a date in the future."
	msgTokenNotFound     pageMessage = "The token is not found."
	msgTokenFailed       pageMessage = "The token operation failed. Try again."
)

// tokenFormRequest documents the form of POST /tokens.
type tokenFormRequest struct {
	Name    string `formData:"name" required:"true" minLength:"1" maxLength:"64"`
	Scopes  string `formData:"scopes" description:"One URL prefix per line. No line reaches every URL."`
	Expires string `formData:"expires" format:"date" description:"The token works until the end of this UTC day. Empty never expires."`
}

// tokenPageRequest documents the query of GET /tokens.
type tokenPageRequest struct {
	Q      string `query:"q" description:"Shows only the tokens whose name, prefix, or scope contains this text."`
	Status string `query:"status" enum:"active,expired,revoked" description:"Shows only the tokens in this state. Any other value shows every token."`
	Done   string `query:"done" description:"The result of the last change. The page shows a fixed message for a known value and ignores any other value."`
}

// tokenRevokeRequest documents the path of POST /tokens/{id}/revoke.
type tokenRevokeRequest struct {
	ID string `path:"id" format:"uuid"`
}

// tokenPage lists the tokens of the session user, with the form to make one.
func (s *service) tokenPage(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.tokenPageUser(w, r)
	if !ok {
		return
	}
	s.renderTokens(w, r, http.StatusOK, user, "")
}

// createToken makes a token and shows it once.
// An AuthAt older than sessions.StepUpAfter starts a step-up first, and the form is sent again after it.
func (s *service) createToken(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		renderDenied(w, r, http.StatusForbidden, msgCrossOrigin)
		return
	}
	user, session, ok := s.tokenPageUser(w, r)
	if !ok {
		return
	}
	if !s.browser.AuthRecent(session) {
		s.askStepUp(w, r, user, loginflow.ReturnURL(s.publicURL.Origin()+tokensPath), msgTokenStepUp)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenFormBody)
	if r.ParseForm() != nil {
		s.renderTokens(w, r, http.StatusBadRequest, user, msgBadForm)
		return
	}
	name, scopes, expiresAt, message := parseTokenForm(r)
	if message != "" {
		s.renderTokens(w, r, http.StatusBadRequest, user, message)
		return
	}
	secret, _, err := s.tokens.Issue(r.Context(), user.ID, name, scopes, expiresAt)
	switch {
	case errors.Is(err, tokens.ErrName):
		s.renderTokens(w, r, http.StatusBadRequest, user, msgTokenName)
		return
	case errors.Is(err, tokens.ErrScope):
		s.renderTokens(w, r, http.StatusBadRequest, user, msgScopeNotValid)
		return
	case errors.Is(err, tokens.ErrExpiry):
		s.renderTokens(w, r, http.StatusBadRequest, user, msgExpiryNotValid)
		return
	case err != nil:
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: issue token", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgTokenFailed)
		return
	}
	// The clear token is in this body only. It MUST NOT reach a URL, a log, or a cache.
	w.Header().Set("Cache-Control", "no-store")
	renderPage(w, r, http.StatusOK, pageTokenCreated, pageView{Shell: s.shellFor(r, user, tokensPath), NewToken: &secret})
}

// revokeToken revokes one token of the session user. A token of another user is 404.
func (s *service) revokeToken(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		renderDenied(w, r, http.StatusForbidden, msgCrossOrigin)
		return
	}
	user, _, ok := s.tokenPageUser(w, r)
	if !ok {
		return
	}
	id, err := tokens.ParseID(r.PathValue("id"))
	if err == nil {
		err = s.tokens.Revoke(r.Context(), user.ID, id)
	}
	if errors.Is(err, tokens.ErrNotFound) {
		s.renderTokens(w, r, http.StatusNotFound, user, msgTokenNotFound)
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: revoke token", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgTokenFailed)
		return
	}
	http.Redirect(w, r, s.publicURL.Origin()+withDone(tokensPath, doneTokenRevoked), http.StatusSeeOther)
}

// tokenPageUser returns the active user of the browser session for the token page.
// It returns false after it wrote a reply.
func (s *service) tokenPageUser(w http.ResponseWriter, r *http.Request) (users.User, sessions.Session, bool) {
	if s.tokens == nil || s.flows == nil || s.passwords == nil {
		renderDenied(w, r, http.StatusServiceUnavailable, msgTokensUnavailable)
		return users.User{}, sessions.Session{}, false
	}
	return s.browserPageUser(w, r, tokensPath, msgTokenFailed)
}

func (s *service) renderTokens(w http.ResponseWriter, r *http.Request, status int, user users.User, message pageMessage) {
	list, err := s.tokens.List(r.Context(), user.ID)
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: list tokens", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgTokenFailed)
		return
	}
	view := pageView{Shell: s.shellFor(r, user, tokensPath), Message: message, Tokens: newTokenTable(r, list, time.Now())}
	if s.oauth != nil {
		view.ShowApps = true
		view.Apps, err = s.oauth.ListConsents(r.Context(), user.ID)
		if err != nil {
			loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: list connected apps", "err", err)
			renderDenied(w, r, http.StatusInternalServerError, msgTokenFailed)
			return
		}
	}
	if r.Method == http.MethodGet {
		view.Notice = doneNotice(r)
	} else {
		view.TokenForm = refusedTokenForm(r, message)
	}
	renderPage(w, r, status, pageTokens, view)
}

// parseTokenForm returns a message for the first field that is not valid, or an empty message.
func parseTokenForm(r *http.Request) (tokens.Name, tokens.Scopes, time.Time, pageMessage) {
	name, err := tokens.ParseName(r.PostForm.Get("name"))
	if err != nil {
		return tokens.Name{}, nil, time.Time{}, msgTokenName
	}
	var lines []string
	for line := range strings.Lines(r.PostForm.Get("scopes")) {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	scopes, err := tokens.ParseScopes(lines)
	if err != nil {
		return tokens.Name{}, nil, time.Time{}, msgScopeNotValid
	}
	var expiresAt time.Time
	if raw := strings.TrimSpace(r.PostForm.Get("expires")); raw != "" {
		day, err := time.Parse(expiryDateLayout, raw)
		if err != nil {
			return tokens.Name{}, nil, time.Time{}, msgExpiryNotValid
		}
		expiresAt = day.AddDate(0, 0, 1)
	}
	return name, scopes, expiresAt, ""
}
