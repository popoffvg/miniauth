package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

// RouterOption changes one optional part of the router.
type RouterOption func(*service)

// WithAccessTokens lets GET /auth/check accept "Authorization: Bearer idp_...".
// Without it, every such token is answered 401.
func WithAccessTokens(access *tokens.Service) RouterOption {
	return func(s *service) {
		s.tokens = access
	}
}

// accessTokenBearer returns the bearer token when it has the access token marker.
// Another bearer token is not an access token, so the session check answers it.
func accessTokenBearer(r *http.Request) (BearerToken, bool) {
	bearer, ok := bearerToken(r)
	if !ok || !strings.HasPrefix(bearer.raw, tokens.SecretMarker) {
		return BearerToken{}, false
	}
	return bearer, true
}

// forwardAuthToken checks a personal access token.
// A bad token or a disabled owner is 401. A URL under no scope is 403.
func (s *service) forwardAuthToken(w http.ResponseWriter, r *http.Request, need []groups.Name, bearer BearerToken) {
	if s.tokens == nil {
		invalidToken(w)
		return
	}
	secret, err := tokens.ParseSecret(bearer.raw)
	if err != nil {
		invalidToken(w)
		return
	}
	token, err := s.tokens.Authenticate(r.Context(), secret)
	if errors.Is(err, tokens.ErrInvalid) {
		invalidToken(w)
		return
	}
	if err != nil {
		authCheckFailed(w, r, err)
		return
	}
	user, err := s.accounts.Find(r.Context(), token.UserID)
	if errors.Is(err, users.ErrNotFound) || err == nil && user.Disabled() {
		invalidToken(w)
		return
	}
	if err != nil {
		authCheckFailed(w, r, err)
		return
	}
	if !token.Scopes.Unlimited() {
		target, ok := forwardedTarget(r)
		if !ok || !token.Scopes.Covers(target) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}
	have, err := s.groups.List(r.Context(), user.ID)
	if err != nil {
		authCheckFailed(w, r, err)
		return
	}
	if !hasGroups(have, need) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !writeAuthHeaders(w, user.Login, have, sessions.MethodAccessToken()) {
		authCheckFailed(w, r, errors.New("api: auth header is not safe"))
		return
	}
	w.WriteHeader(http.StatusOK)
}

// forwardedTarget is the URL from X-Forwarded-Proto, X-Forwarded-Host, and X-Forwarded-Uri.
func forwardedTarget(r *http.Request) (tokens.Target, bool) {
	proto := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" || strings.ContainsAny(host, "\r\n/\\@ ?#") {
		return tokens.Target{}, false
	}
	if _, ok := forwardedHostname(host); !ok {
		return tokens.Target{}, false
	}
	uri := r.Header.Get("X-Forwarded-Uri")
	if uri == "" {
		uri = "/"
	}
	if !safeForwardedURI(uri) {
		return tokens.Target{}, false
	}
	target, err := tokens.ParseTarget(proto + "://" + host + uri)
	if err != nil {
		return tokens.Target{}, false
	}
	return target, true
}

func invalidToken(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	w.WriteHeader(http.StatusUnauthorized)
}

func authCheckFailed(w http.ResponseWriter, r *http.Request, err error) {
	loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: auth check", "err", err)
	writeProblem(w, http.StatusInternalServerError, "The check failed.")
}
