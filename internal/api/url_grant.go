package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/users"
)

// urlAccess decides whether a user may reach the forwarded URL.
// Check returns nil, access.ErrNoResource, access.ErrNoGrant, or a failure.
type urlAccess interface {
	Check(ctx context.Context, user users.ID, userGroups []groups.Name, target access.RequestURL) error
}

// WithURLGrants lets GET /auth/check reach a URL. Without it, every URL is denied with 403.
func WithURLGrants(grants urlAccess) RouterOption {
	return func(s *service) {
		s.grants = grants
	}
}

// noGrants denies every URL. A router without grants fails closed.
type noGrants struct{}

func (noGrants) Check(context.Context, users.ID, []groups.Name, access.RequestURL) error {
	return access.ErrNoResource
}

// urlGranted checks the forwarded URL against the grants of the user and the user's groups, for a session and for a token.
// A missing or refused forwarded URL is denied: there is no URL to grant.
// It writes the 403 or 500 response and returns false when the request MUST stop.
func (s *service) urlGranted(w http.ResponseWriter, r *http.Request, user users.User, userGroups []groups.Name) bool {
	target, err := forwardedRequestURL(r, s)
	if err != nil {
		writeAccessDenied(w, r, s.publicURL.Origin(), user.Login, "")
		return false
	}
	err = s.grants.Check(r.Context(), user.ID, userGroups, target)
	if errors.Is(err, access.ErrNoResource) || errors.Is(err, access.ErrNoGrant) {
		writeAccessDenied(w, r, s.publicURL.Origin(), user.Login, target.String())
		return false
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: auth check", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The check failed.")
		return false
	}
	return true
}

func forwardedRequestURL(r *http.Request, s *service) (access.RequestURL, error) {
	forwarded, ok := forwardedURL(r, s.domain, s.publicURL)
	if !ok || forwarded.uri == "" {
		return access.RequestURL{}, access.ErrRequestURL
	}
	return access.ParseRequestURL(forwarded.proto, forwarded.host, forwarded.uri)
}

// writeAccessDenied names the URL without its query, which can hold a secret.
func writeAccessDenied(w http.ResponseWriter, r *http.Request, origin string, login users.Login, target string) {
	if !browserRequest(r) {
		shown := target
		if shown == "" {
			shown = "the requested URL"
		}
		writeProblem(w, http.StatusForbidden, "The user "+login.String()+" has no access to "+shown+".")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	// Another host serves this page, so the stylesheet and the links name the public origin of miniauth.
	_ = urlDeniedPage(origin, login, target).Render(r.Context(), w)
}
