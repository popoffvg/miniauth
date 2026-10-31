package api

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/popoffvg/miniauth/internal/loginflow"
)

// flowCookieName holds the id and the secret of one login flow.
// The __Host- prefix requires Secure, Path=/, and no Domain, so a subdomain cannot set it.
const flowCookieName = "__Host-id_login_flow"

const flowCookieSeconds = int(loginflow.FlowTTL / time.Second)

// setFlowCookie writes "<flow id>.<base64url secret>". The secret MUST NOT reach a URL.
func setFlowCookie(w http.ResponseWriter, id loginflow.FlowID, secret loginflow.FlowSecret, now time.Time) {
	raw := secret.Bytes()
	http.SetCookie(w, &http.Cookie{
		Name:     flowCookieName,
		Value:    id.String() + "." + base64.RawURLEncoding.EncodeToString(raw[:]),
		Path:     "/",
		MaxAge:   flowCookieSeconds,
		Expires:  now.UTC().Add(loginflow.FlowTTL),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearFlowCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     flowCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// flowFromRequest reads the flow cookie. A missing or malformed cookie is loginflow.ErrFlowNotFound.
// The error MUST NOT contain the cookie value.
func flowFromRequest(r *http.Request) (loginflow.FlowID, loginflow.FlowSecret, error) {
	cookie, err := r.Cookie(flowCookieName)
	if err != nil {
		return "", loginflow.FlowSecret{}, loginflow.ErrFlowNotFound
	}
	rawID, rawSecret, ok := strings.Cut(cookie.Value, ".")
	if !ok {
		return "", loginflow.FlowSecret{}, loginflow.ErrFlowNotFound
	}
	id, err := loginflow.ParseFlowID(rawID)
	if err != nil {
		return "", loginflow.FlowSecret{}, loginflow.ErrFlowNotFound
	}
	decoded, err := base64.RawURLEncoding.DecodeString(rawSecret)
	if err != nil {
		return "", loginflow.FlowSecret{}, loginflow.ErrFlowNotFound
	}
	secret, err := loginflow.ParseFlowSecret(decoded)
	clear(decoded)
	if err != nil {
		return "", loginflow.FlowSecret{}, loginflow.ErrFlowNotFound
	}
	return id, secret, nil
}
