package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/popoffvg/miniauth/internal/loginflow"
)

// flowCookieName holds the id and the secret of one login flow.
const flowCookieName = "__Host-id_login_flow"

// setFlowCookie writes "<flow id>.<base64url secret>". The secret MUST NOT reach a URL.
func setFlowCookie(w http.ResponseWriter, id loginflow.FlowID, secret loginflow.FlowSecret, now time.Time) {
	raw := secret.Bytes()
	value := id.String() + "." + base64.RawURLEncoding.EncodeToString(raw[:])
	http.SetCookie(w, hostCookie(flowCookieName, value, loginflow.FlowTTL, now))
}

func clearFlowCookie(w http.ResponseWriter) {
	http.SetCookie(w, expiredHostCookie(flowCookieName))
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

type newFlowSecretKey struct{}

// withNewFlowSecret lets the page of the response that sets a new flow cookie read the secret of that flow.
func withNewFlowSecret(r *http.Request, secret loginflow.FlowSecret) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), newFlowSecretKey{}, secret))
}

// flowSecretOf returns the secret of the flow this response shows: a new flow first, else the flow cookie.
func flowSecretOf(r *http.Request) (loginflow.FlowSecret, bool) {
	if secret, ok := r.Context().Value(newFlowSecretKey{}).(loginflow.FlowSecret); ok {
		return secret, true
	}
	_, secret, err := flowFromRequest(r)
	return secret, err == nil
}
