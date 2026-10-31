package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/popoffvg/miniauth/internal/sessions"
)

func TestRequestIDRefusesAnIDThatContainsACredential(t *testing.T) {
	const flowID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	const flowSecret = "c2VjcmV0LW9mLXRoZS1sb2dpbi1mbG93LWZvci10ZXN0cw"
	const session = "session-cookie-value-for-tests"
	const bearer = "bearer-token-value-for-tests"
	tests := []struct {
		name string
		id   string
		keep bool
	}{
		{name: "a plain id", id: "req-42", keep: true},
		{name: "the flow secret alone", id: flowSecret},
		{name: "the flow cookie after a prefix", id: "req-" + flowID + "." + flowSecret},
		{name: "the session cookie after a prefix", id: "req-" + session},
		{name: "the bearer token after a prefix", id: "req-" + bearer},
		{name: "the token marker after a prefix", id: "req-idp_0123456789"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			r.AddCookie(&http.Cookie{Name: flowCookieName, Value: flowID + "." + flowSecret})
			r.AddCookie(&http.Cookie{Name: sessions.CookieName, Value: session})
			r.Header.Set("Authorization", "Bearer "+bearer)
			r.Header.Set("X-Request-ID", tt.id)
			assert.Equal(t, tt.keep, requestID(r) == tt.id)
		})
	}
}
