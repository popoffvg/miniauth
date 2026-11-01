package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/identitylink"
	"github.com/popoffvg/miniauth/internal/sessions"
)

func TestLinkPageKeepsTheReturnThroughTheLogin(t *testing.T) {
	s := &service{
		links:     &identitylink.Service{},
		browser:   sessions.NewService(newMemSessions()),
		publicURL: mustPublicURL(t, "https://id.example.test"),
		domain:    mustDomain(t, ".example.test"),
	}
	const target = "https://app.example.test/dash"
	rec := httptest.NewRecorder()
	s.linkPage(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, linkPagePath+"?return="+url.QueryEscape(target), nil))

	require.Equal(t, http.StatusSeeOther, rec.Code)
	login, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	back, err := url.Parse(login.Query().Get("return"))
	require.NoError(t, err)
	assert.Equal(t, linkPagePath, back.Path)
	assert.Equal(t, target, back.Query().Get("return"), "the link page MUST get its return URL back after the login")
}
