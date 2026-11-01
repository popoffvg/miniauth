package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/users"
	"github.com/popoffvg/miniauth/internal/views"
)

func TestShellHidesTheItemOfAServiceThatIsOff(t *testing.T) {
	s := &service{groups: newMemGroups()}
	user := users.User{ID: users.NewID(), Login: mustLogin(t, "ada"), CreatedAt: time.Now()}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/sessions", nil)
	var page strings.Builder
	require.NoError(t, views.SecurityPage(views.SecurityView{Shell: s.shellFor(req, user, sessionsPagePath)}).Render(t.Context(), &page))
	assert.NotContains(t, page.String(), `href="`+tokensPath+`"`, "the token service is off")
	assert.Contains(t, page.String(), `href="`+sessionsPagePath+`"`)
}
