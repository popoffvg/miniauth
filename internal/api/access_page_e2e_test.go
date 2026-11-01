package api

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/providers/password"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

var accessRevokeFormPattern = regexp.MustCompile(`action="/access/grants/([0-9a-f-]{36})/revoke"`)

func TestAccessPageEndToEnd(t *testing.T) {
	t.Logf("gofakeit seed %d", fakeSeed+5)
	fake := gofakeit.New(fakeSeed + 5)
	admin := &account{login: fake.Regex(`[a-z][a-z0-9]{7}`), password: fake.Password(true, true, true, true, false, 24)}
	member := &account{login: fake.Regex(`[a-z][a-z0-9]{7}`), password: fake.Password(true, true, true, true, false, 24)}

	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))

	accountRepo := postgres.NewUserRepository(pool)
	accounts := users.NewService(accountRepo)
	for _, a := range []*account{admin, member} {
		login, loginErr := users.ParseLogin(a.login)
		require.NoError(t, loginErr)
		userPassword, passwordErr := users.NewPassword(a.password)
		require.NoError(t, passwordErr)
		user, createErr := accounts.Create(ctx, login, userPassword)
		require.NoError(t, createErr)
		a.id = user.ID
	}
	groupRepo, err := postgres.NewGroupRepository(pool)
	require.NoError(t, err)
	require.NoError(t, groupRepo.Add(ctx, admin.id, groups.Admin()))
	passwords, err := password.NewService(accountRepo, postgres.NewAttemptRepository(pool))
	require.NoError(t, err)
	accessRepo, err := postgres.NewAccessRepository(pool)
	require.NoError(t, err)
	grants := access.NewService(accessRepo, accounts)
	clock := &testClock{now: time.Now()}

	server := httptest.NewUnstartedServer(nil)
	base := "https://" + server.Listener.Addr().String()
	host := server.Listener.Addr().String()
	router, err := NewRouter(
		accounts,
		sessions.NewServiceWithClock(postgres.NewSessionRepository(pool), clock.Now),
		groupRepo,
		sessions.Domain{},
		mustPublicURL(t, base),
		hashToken(t, "bootstrap-token-for-tests"),
		&readyState{ok: true},
		slog.New(slog.DiscardHandler),
		WithLogin(loginflow.NewLoginFlows(postgres.NewFlowStore(pool)), passwords),
		WithURLGrants(grants),
		WithAccessAdmin(grants),
	)
	require.NoError(t, err)
	server.Config.Handler = router
	server.StartTLS()
	t.Cleanup(server.Close)

	adminBrowser := newBrowser(t, server)
	memberBrowser := newBrowser(t, server)
	grantForm := url.Values{"resource": {"app"}, "user": {member.login}}
	var grantID string

	t.Run("no session redirects to the login page with a return URL", func(t *testing.T) {
		resp := get(t, newBrowser(t, server), base+accessPagePath)
		require.Equal(t, http.StatusSeeOther, resp.status)
		assert.Equal(t, base+"/login?return="+url.QueryEscape(base+accessPagePath), resp.header.Get("Location"))
	})

	t.Run("the login of an admin returns to the access page", func(t *testing.T) {
		openLogin(t, adminBrowser, base, base+accessPagePath)
		resp := submitLogin(t, adminBrowser, base, base, admin.login, admin.password)
		require.Equal(t, http.StatusSeeOther, resp.status)
		assert.Equal(t, base+accessPagePath, resp.header.Get("Location"))

		page := get(t, adminBrowser, base+accessPagePath)
		require.Equal(t, http.StatusOK, page.status)
		assert.Contains(t, page.body, `action="/access/resources"`)
		assert.Contains(t, page.body, `action="/access/grants"`)
		assert.Contains(t, page.body, "No resources.")
	})

	t.Run("a user outside the admin group gets 403 on the page and on each POST", func(t *testing.T) {
		openLogin(t, memberBrowser, base, base+accessPagePath)
		login := submitLogin(t, memberBrowser, base, base, member.login, member.password)
		require.Equal(t, http.StatusSeeOther, login.status)

		page := get(t, memberBrowser, base+accessPagePath)
		assert.Equal(t, http.StatusForbidden, page.status)
		assert.Contains(t, page.body, string(msgAccessAdminOnly))
		for _, post := range []struct {
			path string
			form url.Values
		}{
			{path: "/resources", form: url.Values{"name": {"app"}, "url": {base + "/app"}}},
			{path: "/resources/app/delete", form: url.Values{}},
			{path: "/grants", form: grantForm},
			{path: "/grants/" + access.NewGrantID().String() + "/revoke", form: url.Values{}},
		} {
			resp := postForm(t, memberBrowser, base+accessPagePath+post.path, base, post.form)
			assert.Equal(t, http.StatusForbidden, resp.status, post.path)
			assert.Contains(t, resp.body, string(msgAccessAdminOnly), post.path)
		}
		resources, listErr := grants.ListResources(t.Context())
		require.NoError(t, listErr)
		assert.Empty(t, resources)
		assert.Equal(t, http.StatusForbidden, forwardedCheck(t, memberBrowser, base, host, "/app/home").status)
	})

	t.Run("an old login asks for a step-up and changes nothing", func(t *testing.T) {
		clock.Advance(sessions.StepUpAfter + time.Minute)
		resp := postForm(t, adminBrowser, base+accessPagePath+"/resources", base, url.Values{"name": {"app"}, "url": {base + "/app"}})
		require.Equal(t, http.StatusOK, resp.status)
		assert.Contains(t, resp.body, stepUpFormSentinel)
		assert.Contains(t, resp.body, string(msgAccessStepUp))
		resources, listErr := grants.ListResources(t.Context())
		require.NoError(t, listErr)
		assert.Empty(t, resources)
	})

	t.Run("the step-up returns to the access page", func(t *testing.T) {
		resp := submitStepUp(t, adminBrowser, base, "", admin.password)
		require.Equal(t, http.StatusSeeOther, resp.status)
		assert.Equal(t, base+accessPagePath, resp.header.Get("Location"))
	})

	t.Run("the admin adds a resource and grants it to the other user", func(t *testing.T) {
		added := postForm(t, adminBrowser, base+accessPagePath+"/resources", base, url.Values{"name": {"app"}, "url": {base + "/app"}})
		require.Equal(t, http.StatusSeeOther, added.status, added.body)
		assert.Equal(t, base+accessPagePath+"?done=resource-added", added.header.Get("Location"))

		granted := postForm(t, adminBrowser, base+accessPagePath+"/grants", base, grantForm)
		require.Equal(t, http.StatusSeeOther, granted.status, granted.body)
		assert.Equal(t, base+accessPagePath+"?done=granted", granted.header.Get("Location"))

		page := get(t, adminBrowser, granted.header.Get("Location"))
		require.Equal(t, http.StatusOK, page.status)
		assert.Contains(t, page.body, "The access is granted.")
		assert.Contains(t, page.body, host+"/app")
		assert.Contains(t, page.body, member.login)
		assert.Contains(t, page.body, `data-label="Expires"><span class="subtle">Never</span>`)
		matches := accessRevokeFormPattern.FindStringSubmatch(page.body)
		require.Len(t, matches, 2)
		grantID = matches[1]
	})

	t.Run("the other user passes the auth check for the URL", func(t *testing.T) {
		resp := forwardedCheck(t, memberBrowser, base, host, "/app/home")
		assert.Equal(t, http.StatusOK, resp.status)
		assert.Equal(t, member.login, resp.header.Get(headerAuthUser))
	})

	t.Run("a refused change shows the page with the service message", func(t *testing.T) {
		duplicate := postForm(t, adminBrowser, base+accessPagePath+"/grants", base, grantForm)
		assert.Equal(t, http.StatusConflict, duplicate.status)
		assert.Contains(t, duplicate.body, "The grant already exists.")

		unknown := postForm(t, adminBrowser, base+accessPagePath+"/grants", base, url.Values{"resource": {"app"}, "user": {"nobody"}})
		assert.Equal(t, http.StatusNotFound, unknown.status)
		assert.Contains(t, unknown.body, "The user is not found.")

		both := postForm(t, adminBrowser, base+accessPagePath+"/grants", base, url.Values{"resource": {"app"}, "user": {member.login}, "group": {"editors"}})
		assert.Equal(t, http.StatusBadRequest, both.status)
		assert.Contains(t, both.body, "Name exactly one of user and group.")

		past := postForm(t, adminBrowser, base+accessPagePath+"/grants", base, url.Values{"resource": {"app"}, "group": {"editors"}, "expires": {"2000-01-01"}})
		assert.Equal(t, http.StatusBadRequest, past.status)
		assert.Contains(t, past.body, "The expiry MUST be in the future.")

		badURL := postForm(t, adminBrowser, base+accessPagePath+"/resources", base, url.Values{"name": {"other"}, "url": {base + "/x?y=1"}})
		assert.Equal(t, http.StatusBadRequest, badURL.status)
		assert.Contains(t, badURL.body, "no query")
	})

	t.Run("a group grant with an expiry is listed", func(t *testing.T) {
		expires := clock.Now().UTC().Add(48 * time.Hour).Format("2006-01-02T15:04")
		resp := postForm(t, adminBrowser, base+accessPagePath+"/grants", base, url.Values{"resource": {"app"}, "group": {"Editors"}, "expires": {expires}})
		require.Equal(t, http.StatusSeeOther, resp.status, resp.body)
		page := get(t, adminBrowser, base+accessPagePath)
		assert.Contains(t, page.body, `<span class="subtle">Group</span> <code>editors</code>`)
		assert.Contains(t, page.body, `datetime="`+expires+`:00Z"`)
	})

	t.Run("a bad origin is 403 and changes nothing", func(t *testing.T) {
		require.NotEmpty(t, grantID)
		for _, origin := range []string{"", "https://evil.example.test"} {
			revoked := postForm(t, adminBrowser, base+accessPagePath+"/grants/"+grantID+"/revoke", origin, url.Values{})
			assert.Equal(t, http.StatusForbidden, revoked.status, origin)
			deleted := postForm(t, adminBrowser, base+accessPagePath+"/resources/app/delete", origin, url.Values{})
			assert.Equal(t, http.StatusForbidden, deleted.status, origin)
		}
		assert.Equal(t, http.StatusOK, forwardedCheck(t, memberBrowser, base, host, "/app/home").status)
	})

	t.Run("the admin revokes the grant and the next check is 403", func(t *testing.T) {
		require.NotEmpty(t, grantID)
		resp := postForm(t, adminBrowser, base+accessPagePath+"/grants/"+grantID+"/revoke", base, url.Values{})
		require.Equal(t, http.StatusSeeOther, resp.status, resp.body)
		assert.Equal(t, base+accessPagePath+"?done=revoked", resp.header.Get("Location"))

		assert.Equal(t, http.StatusForbidden, forwardedCheck(t, memberBrowser, base, host, "/app/home").status)

		again := postForm(t, adminBrowser, base+accessPagePath+"/grants/"+grantID+"/revoke", base, url.Values{})
		assert.Equal(t, http.StatusNotFound, again.status)
		assert.Contains(t, again.body, "The grant is not found.")
	})

	t.Run("the admin deletes the resource", func(t *testing.T) {
		resp := postForm(t, adminBrowser, base+accessPagePath+"/resources/app/delete", base, url.Values{})
		require.Equal(t, http.StatusSeeOther, resp.status, resp.body)
		assert.Equal(t, base+accessPagePath+"?done=resource-deleted", resp.header.Get("Location"))
		page := get(t, adminBrowser, base+accessPagePath)
		assert.Contains(t, page.body, "No resources.")
		entries, listErr := grants.ListGrants(t.Context(), access.GrantFilter{})
		require.NoError(t, listErr)
		assert.Empty(t, entries)
	})
}
