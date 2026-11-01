package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groupadmin"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/invites"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/providers/password"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/useradmin"
	"github.com/popoffvg/miniauth/internal/users"
)

const usersAdminToken = "bootstrap-token-for-tests"

// adminCall sends one users admin API request with the bootstrap token, or with no token when token is empty.
func adminCall(t *testing.T, client *http.Client, method, target, token string) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, target, nil)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return do(t, client, req)
}

func TestUsersAdminEndToEnd(t *testing.T) {
	pool, err := postgres.Open(t.Context(), postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(t.Context(), pool))

	accountRepo := postgres.NewUserRepository(pool)
	accounts := users.NewService(accountRepo)
	admin := &account{login: "ada", password: "ada-password-for-tests"}
	bob := &account{login: "bob", password: "bob-password-for-tests"}
	carol := &account{login: "carol", password: "carol-password-for-tests"}
	for _, a := range []*account{admin, bob, carol} {
		login, loginErr := users.ParseLogin(a.login)
		require.NoError(t, loginErr)
		userPassword, passwordErr := users.NewPassword(a.password)
		require.NoError(t, passwordErr)
		user, createErr := accounts.Create(t.Context(), login, userPassword)
		require.NoError(t, createErr)
		a.id = user.ID
	}
	groupRepo, err := postgres.NewGroupRepository(pool)
	require.NoError(t, err)
	require.NoError(t, groupRepo.Add(t.Context(), admin.id, groups.Admins()))
	groupStore, err := postgres.NewGroupAdminRepository(pool)
	require.NoError(t, err)
	editors, err := groups.ParseName("editors")
	require.NoError(t, err)
	require.NoError(t, groupStore.CreateGroup(t.Context(), editors, time.Now()))
	passwords, err := password.NewService(accountRepo, postgres.NewAttemptRepository(pool))
	require.NoError(t, err)
	accessRepo, err := postgres.NewAccessRepository(pool)
	require.NoError(t, err)
	grants := access.NewService(accessRepo, accounts)
	inviteRepo, err := postgres.NewInviteRepository(pool)
	require.NoError(t, err)
	inviteService, err := invites.NewService(inviteRepo, nil, nil)
	require.NoError(t, err)
	adminRepo, err := postgres.NewUserAdminRepository(pool)
	require.NoError(t, err)
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
		hashToken(t, usersAdminToken),
		&readyState{ok: true},
		slog.New(slog.DiscardHandler),
		WithLogin(loginflow.NewLoginFlows(postgres.NewFlowStore(pool)), passwords),
		WithURLGrants(grants),
		WithAccessAdmin(grants),
		WithInvites(inviteService),
		WithUserAdmin(useradmin.NewService(adminRepo, accounts)),
		WithGroupAdmin(mustGroupAdmin(t, groupStore, grants)),
	)
	require.NoError(t, err)
	server.Config.Handler = router
	server.StartTLS()
	t.Cleanup(server.Close)
	client := server.Client()

	appName, err := access.ParseResourceName("app")
	require.NoError(t, err)
	appURL, err := access.ParseResourceURL(base + "/app")
	require.NoError(t, err)
	_, err = grants.CreateResource(t.Context(), appName, appURL)
	require.NoError(t, err)
	bobLogin, err := users.ParseLogin(bob.login)
	require.NoError(t, err)
	_, err = grants.GrantTo(t.Context(), appName, access.Grantee{User: bobLogin}, access.Expiry{})
	require.NoError(t, err)

	signIn := func(t *testing.T, a *account, returnTo string) *http.Client {
		t.Helper()
		browser := newBrowser(t, server)
		openLogin(t, browser, base, returnTo)
		require.Equal(t, http.StatusSeeOther, submitLogin(t, browser, base, base, a.login, a.password).status)
		return browser
	}
	adminBrowser := signIn(t, admin, base+usersPagePath)
	bobBrowser := signIn(t, bob, base+"/")

	t.Run("the API needs the admin token", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, adminCall(t, client, http.MethodGet, base+"/api/v1/users", "").status)
		assert.Equal(t, http.StatusUnauthorized, adminCall(t, client, http.MethodPost, base+"/api/v1/users/bob/disable", "").status)
		assert.Equal(t, http.StatusUnauthorized, adminCall(t, client, http.MethodPut, base+"/api/v1/groups/editors/members/bob", "").status)
	})

	t.Run("the API lists the users with their groups", func(t *testing.T) {
		resp := adminCall(t, client, http.MethodGet, base+"/api/v1/users", usersAdminToken)
		require.Equal(t, http.StatusOK, resp.status, resp.body)
		var body struct {
			Users []struct {
				Login    string   `json:"login"`
				Groups   []string `json:"groups"`
				Disabled bool     `json:"disabled"`
				Devices  int      `json:"devices"`
			} `json:"users"`
		}
		require.NoError(t, json.Unmarshal([]byte(resp.body), &body))
		require.Len(t, body.Users, 3)
		assert.Equal(t, "ada", body.Users[0].Login)
		assert.Equal(t, []string{"admins", "users"}, body.Users[0].Groups)
		assert.Equal(t, []string{"users"}, body.Users[2].Groups)
		assert.Equal(t, 1, body.Users[1].Devices)
		assert.False(t, body.Users[1].Disabled)
	})

	t.Run("the API changes membership", func(t *testing.T) {
		for range 2 {
			assert.Equal(t, http.StatusNoContent, adminCall(t, client, http.MethodPut, base+"/api/v1/groups/editors/members/bob", usersAdminToken).status)
		}
		names, listErr := groupRepo.List(t.Context(), bob.id)
		require.NoError(t, listErr)
		assert.Equal(t, []groups.Name{editors, groups.Users()}, names)
		assert.Equal(t, http.StatusNoContent, adminCall(t, client, http.MethodDelete, base+"/api/v1/groups/editors/members/bob", usersAdminToken).status)
		assert.Equal(t, http.StatusNotFound, adminCall(t, client, http.MethodDelete, base+"/api/v1/groups/editors/members/bob", usersAdminToken).status)
		assert.Equal(t, http.StatusNotFound, adminCall(t, client, http.MethodPut, base+"/api/v1/groups/editors/members/nobody", usersAdminToken).status)
		assert.Equal(t, http.StatusNotFound, adminCall(t, client, http.MethodPut, base+"/api/v1/groups/ghosts/members/bob", usersAdminToken).status)
		assert.Equal(t, http.StatusBadRequest, adminCall(t, client, http.MethodPut, base+"/api/v1/groups/-bad-/members/bob", usersAdminToken).status)
		assert.Equal(t, http.StatusNotFound, adminCall(t, client, http.MethodPost, base+"/api/v1/users/nobody/enable", usersAdminToken).status)
	})

	t.Run("the API disables and enables a user", func(t *testing.T) {
		probe := signIn(t, bob, base+"/")
		require.Equal(t, http.StatusOK, forwardedCheck(t, probe, base, host, "/app/home").status)
		assert.Equal(t, http.StatusNoContent, adminCall(t, client, http.MethodPost, base+"/api/v1/users/bob/disable", usersAdminToken).status)
		assert.NotEqual(t, http.StatusOK, forwardedCheck(t, probe, base, host, "/app/home").status)
		assert.Equal(t, http.StatusNoContent, adminCall(t, client, http.MethodPost, base+"/api/v1/users/bob/enable", usersAdminToken).status)
		bobBrowser = signIn(t, bob, base+"/")
	})

	t.Run("a user outside the admins group gets 403 on the page and on each POST", func(t *testing.T) {
		page := get(t, bobBrowser, base+usersPagePath)
		assert.Equal(t, http.StatusForbidden, page.status)
		assert.Contains(t, page.body, string(msgUsersAdminOnly))
		for _, path := range []string{"/carol/disable", "/carol/enable", "/carol/groups", "/ada/groups/admins/remove", "/invites"} {
			resp := postForm(t, bobBrowser, base+usersPagePath+path, base, url.Values{"group": {"admins"}})
			assert.Equal(t, http.StatusForbidden, resp.status, path)
		}
		names, listErr := groupRepo.List(t.Context(), carol.id)
		require.NoError(t, listErr)
		assert.Equal(t, []groups.Name{groups.Users()}, names)
	})

	t.Run("the admin page lists the users", func(t *testing.T) {
		page := get(t, adminBrowser, base+usersPagePath)
		require.Equal(t, http.StatusOK, page.status)
		for _, a := range []*account{admin, bob, carol} {
			assert.Contains(t, page.body, `action="/users/`+a.login+`/groups"`)
		}
		assert.NotContains(t, page.body, `action="/users/ada/disable"`, "the page offers no self disable")
		assert.NotContains(t, page.body, `action="/users/ada/groups/admins/remove"`, "the page offers no self admin removal")
		filtered := get(t, adminBrowser, base+usersPagePath+"?q=car")
		assert.Contains(t, filtered.body, `action="/users/carol/groups"`)
		assert.NotContains(t, filtered.body, `action="/users/bob/groups"`)
	})

	t.Run("a bad origin is 403 and changes nothing", func(t *testing.T) {
		for _, origin := range []string{"", "https://evil.example.test"} {
			resp := postForm(t, adminBrowser, base+usersPagePath+"/bob/disable", origin, url.Values{})
			assert.Equal(t, http.StatusForbidden, resp.status, origin)
		}
		assert.Equal(t, http.StatusOK, forwardedCheck(t, bobBrowser, base, host, "/app/home").status)
	})

	t.Run("an old login asks for a step-up and changes nothing", func(t *testing.T) {
		clock.Advance(sessions.StepUpAfter + time.Minute)
		resp := postForm(t, adminBrowser, base+usersPagePath+"/bob/disable", base, url.Values{})
		require.Equal(t, http.StatusOK, resp.status)
		assert.Contains(t, resp.body, stepUpFormSentinel)
		assert.Contains(t, resp.body, string(msgUsersStepUp))
		up := submitStepUp(t, adminBrowser, base, "", admin.password)
		require.Equal(t, http.StatusSeeOther, up.status)
		assert.Equal(t, base+usersPagePath, up.header.Get("Location"))
		assert.Equal(t, http.StatusOK, forwardedCheck(t, bobBrowser, base, host, "/app/home").status)
	})

	t.Run("the admin disables bob and his next check is refused", func(t *testing.T) {
		resp := postForm(t, adminBrowser, base+usersPagePath+"/bob/disable", base, url.Values{})
		require.Equal(t, http.StatusSeeOther, resp.status, resp.body)
		assert.Equal(t, base+withDone(usersPagePath, doneUserDisabled), resp.header.Get("Location"))
		assert.NotEqual(t, http.StatusOK, forwardedCheck(t, bobBrowser, base, host, "/app/home").status)
		assert.Contains(t, get(t, adminBrowser, resp.header.Get("Location")).body, "The user is disabled and signed out everywhere.")
		page := get(t, adminBrowser, base+usersPagePath+"?status=disabled")
		assert.Contains(t, page.body, `action="/users/bob/enable"`)
		assert.NotContains(t, page.body, `action="/users/carol/groups"`)

		enabled := postForm(t, adminBrowser, base+usersPagePath+"/bob/enable", base, url.Values{})
		require.Equal(t, http.StatusSeeOther, enabled.status, enabled.body)
		assert.Equal(t, base+withDone(usersPagePath, doneUserEnabled), enabled.header.Get("Location"))
	})

	t.Run("the admin cannot disable itself or leave the admins group", func(t *testing.T) {
		self := postForm(t, adminBrowser, base+usersPagePath+"/ada/disable", base, url.Values{})
		assert.Equal(t, http.StatusConflict, self.status)
		assert.Contains(t, self.body, "You cannot disable your own account.")
		leave := postForm(t, adminBrowser, base+usersPagePath+"/ada/groups/admins/remove", base, url.Values{})
		assert.Equal(t, http.StatusConflict, leave.status)
		assert.Contains(t, leave.body, "You cannot remove yourself from the admins group.")
		names, listErr := groupRepo.List(t.Context(), admin.id)
		require.NoError(t, listErr)
		assert.Equal(t, []groups.Name{groups.Admins(), groups.Users()}, names)
	})

	t.Run("the admin adds carol to admin and carol opens the access page", func(t *testing.T) {
		carolBrowser := signIn(t, carol, base+"/")
		assert.Equal(t, http.StatusForbidden, get(t, carolBrowser, base+accessPagePath).status)
		resp := postForm(t, adminBrowser, base+usersPagePath+"/carol/groups", base, url.Values{"group": {"Admins"}})
		require.Equal(t, http.StatusSeeOther, resp.status, resp.body)
		assert.Equal(t, base+withDone(usersPagePath, doneMemberAdded), resp.header.Get("Location"))
		assert.Equal(t, http.StatusOK, get(t, carolBrowser, base+accessPagePath).status)

		removed := postForm(t, adminBrowser, base+usersPagePath+"/carol/groups/admins/remove", base, url.Values{})
		require.Equal(t, http.StatusSeeOther, removed.status, removed.body)
		assert.Equal(t, http.StatusForbidden, get(t, carolBrowser, base+accessPagePath).status)
		again := postForm(t, adminBrowser, base+usersPagePath+"/carol/groups/admins/remove", base, url.Values{})
		assert.Equal(t, http.StatusNotFound, again.status)
		assert.Contains(t, again.body, "The user is not in the group.")
		bad := postForm(t, adminBrowser, base+usersPagePath+"/carol/groups", base, url.Values{"group": {"-bad-"}})
		assert.Equal(t, http.StatusBadRequest, bad.status)
	})

	t.Run("the admin makes an invite link that the page shows once", func(t *testing.T) {
		resp := postForm(t, adminBrowser, base+usersPagePath+"/invites", base, url.Values{"group": {"editors"}})
		require.Equal(t, http.StatusOK, resp.status, resp.body)
		assert.Equal(t, "no-store", resp.header.Get("Cache-Control"))
		_, rest, found := strings.Cut(resp.body, `id="invite-link">`)
		require.True(t, found)
		link, _, _ := strings.Cut(rest, "<")
		assert.True(t, strings.HasPrefix(link, base+invitePathPrefix), link)
		assert.NotContains(t, get(t, adminBrowser, base+usersPagePath).body, link)
		assert.Equal(t, http.StatusOK, get(t, newBrowser(t, server), link).status)

		unknown := postForm(t, adminBrowser, base+usersPagePath+"/invites", base, url.Values{"group": {"nothing"}})
		assert.Equal(t, http.StatusBadRequest, unknown.status)
		assert.Contains(t, unknown.body, string(msgInviteGroup))
	})
}

func mustGroupAdmin(t *testing.T, store groupadmin.Store, grants *access.Service) *groupadmin.Service {
	t.Helper()
	admin, err := groupadmin.NewService(store, grants)
	require.NoError(t, err)
	return admin
}

func mustGroupName(t *testing.T, raw string) groups.Name {
	t.Helper()
	name, err := groups.ParseName(raw)
	require.NoError(t, err)
	return name
}
