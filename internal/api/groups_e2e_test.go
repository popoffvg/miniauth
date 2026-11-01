package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/access"
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

const groupsAdminToken = "bootstrap-token-for-tests"

// groupsCall sends one admin API request with the bootstrap token and an optional JSON body.
func groupsCall(t *testing.T, client *http.Client, method, target, body string) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+groupsAdminToken)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return do(t, client, req)
}

func TestGroupsEndToEnd(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))

	server := httptest.NewUnstartedServer(nil)
	host := server.Listener.Addr().String()
	base := "https://" + host

	// The resources file gives dashboards to users. The start applies it before the router serves.
	dashURL, err := access.ParseResourceURL(base + "/dash")
	require.NoError(t, err)
	dash, err := access.ParseResourceName("dashboards")
	require.NoError(t, err)
	managedStore, err := postgres.NewManagedRepository(pool)
	require.NoError(t, err)
	reconciler, err := access.NewReconciler(managedStore)
	require.NoError(t, err)
	require.NoError(t, reconciler.Reconcile(ctx, []access.PredefinedResource{{Name: dash, URL: dashURL, Groups: []groups.Name{groups.Users()}}}))

	accountRepo := postgres.NewUserRepository(pool)
	accounts := users.NewService(accountRepo)
	admin := &account{login: "ada", password: "ada-password-for-tests"}
	member := &account{login: "max", password: "max-password-for-tests"}
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
	require.NoError(t, groupRepo.Add(ctx, admin.id, groups.Admins()))
	passwords, err := password.NewService(accountRepo, postgres.NewAttemptRepository(pool))
	require.NoError(t, err)
	accessRepo, err := postgres.NewAccessRepository(pool)
	require.NoError(t, err)
	grants := access.NewService(accessRepo, accounts)
	createResource(t, grants, "grafana", host, "/grafana")
	inviteRepo, err := postgres.NewInviteRepository(pool)
	require.NoError(t, err)
	invitations, err := invites.NewService(inviteRepo, nil, nil)
	require.NoError(t, err)
	userAdminRepo, err := postgres.NewUserAdminRepository(pool)
	require.NoError(t, err)
	groupStore, err := postgres.NewGroupAdminRepository(pool)
	require.NoError(t, err)

	router, err := NewRouter(
		accounts,
		sessions.NewService(postgres.NewSessionRepository(pool)),
		groupRepo,
		sessions.Domain{},
		mustPublicURL(t, base),
		hashToken(t, groupsAdminToken),
		&readyState{ok: true},
		slog.New(slog.DiscardHandler),
		WithLogin(loginflow.NewLoginFlows(postgres.NewFlowStore(pool)), passwords),
		WithURLGrants(grants),
		WithAccessAdmin(grants),
		WithInvites(invitations),
		WithUserAdmin(useradmin.NewService(userAdminRepo, accounts, nil)),
		WithGroupAdmin(mustGroupAdmin(t, groupStore, grants)),
	)
	require.NoError(t, err)
	server.Config.Handler = router
	server.StartTLS()
	t.Cleanup(server.Close)
	client := server.Client()

	signIn := func(t *testing.T, login, userPassword, returnTo string) *http.Client {
		t.Helper()
		browser := newBrowser(t, server)
		openLogin(t, browser, base, returnTo)
		require.Equal(t, http.StatusSeeOther, submitLogin(t, browser, base, base, login, userPassword).status)
		return browser
	}
	adminBrowser := signIn(t, admin.login, admin.password, base+groupsPagePath)

	t.Run("the API lists the built-in groups and the resource from the file", func(t *testing.T) {
		resp := groupsCall(t, client, http.MethodGet, base+"/api/v1/groups", "")
		require.Equal(t, http.StatusOK, resp.status, resp.body)
		var body struct {
			Groups []struct {
				Name      string `json:"name"`
				BuiltIn   bool   `json:"built_in"`
				Members   int    `json:"members"`
				Resources []struct {
					Name    string `json:"name"`
					Managed bool   `json:"managed"`
				} `json:"resources"`
			} `json:"groups"`
		}
		require.NoError(t, json.Unmarshal([]byte(resp.body), &body))
		require.Len(t, body.Groups, 2)
		assert.Equal(t, "admins", body.Groups[0].Name)
		assert.True(t, body.Groups[0].BuiltIn)
		assert.Equal(t, 1, body.Groups[0].Members)
		assert.Equal(t, "users", body.Groups[1].Name)
		assert.Equal(t, 2, body.Groups[1].Members, "every account joins users")
		require.Len(t, body.Groups[1].Resources, 1)
		assert.Equal(t, "dashboards", body.Groups[1].Resources[0].Name)
		assert.True(t, body.Groups[1].Resources[0].Managed)
		assert.Equal(t, http.StatusUnauthorized, adminCall(t, client, http.MethodGet, base+"/api/v1/groups", "").status)
	})

	t.Run("the API creates, changes, and deletes a group", func(t *testing.T) {
		created := groupsCall(t, client, http.MethodPost, base+"/api/v1/groups", `{"name":"Readers"}`)
		require.Equal(t, http.StatusCreated, created.status, created.body)
		assert.Contains(t, created.body, `"name":"readers"`)
		assert.Equal(t, http.StatusConflict, groupsCall(t, client, http.MethodPost, base+"/api/v1/groups", `{"name":"readers"}`).status)
		assert.Equal(t, http.StatusBadRequest, groupsCall(t, client, http.MethodPost, base+"/api/v1/groups", `{"name":"-bad-"}`).status)
		for range 2 {
			assert.Equal(t, http.StatusNoContent, groupsCall(t, client, http.MethodPut, base+"/api/v1/groups/readers/resources/grafana", "").status)
		}
		assert.Equal(t, http.StatusNotFound, groupsCall(t, client, http.MethodPut, base+"/api/v1/groups/readers/resources/missing", "").status)
		assert.Equal(t, http.StatusNotFound, groupsCall(t, client, http.MethodPut, base+"/api/v1/groups/ghosts/resources/grafana", "").status)
		assert.Equal(t, http.StatusNoContent, groupsCall(t, client, http.MethodDelete, base+"/api/v1/groups/readers/resources/grafana", "").status)
		assert.Equal(t, http.StatusNotFound, groupsCall(t, client, http.MethodDelete, base+"/api/v1/groups/readers/resources/grafana", "").status)
		assert.Equal(t, http.StatusNoContent, groupsCall(t, client, http.MethodDelete, base+"/api/v1/groups/readers", "").status)
		assert.Equal(t, http.StatusNotFound, groupsCall(t, client, http.MethodDelete, base+"/api/v1/groups/readers", "").status)
		for _, builtIn := range []string{"admins", "users"} {
			resp := groupsCall(t, client, http.MethodDelete, base+"/api/v1/groups/"+builtIn, "")
			assert.Equal(t, http.StatusConflict, resp.status, builtIn)
			assert.Contains(t, resp.header.Get("Content-Type"), "application/problem+json")
		}
	})

	t.Run("a managed resource and its grant cannot be changed", func(t *testing.T) {
		resp := groupsCall(t, client, http.MethodDelete, base+"/api/v1/resources/dashboards", "")
		assert.Equal(t, http.StatusConflict, resp.status)
		assert.Contains(t, resp.body, "resources file")
		assert.Equal(t, http.StatusConflict, groupsCall(t, client, http.MethodDelete, base+"/api/v1/groups/users/resources/dashboards", "").status)
		entries, listErr := grants.ListGrants(t.Context(), access.GrantFilter{Resource: dash})
		require.NoError(t, listErr)
		require.Len(t, entries, 1)
		assert.Equal(t, http.StatusConflict, groupsCall(t, client, http.MethodDelete, base+"/api/v1/grants/"+entries[0].Grant.ID.String(), "").status)

		page := postForm(t, adminBrowser, base+accessPagePath+"/resources/dashboards/delete", base, url.Values{})
		assert.Equal(t, http.StatusConflict, page.status)
		assert.Contains(t, page.body, "The resource comes from the resources file.")
		listed := get(t, adminBrowser, base+accessPagePath)
		assert.Contains(t, listed.body, "From config")
		assert.NotContains(t, listed.body, `action="/access/resources/dashboards/delete"`)
	})

	var invitee *http.Client
	t.Run("an invited user in users opens the resource from the file", func(t *testing.T) {
		resp := groupsCall(t, client, http.MethodPost, base+"/api/v1/invites", `{"group":"users"}`)
		require.Equal(t, http.StatusCreated, resp.status, resp.body)
		var created struct {
			Link string `json:"link"`
		}
		require.NoError(t, json.Unmarshal([]byte(resp.body), &created))
		token, ok := strings.CutPrefix(created.Link, base+invitePathPrefix)
		require.True(t, ok, created.Link)
		invitee = newBrowser(t, server)
		accepted := postForm(t, invitee, base+inviteAcceptPath, base, url.Values{"token": {token}, "login": {"newcomer"}, "password": {"newcomer-password-1"}})
		require.Equal(t, http.StatusSeeOther, accepted.status, accepted.body)
		check := forwardedCheck(t, invitee, base, host, "/dash/home")
		require.Equal(t, http.StatusOK, check.status)
		assert.Equal(t, "newcomer", check.header.Get(headerAuthUser))
		assert.NotEqual(t, http.StatusOK, forwardedCheck(t, invitee, base, host, "/grafana/home").status)
	})

	t.Run("the admin makes ops with grafana and the user in ops reaches grafana", func(t *testing.T) {
		created := postForm(t, adminBrowser, base+groupsPagePath, base, url.Values{"name": {"ops"}})
		require.Equal(t, http.StatusSeeOther, created.status, created.body)
		assert.Equal(t, base+withDone(groupsPagePath, doneGroupCreated), created.header.Get("Location"))
		added := postForm(t, adminBrowser, base+groupsPagePath+"/ops/resources", base, url.Values{"resource": {"grafana"}})
		require.Equal(t, http.StatusSeeOther, added.status, added.body)
		member := postForm(t, adminBrowser, base+usersPagePath+"/newcomer/groups", base, url.Values{"group": {"ops"}})
		require.Equal(t, http.StatusSeeOther, member.status, member.body)
		assert.Equal(t, http.StatusOK, forwardedCheck(t, invitee, base, host, "/grafana/home").status)

		page := get(t, adminBrowser, base+groupsPagePath)
		require.Equal(t, http.StatusOK, page.status)
		assert.Contains(t, page.body, "Built-in")
		assert.Contains(t, page.body, "From config")
		assert.Contains(t, page.body, `action="/groups/ops/delete"`)
		assert.Contains(t, page.body, `action="/groups/ops/resources/grafana/remove"`)
		assert.NotContains(t, page.body, `action="/groups/users/delete"`)
		assert.NotContains(t, page.body, `action="/groups/users/resources/dashboards/remove"`)

		removed := postForm(t, adminBrowser, base+groupsPagePath+"/ops/resources/grafana/remove", base, url.Values{})
		require.Equal(t, http.StatusSeeOther, removed.status, removed.body)
		assert.NotEqual(t, http.StatusOK, forwardedCheck(t, invitee, base, host, "/grafana/home").status)
		deleted := postForm(t, adminBrowser, base+groupsPagePath+"/ops/delete", base, url.Values{})
		require.Equal(t, http.StatusSeeOther, deleted.status, deleted.body)
		names, listErr := groupRepo.List(t.Context(), newcomerID(t, accounts))
		require.NoError(t, listErr)
		assert.Equal(t, []groups.Name{groups.Users()}, names, "a deleted group leaves no membership")
	})

	t.Run("the page refuses a built-in delete, a bad origin, and a user outside admins", func(t *testing.T) {
		builtIn := postForm(t, adminBrowser, base+groupsPagePath+"/users/delete", base, url.Values{})
		assert.Equal(t, http.StatusConflict, builtIn.status)
		assert.Contains(t, builtIn.body, "built in")
		assert.Equal(t, http.StatusForbidden, postForm(t, adminBrowser, base+groupsPagePath, "https://evil.example.test", url.Values{"name": {"evil"}}).status)
		memberBrowser := signIn(t, member.login, member.password, base+"/")
		assert.Equal(t, http.StatusForbidden, get(t, memberBrowser, base+groupsPagePath).status)
		assert.Equal(t, http.StatusForbidden, postForm(t, memberBrowser, base+groupsPagePath, base, url.Values{"name": {"evil"}}).status)
		_, findErr := groupStore.FindGroup(t.Context(), mustGroupName(t, "evil"))
		require.ErrorIs(t, findErr, groups.ErrGroupNotFound)
	})
}

// newcomerID returns the id of the account that the invite created.
func newcomerID(t *testing.T, accounts *users.Service) users.ID {
	t.Helper()
	login, err := users.ParseLogin("newcomer")
	require.NoError(t, err)
	user, err := accounts.FindByLogin(t.Context(), login)
	require.NoError(t, err)
	return user.ID
}
