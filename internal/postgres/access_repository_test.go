package postgres_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestAccessRepositoryRoundTrip(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))

	ada := createAccount(t, users.NewService(postgres.NewUserRepository(pool)), "ada")
	repo, err := postgres.NewAccessRepository(pool)
	require.NoError(t, err)
	service := access.NewService(repo, nil)
	editors, err := groups.ParseName("editors")
	require.NoError(t, err)

	root := accessResource(t, "root", "dash.example.test", "/")
	mcp := accessResource(t, "mcp", "dash.example.test", "/mcp/")
	other := accessResource(t, "other", "other.example.test:8443", "/")
	for _, resource := range []access.Resource{root, mcp, other} {
		_, err = service.CreateResource(ctx, resource.Name, resource.URL)
		require.NoError(t, err)
	}
	_, err = service.CreateResource(ctx, root.Name, other.URL)
	require.ErrorIs(t, err, access.ErrDuplicateResource)
	_, err = service.CreateResource(ctx, accessResource(t, "copy", "x.example.test", "/").Name, root.URL)
	require.ErrorIs(t, err, access.ErrDuplicateResource)

	found, err := repo.FindResource(ctx, mcp.Name)
	require.NoError(t, err)
	assert.Equal(t, mcp, found)
	listed, err := repo.ListResources(ctx, root.URL.Host)
	require.NoError(t, err)
	assert.Equal(t, []access.Resource{mcp, root}, listed)

	later := time.Now().Add(time.Hour).Truncate(time.Microsecond)
	userGrant, err := service.Grant(ctx, mcp.Name, access.UserSubject(ada.ID), access.ExpiresAt(later))
	require.NoError(t, err)
	groupGrant, err := service.Grant(ctx, root.Name, access.GroupSubject(editors), access.Expiry{})
	require.NoError(t, err)
	_, err = service.Grant(ctx, mcp.Name, access.UserSubject(ada.ID), access.Expiry{})
	require.ErrorIs(t, err, access.ErrDuplicateGrant)
	_, err = service.Grant(ctx, root.Name, access.GroupSubject(editors), access.Expiry{})
	require.ErrorIs(t, err, access.ErrDuplicateGrant)
	_, err = service.Grant(ctx, mcp.Name, access.UserSubject(users.NewID()), access.Expiry{})
	require.ErrorIs(t, err, access.ErrUnknownUser)
	_, err = service.Grant(ctx, accessResource(t, "missing", "x.example.test", "/").Name, access.UserSubject(ada.ID), access.Expiry{})
	require.ErrorIs(t, err, access.ErrResourceNotFound)

	grants, err := service.ListGrants(ctx, access.GrantFilter{Resource: mcp.Name})
	require.NoError(t, err)
	require.Len(t, grants, 1)
	assert.Equal(t, userGrant.ID, grants[0].Grant.ID)
	assert.Equal(t, access.UserSubject(ada.ID), grants[0].Grant.Subject)
	assert.Equal(t, mcp.URL, grants[0].URL)
	assert.Equal(t, ada.Login, grants[0].UserLogin)
	at, ok := grants[0].Grant.Expiry.Time()
	require.True(t, ok)
	assert.True(t, at.Equal(later))

	tools, err := access.ParseRequestURL("https", "dash.example.test", "/mcp/tools")
	require.NoError(t, err)
	page, err := access.ParseRequestURL("https", "dash.example.test", "/page")
	require.NoError(t, err)
	require.NoError(t, service.Check(ctx, ada.ID, nil, tools))
	require.ErrorIs(t, service.Check(ctx, ada.ID, nil, page), access.ErrNoGrant)
	require.NoError(t, service.Check(ctx, ada.ID, []groups.Name{editors}, page))

	require.NoError(t, service.Revoke(ctx, userGrant.ID))
	require.ErrorIs(t, service.Check(ctx, ada.ID, nil, tools), access.ErrNoGrant)
	require.ErrorIs(t, service.Revoke(ctx, userGrant.ID), access.ErrGrantNotFound)

	require.NoError(t, service.DeleteResource(ctx, root.Name))
	require.ErrorIs(t, service.DeleteResource(ctx, root.Name), access.ErrResourceNotFound)
	require.ErrorIs(t, service.Revoke(ctx, groupGrant.ID), access.ErrGrantNotFound)
	_, err = repo.FindResource(ctx, root.Name)
	require.ErrorIs(t, err, access.ErrResourceNotFound)
}

func accessResource(t *testing.T, rawName, rawHost, rawPrefix string) access.Resource {
	t.Helper()
	name, err := access.ParseResourceName(rawName)
	require.NoError(t, err)
	host, err := access.ParseHost(rawHost)
	require.NoError(t, err)
	prefix, err := access.ParsePathPrefix(rawPrefix)
	require.NoError(t, err)
	return access.Resource{Name: name, URL: access.ResourceURL{Host: host, Prefix: prefix}}
}

func TestAccessRepositoryListsGrantEntries(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))

	accounts := users.NewService(postgres.NewUserRepository(pool))
	ada := createAccount(t, accounts, "ada")
	bob := createAccount(t, accounts, "bob")
	repo, err := postgres.NewAccessRepository(pool)
	require.NoError(t, err)
	service := access.NewService(repo, accounts)
	editors, err := groups.ParseName("editors")
	require.NoError(t, err)

	root := accessResource(t, "root", "dash.example.test", "/")
	mcp := accessResource(t, "mcp", "dash.example.test", "/mcp")
	for _, resource := range []access.Resource{root, mcp} {
		_, err = service.CreateResource(ctx, resource.Name, resource.URL)
		require.NoError(t, err)
	}
	all, err := service.ListResources(ctx)
	require.NoError(t, err)
	assert.Equal(t, []access.Resource{mcp, root}, all)

	adaRoot, err := service.GrantTo(ctx, root.Name, access.Grantee{User: ada.Login}, access.Expiry{})
	require.NoError(t, err)
	assert.Equal(t, ada.Login, adaRoot.UserLogin)
	assert.Equal(t, root.URL, adaRoot.URL)
	_, err = service.GrantTo(ctx, mcp.Name, access.Grantee{User: bob.Login}, access.Expiry{})
	require.NoError(t, err)
	_, err = service.GrantTo(ctx, mcp.Name, access.Grantee{Group: editors}, access.Expiry{})
	require.NoError(t, err)
	_, err = service.GrantTo(ctx, mcp.Name, access.Grantee{User: mustAccountLogin(t, "nobody")}, access.Expiry{})
	require.ErrorIs(t, err, access.ErrUnknownUser)

	tests := []struct {
		name   string
		filter access.GrantFilter
		want   []string
	}{
		{name: "every grant", want: []string{"mcp bob", "mcp editors", "root ada"}},
		{name: "one user", filter: access.GrantFilter{User: ada.Login}, want: []string{"root ada"}},
		{name: "one resource", filter: access.GrantFilter{Resource: mcp.Name}, want: []string{"mcp bob", "mcp editors"}},
		{name: "user and resource", filter: access.GrantFilter{User: ada.Login, Resource: mcp.Name}, want: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := service.ListGrants(ctx, tt.filter)
			require.NoError(t, err)
			got := []string{}
			for _, entry := range entries {
				subject := entry.UserLogin.String()
				if name, ok := entry.Grant.Subject.Group(); ok {
					subject = name.String()
				}
				got = append(got, entry.Grant.Resource.String()+" "+subject)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func mustAccountLogin(t *testing.T, raw string) users.Login {
	t.Helper()
	login, err := users.ParseLogin(raw)
	require.NoError(t, err)
	return login
}
