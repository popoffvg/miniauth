package access_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/access/accesstest"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestServiceCheck(t *testing.T) {
	ada := users.NewID()
	editors := mustGroup(t, "editors")

	type storedGrant struct {
		resource string
		user     bool
		group    string
		expiry   access.Expiry
	}
	tests := []struct {
		name   string
		grants []storedGrant
		groups []groups.Name
		host   string
		uri    string
		want   error
	}{
		{name: "grant to user", grants: []storedGrant{{resource: "root", user: true}}, uri: "/x", want: nil},
		{name: "grant to group", grants: []storedGrant{{resource: "root", group: "editors"}}, groups: []groups.Name{editors}, uri: "/x", want: nil},
		{name: "grant to another group", grants: []storedGrant{{resource: "root", group: "admins"}}, groups: []groups.Name{editors}, uri: "/x", want: access.ErrNoGrant},
		{name: "expired grant", grants: []storedGrant{{resource: "root", user: true, expiry: access.ExpiresAt(time.Now().Add(-time.Minute))}}, uri: "/x", want: access.ErrNoGrant},
		{name: "grant that expires later", grants: []storedGrant{{resource: "root", user: true, expiry: access.ExpiresAt(time.Now().Add(time.Hour))}}, uri: "/x", want: nil},
		{name: "longest prefix wins over a shorter grant", grants: []storedGrant{{resource: "root", user: true}}, uri: "/mcp/tools", want: access.ErrNoGrant},
		{name: "longest prefix grant", grants: []storedGrant{{resource: "mcp", user: true}}, uri: "/mcp/tools", want: nil},
		{name: "segment border", grants: []storedGrant{{resource: "mcp", user: true}}, uri: "/mcpx", want: access.ErrNoGrant},
		{name: "no grant", uri: "/x", want: access.ErrNoGrant},
		{name: "no resource", grants: []storedGrant{{resource: "mcp", user: true}}, uri: "/other", want: access.ErrNoResource, host: "other.example.test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := accesstest.NewRepository()
			service := access.NewService(repo)
			createResource(t, service, "root", "dash.example.test", "/")
			createResource(t, service, "mcp", "dash.example.test", "/mcp")
			for _, stored := range tt.grants {
				subject := access.UserSubject(ada)
				if stored.group != "" {
					subject = access.GroupSubject(mustGroup(t, stored.group))
				}
				require.NoError(t, repo.CreateGrant(t.Context(), access.Grant{
					ID:        access.NewGrantID(),
					Resource:  mustResourceName(t, stored.resource),
					Subject:   subject,
					Expiry:    stored.expiry,
					CreatedAt: time.Now(),
				}))
			}
			host := "dash.example.test"
			if tt.host != "" {
				host = tt.host
			}
			target, err := access.ParseRequestURL("https", host, tt.uri)
			require.NoError(t, err)
			err = service.Check(t.Context(), ada, tt.groups, target)
			if tt.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tt.want)
		})
	}
}

func TestServiceRevokeAppliesToTheNextCheck(t *testing.T) {
	service := access.NewService(accesstest.NewRepository())
	ada := users.NewID()
	root := createResource(t, service, "root", "dash.example.test", "/")
	target, err := access.ParseRequestURL("https", "dash.example.test", "/")
	require.NoError(t, err)

	grant, err := service.Grant(t.Context(), root, access.UserSubject(ada), access.Expiry{})
	require.NoError(t, err)
	require.NoError(t, service.Check(t.Context(), ada, nil, target))

	require.NoError(t, service.Revoke(t.Context(), grant.ID))
	require.ErrorIs(t, service.Check(t.Context(), ada, nil, target), access.ErrNoGrant)
	require.ErrorIs(t, service.Revoke(t.Context(), grant.ID), access.ErrGrantNotFound)
}

func TestServiceWrites(t *testing.T) {
	ctx := t.Context()
	service := access.NewService(accesstest.NewRepository())
	ada := users.NewID()
	root := createResource(t, service, "root", "dash.example.test", "/")
	host, err := access.ParseHost("dash.example.test")
	require.NoError(t, err)
	slash, err := access.ParsePathPrefix("/")
	require.NoError(t, err)

	_, err = service.CreateResource(ctx, mustResourceName(t, "root"), access.ResourceURL{Host: host, Prefix: slash})
	require.ErrorIs(t, err, access.ErrDuplicateResource)
	_, err = service.CreateResource(ctx, mustResourceName(t, "copy"), access.ResourceURL{Host: host, Prefix: slash})
	require.ErrorIs(t, err, access.ErrDuplicateResource, "two resources MUST NOT share one URL")
	_, err = service.CreateResource(ctx, mustResourceName(t, "empty"), access.ResourceURL{})
	require.ErrorIs(t, err, access.ErrHost)

	_, err = service.Grant(ctx, root, access.Subject{}, access.Expiry{})
	require.ErrorIs(t, err, access.ErrSubject)
	_, err = service.Grant(ctx, root, access.UserSubject(ada), access.ExpiresAt(time.Now().Add(-time.Second)))
	require.ErrorIs(t, err, access.ErrExpiry)
	_, err = service.Grant(ctx, mustResourceName(t, "missing"), access.UserSubject(ada), access.Expiry{})
	require.ErrorIs(t, err, access.ErrResourceNotFound)

	later := time.Now().Add(time.Hour)
	userGrant, err := service.Grant(ctx, root, access.UserSubject(ada), access.ExpiresAt(later))
	require.NoError(t, err)
	_, err = service.Grant(ctx, root, access.UserSubject(ada), access.Expiry{})
	require.ErrorIs(t, err, access.ErrDuplicateGrant)
	groupGrant, err := service.Grant(ctx, root, access.GroupSubject(mustGroup(t, "editors")), access.Expiry{})
	require.NoError(t, err)

	listed, err := service.ListGrants(ctx, root)
	require.NoError(t, err)
	require.Len(t, listed, 2)
	assert.Equal(t, userGrant.ID, listed[0].ID)
	assert.Equal(t, groupGrant.ID, listed[1].ID)
	at, ok := listed[0].Expiry.Time()
	require.True(t, ok)
	assert.True(t, at.Equal(later))
	_, err = service.ListGrants(ctx, mustResourceName(t, "missing"))
	require.ErrorIs(t, err, access.ErrResourceNotFound)

	require.NoError(t, service.DeleteResource(ctx, root))
	require.ErrorIs(t, service.DeleteResource(ctx, root), access.ErrResourceNotFound)
	require.ErrorIs(t, service.Revoke(ctx, userGrant.ID), access.ErrGrantNotFound, "a deleted resource MUST take its grants")
}

func TestSubject(t *testing.T) {
	ada := users.NewID()
	editors := mustGroup(t, "editors")
	assert.True(t, access.UserSubject(ada).Covers(ada, nil))
	assert.False(t, access.UserSubject(ada).Covers(users.NewID(), []groups.Name{editors}))
	assert.True(t, access.GroupSubject(editors).Covers(users.NewID(), []groups.Name{editors}))
	assert.False(t, access.GroupSubject(editors).Covers(ada, nil))
	assert.False(t, access.Subject{}.Valid())
	assert.False(t, access.Subject{}.Covers(users.ID{}, nil))
	assert.False(t, access.UserSubject(users.ID{}).Valid())
}

func createResource(t *testing.T, service *access.Service, rawName, rawHost, rawPrefix string) access.ResourceName {
	t.Helper()
	host, err := access.ParseHost(rawHost)
	require.NoError(t, err)
	prefix, err := access.ParsePathPrefix(rawPrefix)
	require.NoError(t, err)
	created, err := service.CreateResource(t.Context(), mustResourceName(t, rawName), access.ResourceURL{Host: host, Prefix: prefix})
	require.NoError(t, err)
	return created.Name
}

func mustResourceName(t *testing.T, raw string) access.ResourceName {
	t.Helper()
	name, err := access.ParseResourceName(raw)
	require.NoError(t, err)
	return name
}

func mustGroup(t *testing.T, raw string) groups.Name {
	t.Helper()
	name, err := groups.ParseName(raw)
	require.NoError(t, err)
	return name
}
