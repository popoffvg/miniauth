package postgres_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groupadmin"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestReconcileResourcesFile(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))

	accounts := users.NewService(postgres.NewUserRepository(pool))
	ada := createAccount(t, accounts, "ada")
	accessRepo, err := postgres.NewAccessRepository(pool)
	require.NoError(t, err)
	grants := access.NewService(accessRepo, accounts)
	store, err := postgres.NewManagedRepository(pool)
	require.NoError(t, err)
	reconciler, err := access.NewReconciler(store)
	require.NoError(t, err)
	groupStore, err := postgres.NewGroupAdminRepository(pool)
	require.NoError(t, err)

	dash := accessResource(t, "dash", "dash.example.test", "/")
	wiki := accessResource(t, "wiki", "wiki.example.test", "/")
	manual := accessResource(t, "manual", "manual.example.test", "/")
	ops := mustGroupName(t, "ops")
	_, err = grants.CreateResource(ctx, manual.Name, manual.URL)
	require.NoError(t, err)
	manualGrant, err := grants.GrantTo(ctx, manual.Name, access.Grantee{Group: groups.Users()}, access.Expiry{})
	require.NoError(t, err)

	grantKeys := func() []string {
		t.Helper()
		entries, listErr := grants.ListGrants(ctx, access.GrantFilter{})
		require.NoError(t, listErr)
		var keys []string
		for _, entry := range entries {
			name, _ := entry.Grant.Subject.Group()
			key := entry.Grant.Resource.String() + ":" + name.String()
			if entry.Grant.Managed {
				key += ":managed"
			}
			keys = append(keys, key)
		}
		slices.Sort(keys)
		return keys
	}

	t.Run("creates resources, grants, and a missing group", func(t *testing.T) {
		require.NoError(t, reconciler.Reconcile(ctx, []access.PredefinedResource{
			{Name: dash.Name, URL: dash.URL, Groups: []groups.Name{groups.Users(), ops}},
			{Name: wiki.Name, URL: wiki.URL, Groups: []groups.Name{groups.Users()}},
		}))
		found, findErr := accessRepo.FindResource(ctx, dash.Name)
		require.NoError(t, findErr)
		assert.True(t, found.Managed)
		group, findErr := groupStore.FindGroup(ctx, ops)
		require.NoError(t, findErr)
		assert.False(t, group.BuiltIn)
		assert.Equal(t, []groupadmin.GroupResource{{Name: dash.Name, Managed: true}}, group.Resources)
		assert.Equal(t, []string{"dash:ops:managed", "dash:users:managed", "manual:users", "wiki:users:managed"}, grantKeys())
		require.NoError(t, grants.Check(ctx, ada.ID, []groups.Name{groups.Users()}, requestURL(t, "wiki.example.test", "/page")))
	})

	t.Run("a second run with the same file changes nothing", func(t *testing.T) {
		before := grantKeys()
		require.NoError(t, reconciler.Reconcile(ctx, []access.PredefinedResource{
			{Name: dash.Name, URL: dash.URL, Groups: []groups.Name{groups.Users(), ops}},
			{Name: wiki.Name, URL: wiki.URL, Groups: []groups.Name{groups.Users()}},
		}))
		assert.Equal(t, before, grantKeys())
	})

	t.Run("updates the URL and deletes stale managed rows, never unmanaged ones", func(t *testing.T) {
		moved := accessResource(t, "dash", "dash.example.test", "/v2")
		require.NoError(t, reconciler.Reconcile(ctx, []access.PredefinedResource{
			{Name: dash.Name, URL: moved.URL, Groups: []groups.Name{ops}},
		}))
		found, findErr := accessRepo.FindResource(ctx, dash.Name)
		require.NoError(t, findErr)
		assert.Equal(t, moved.URL, found.URL)
		_, findErr = accessRepo.FindResource(ctx, wiki.Name)
		require.ErrorIs(t, findErr, access.ErrResourceNotFound)
		assert.Equal(t, []string{"dash:ops:managed", "manual:users"}, grantKeys())
		stored, findErr := accessRepo.FindGrant(ctx, manualGrant.Grant.ID)
		require.NoError(t, findErr)
		assert.False(t, stored.Managed)
	})

	t.Run("a managed row is read-only for the access service", func(t *testing.T) {
		require.ErrorIs(t, grants.DeleteResource(ctx, dash.Name), access.ErrManagedResource)
		entries, listErr := grants.ListGrants(ctx, access.GrantFilter{Resource: dash.Name})
		require.NoError(t, listErr)
		require.Len(t, entries, 1)
		require.ErrorIs(t, grants.Revoke(ctx, entries[0].Grant.ID), access.ErrManagedGrant)
	})

	t.Run("a URL that an unmanaged resource has stops the reconcile and rolls it back", func(t *testing.T) {
		err := reconciler.Reconcile(ctx, []access.PredefinedResource{
			{Name: wiki.Name, URL: wiki.URL},
			{Name: mustResource(t, "clash"), URL: manual.URL},
		})
		require.ErrorIs(t, err, access.ErrDuplicateResource)
		assert.Contains(t, err.Error(), "predefined resource 1")
		_, findErr := accessRepo.FindResource(ctx, wiki.Name)
		require.ErrorIs(t, findErr, access.ErrResourceNotFound, "the failed run MUST write nothing")
		_, findErr = accessRepo.FindResource(ctx, dash.Name)
		require.NoError(t, findErr)
	})

	t.Run("an empty file deletes every managed row", func(t *testing.T) {
		require.NoError(t, reconciler.Reconcile(ctx, nil))
		_, findErr := accessRepo.FindResource(ctx, dash.Name)
		require.ErrorIs(t, findErr, access.ErrResourceNotFound)
		assert.Equal(t, []string{"manual:users"}, grantKeys())
		_, findErr = groupStore.FindGroup(ctx, ops)
		require.NoError(t, findErr, "a group stays: the file only made it")
	})
}

func mustGroupName(t *testing.T, raw string) groups.Name {
	t.Helper()
	name, err := groups.ParseName(raw)
	require.NoError(t, err)
	return name
}

func mustResource(t *testing.T, raw string) access.ResourceName {
	t.Helper()
	name, err := access.ParseResourceName(raw)
	require.NoError(t, err)
	return name
}

func requestURL(t *testing.T, host, path string) access.RequestURL {
	t.Helper()
	target, err := access.ParseRequestURL("https", host, path)
	require.NoError(t, err)
	return target
}
