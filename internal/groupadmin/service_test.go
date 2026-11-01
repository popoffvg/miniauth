package groupadmin_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/access/accesstest"
	"github.com/popoffvg/miniauth/internal/groupadmin"
	"github.com/popoffvg/miniauth/internal/groups"
)

// memoryGroups reads the resources of a group from the grants of repo, the way the SQL query does.
type memoryGroups struct {
	repo   *accesstest.Repository
	stored []groupadmin.Group
}

func (m *memoryGroups) ListGroups(ctx context.Context) ([]groupadmin.Group, error) {
	var found []groupadmin.Group
	for _, group := range m.stored {
		full, err := m.FindGroup(ctx, group.Name)
		if err != nil {
			return nil, err
		}
		found = append(found, full)
	}
	return found, nil
}

func (m *memoryGroups) FindGroup(ctx context.Context, name groups.Name) (groupadmin.Group, error) {
	for _, group := range m.stored {
		if group.Name != name {
			continue
		}
		entries, err := m.repo.ListGrantEntries(ctx, access.GrantFilter{})
		if err != nil {
			return groupadmin.Group{}, err
		}
		for _, entry := range entries {
			if subject, ok := entry.Grant.Subject.Group(); ok && subject == name {
				group.Resources = append(group.Resources, groupadmin.GroupResource{Name: entry.Grant.Resource, Managed: entry.Grant.Managed})
			}
		}
		return group, nil
	}
	return groupadmin.Group{}, groups.ErrGroupNotFound
}

func (m *memoryGroups) CreateGroup(_ context.Context, name groups.Name, at time.Time) error {
	for _, group := range m.stored {
		if group.Name == name {
			return groups.ErrDuplicateGroup
		}
	}
	m.stored = append(m.stored, groupadmin.Group{Name: name, CreatedAt: at, BuiltIn: name.BuiltIn()})
	return nil
}

func (m *memoryGroups) DeleteGroup(_ context.Context, name groups.Name) error {
	for i, group := range m.stored {
		if group.Name == name {
			m.stored = append(m.stored[:i], m.stored[i+1:]...)
			return nil
		}
	}
	return groups.ErrGroupNotFound
}

func mustName(t *testing.T, raw string) groups.Name {
	t.Helper()
	name, err := groups.ParseName(raw)
	require.NoError(t, err)
	return name
}

func TestGroupResources(t *testing.T) {
	ctx := t.Context()
	repo := accesstest.NewRepository()
	grants := access.NewService(repo, nil)
	store := &memoryGroups{repo: repo}
	service, err := groupadmin.NewService(store, grants)
	require.NoError(t, err)
	grafanaURL, err := access.ParseResourceURL("https://grafana.example.test/")
	require.NoError(t, err)
	grafana, err := access.ParseResourceName("grafana")
	require.NoError(t, err)
	_, err = grants.CreateResource(ctx, grafana, grafanaURL)
	require.NoError(t, err)
	ops := mustName(t, "ops")
	_, err = service.Create(ctx, groups.Users())
	require.NoError(t, err)

	_, err = service.Create(ctx, ops)
	require.NoError(t, err)
	_, err = service.Create(ctx, ops)
	require.ErrorIs(t, err, groups.ErrDuplicateGroup)
	require.ErrorIs(t, service.AddResource(ctx, mustName(t, "ghosts"), grafana), groups.ErrGroupNotFound)

	require.NoError(t, service.AddResource(ctx, ops, grafana))
	require.NoError(t, service.AddResource(ctx, ops, grafana), "an added resource stays: the call is idempotent")
	found, err := service.List(ctx)
	require.NoError(t, err)
	require.Len(t, found, 2)
	assert.Equal(t, []groupadmin.GroupResource{{Name: grafana}}, found[1].Resources)

	require.NoError(t, service.RemoveResource(ctx, ops, grafana))
	require.ErrorIs(t, service.RemoveResource(ctx, ops, grafana), groupadmin.ErrNotGranted)

	require.ErrorIs(t, service.Delete(ctx, groups.Users()), groups.ErrBuiltIn)
	require.ErrorIs(t, service.Delete(ctx, groups.Admins()), groups.ErrBuiltIn)
	require.NoError(t, service.Delete(ctx, ops))
	require.ErrorIs(t, service.Delete(ctx, ops), groups.ErrGroupNotFound)
}

func TestManagedGrantsAreReadOnly(t *testing.T) {
	ctx := t.Context()
	repo := accesstest.NewRepository()
	grants := access.NewService(repo, nil)
	store := &memoryGroups{repo: repo}
	service, err := groupadmin.NewService(store, grants)
	require.NoError(t, err)
	dashURL, err := access.ParseResourceURL("https://dash.example.test/")
	require.NoError(t, err)
	dash, err := access.ParseResourceName("dash")
	require.NoError(t, err)
	require.NoError(t, repo.CreateResource(ctx, access.Resource{Name: dash, URL: dashURL, Managed: true}))
	ops := mustName(t, "ops")
	_, err = service.Create(ctx, ops)
	require.NoError(t, err)
	require.NoError(t, repo.CreateGrant(ctx, access.Grant{ID: access.NewGrantID(), Resource: dash, Subject: access.GroupSubject(ops), Managed: true}))

	require.ErrorIs(t, service.RemoveResource(ctx, ops, dash), access.ErrManagedGrant)
	require.ErrorIs(t, service.Delete(ctx, ops), groupadmin.ErrManagedGroup)
	require.ErrorIs(t, grants.DeleteResource(ctx, dash), access.ErrManagedResource)
	found, err := store.FindGroup(ctx, ops)
	require.NoError(t, err)
	assert.Equal(t, []groupadmin.GroupResource{{Name: dash, Managed: true}}, found.Resources)
}
