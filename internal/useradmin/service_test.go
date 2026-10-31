package useradmin_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/useradmin"
	"github.com/popoffvg/miniauth/internal/users"
)

type memAccounts map[string]users.User

func (m memAccounts) FindByLogin(_ context.Context, login users.Login) (users.User, error) {
	user, ok := m[login.String()]
	if !ok {
		return users.User{}, users.ErrNotFound
	}
	return user, nil
}

type spyStore struct {
	disabled []users.ID
	removed  []groups.Name
}

func (s *spyStore) ListAccounts(context.Context) ([]useradmin.Account, error) { return nil, nil }

func (s *spyStore) Disable(_ context.Context, id users.ID, _ time.Time) error {
	s.disabled = append(s.disabled, id)
	return nil
}
func (s *spyStore) Enable(context.Context, users.ID) error                 { return nil }
func (s *spyStore) AddMember(context.Context, users.ID, groups.Name) error { return nil }

func (s *spyStore) RemoveMember(_ context.Context, _ users.ID, name groups.Name) error {
	s.removed = append(s.removed, name)
	return nil
}

func login(t *testing.T, raw string) users.Login {
	t.Helper()
	parsed, err := users.ParseLogin(raw)
	require.NoError(t, err)
	return parsed
}

func TestServiceRefusesSelfChanges(t *testing.T) {
	ada := users.User{ID: users.NewID(), Login: login(t, "ada")}
	bob := users.User{ID: users.NewID(), Login: login(t, "bob")}
	store := &spyStore{}
	service := useradmin.NewService(store, memAccounts{"ada": ada, "bob": bob})
	editors, err := groups.ParseName("editors")
	require.NoError(t, err)
	ctx := t.Context()
	admin := useradmin.Actor{ID: ada.ID}

	require.ErrorIs(t, service.Disable(ctx, admin, ada.Login), useradmin.ErrSelfDisable)
	require.ErrorIs(t, service.RemoveFromGroup(ctx, admin, ada.Login, groups.Admin()), useradmin.ErrSelfAdmin)
	assert.Empty(t, store.disabled)
	assert.Empty(t, store.removed)

	require.NoError(t, service.RemoveFromGroup(ctx, admin, ada.Login, editors), "the actor may leave another group")
	require.NoError(t, service.RemoveFromGroup(ctx, admin, bob.Login, groups.Admin()))
	require.NoError(t, service.Disable(ctx, admin, bob.Login))
	require.NoError(t, service.Disable(ctx, useradmin.Actor{}, bob.Login), "the bootstrap token is no user")
	assert.Equal(t, []users.ID{bob.ID, bob.ID}, store.disabled)

	require.ErrorIs(t, service.Enable(ctx, login(t, "carol")), useradmin.ErrUserNotFound)
	require.ErrorIs(t, service.AddToGroup(ctx, login(t, "carol"), editors), useradmin.ErrUserNotFound)
}
