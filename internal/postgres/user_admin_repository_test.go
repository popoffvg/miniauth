package postgres_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/useradmin"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestUserAdminRepository(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))

	accounts := users.NewService(postgres.NewUserRepository(pool))
	ada := createAccount(t, accounts, "ada")
	bob := createAccount(t, accounts, "bob")
	repo, err := postgres.NewUserAdminRepository(pool)
	require.NoError(t, err)
	editors, err := groups.ParseName("editors")
	require.NoError(t, err)

	t.Run("membership", func(t *testing.T) {
		require.NoError(t, repo.AddMember(ctx, ada.ID, editors))
		require.NoError(t, repo.AddMember(ctx, ada.ID, editors), "a stored pair changes nothing")
		require.NoError(t, repo.AddMember(ctx, ada.ID, groups.Admin()))
		require.ErrorIs(t, repo.AddMember(ctx, users.NewID(), editors), useradmin.ErrUserNotFound)
		require.ErrorIs(t, repo.RemoveMember(ctx, bob.ID, editors), useradmin.ErrNotMember)

		list, err := repo.ListAccounts(ctx)
		require.NoError(t, err)
		require.Len(t, list, 2)
		assert.Equal(t, "ada", list[0].User.Login.String())
		assert.Equal(t, []groups.Name{groups.Admin(), editors}, list[0].Groups)
		assert.Empty(t, list[1].Groups)
		assert.Zero(t, list[1].Devices)
		assert.True(t, list[1].LastSeen.IsZero())

		require.NoError(t, repo.RemoveMember(ctx, ada.ID, editors))
		list, err = repo.ListAccounts(ctx)
		require.NoError(t, err)
		assert.Equal(t, []groups.Name{groups.Admin()}, list[0].Groups)
	})

	t.Run("disable deletes the sessions and enable clears the time", func(t *testing.T) {
		browser := sessions.NewService(postgres.NewSessionRepository(pool))
		id, _, err := browser.Start(ctx, bob.ID, loginflow.Factors(loginflow.FactorPassword))
		require.NoError(t, err)
		at := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

		require.NoError(t, repo.Disable(ctx, bob.ID, at))
		_, _, err = browser.Open(ctx, id)
		require.ErrorIs(t, err, sessions.ErrNotFound, "a disabled user keeps no session")
		require.NoError(t, repo.Disable(ctx, bob.ID, at.Add(time.Hour)))
		loaded, err := accounts.Find(ctx, bob.ID)
		require.NoError(t, err)
		assert.Equal(t, at, loaded.DisabledAt, "a second disable keeps the first time")

		require.NoError(t, repo.Enable(ctx, bob.ID))
		loaded, err = accounts.Find(ctx, bob.ID)
		require.NoError(t, err)
		assert.False(t, loaded.Disabled())

		require.ErrorIs(t, repo.Disable(ctx, users.NewID(), at), useradmin.ErrUserNotFound)
		require.ErrorIs(t, repo.Enable(ctx, users.NewID()), useradmin.ErrUserNotFound)
	})
}
