package postgres_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestGroupMembershipRoundTrip(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))

	accounts := users.NewService(postgres.NewUserRepository(pool))
	ada := createAccount(t, accounts, "ada")
	repo, err := postgres.NewGroupRepository(pool)
	require.NoError(t, err)
	editors, err := groups.ParseName("Editors")
	require.NoError(t, err)
	readers, err := groups.ParseName("readers")
	require.NoError(t, err)
	require.NoError(t, repo.Add(ctx, ada.ID, editors))
	require.NoError(t, repo.Add(ctx, ada.ID, readers))
	require.ErrorIs(t, repo.Add(ctx, ada.ID, editors), groups.ErrDuplicate)
	require.ErrorIs(t, repo.Add(ctx, users.NewID(), editors), groups.ErrUnknownUser)

	got, err := repo.List(ctx, ada.ID)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "editors", got[0].String())
	assert.Equal(t, "readers", got[1].String())
	loaded, err := accounts.Find(ctx, ada.ID)
	require.NoError(t, err)
	assert.Equal(t, ada.Login, loaded.Login)
	_, err = postgres.NewUserRepository(pool).Find(ctx, users.NewID())
	require.ErrorIs(t, err, users.ErrNotFound)
}
