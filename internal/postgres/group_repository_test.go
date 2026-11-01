package postgres_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
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
	editors := createGroup(t, pool, "Editors")
	readers := createGroup(t, pool, "readers")
	missing, err := groups.ParseName("missing")
	require.NoError(t, err)
	require.ErrorIs(t, repo.Add(ctx, ada.ID, missing), groups.ErrGroupNotFound)
	require.NoError(t, repo.Add(ctx, ada.ID, editors))
	require.NoError(t, repo.Add(ctx, ada.ID, readers))
	require.ErrorIs(t, repo.Add(ctx, ada.ID, editors), groups.ErrDuplicate)
	require.ErrorIs(t, repo.Add(ctx, users.NewID(), editors), groups.ErrUnknownUser)

	got, err := repo.List(ctx, ada.ID)
	require.NoError(t, err)
	assert.Equal(t, []groups.Name{editors, readers, groups.Users()}, got, "a new account is in users")
	loaded, err := accounts.Find(ctx, ada.ID)
	require.NoError(t, err)
	assert.Equal(t, ada.Login, loaded.Login)
	_, err = postgres.NewUserRepository(pool).Find(ctx, users.NewID())
	require.ErrorIs(t, err, users.ErrNotFound)
}

// createGroup stores a group with the name raw and returns its name.
func createGroup(t *testing.T, db sqlcgen.DBTX, raw string) groups.Name {
	t.Helper()
	name, err := groups.ParseName(raw)
	require.NoError(t, err)
	repo, err := postgres.NewGroupAdminRepository(db)
	require.NoError(t, err)
	require.NoError(t, repo.CreateGroup(t.Context(), name, time.Now()))
	return name
}
