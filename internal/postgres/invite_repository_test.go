package postgres_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/invites"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestInviteAcceptance(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))

	accounts := users.NewService(postgres.NewUserRepository(pool))
	createAccount(t, accounts, "taken")
	grantRepo, err := postgres.NewAccessRepository(pool)
	require.NoError(t, err)
	grants := access.NewService(grantRepo, accounts)
	app := accessResource(t, "app", "app.example.test", "/")
	_, err = grants.CreateResource(ctx, app.Name, app.URL)
	require.NoError(t, err)
	repo, err := postgres.NewInviteRepository(pool)
	require.NoError(t, err)
	now := time.Now()
	service, err := invites.NewService(repo, func() time.Time { return now })
	require.NoError(t, err)
	password, err := users.NewPassword("invite-password-1")
	require.NoError(t, err)
	login := func(raw string) users.Login {
		parsed, err := users.ParseLogin(raw)
		require.NoError(t, err)
		return parsed
	}

	t.Run("an unknown resource is refused", func(t *testing.T) {
		_, _, err := service.Create(ctx, accessResource(t, "missing", "x.example.test", "/").Name)
		require.ErrorIs(t, err, access.ErrResourceNotFound)
	})

	t.Run("a taken login keeps the invite unused", func(t *testing.T) {
		token, _, err := service.Create(ctx, app.Name)
		require.NoError(t, err)
		_, err = service.Accept(ctx, token, login("taken"), password)
		require.ErrorIs(t, err, users.ErrLoginTaken)
		stored, err := repo.Find(ctx, token.Hash())
		require.NoError(t, err)
		assert.True(t, stored.UsedAt.IsZero())
		_, err = service.Open(ctx, token)
		require.NoError(t, err)
	})

	t.Run("two parallel acceptances create one account", func(t *testing.T) {
		token, _, err := service.Create(ctx, app.Name)
		require.NoError(t, err)
		logins := []users.Login{login("first"), login("second")}
		errs := make([]error, len(logins))
		var wg sync.WaitGroup
		for i, name := range logins {
			wg.Go(func() {
				_, errs[i] = service.Accept(ctx, token, name, password)
			})
		}
		wg.Wait()
		var won int
		for _, err := range errs {
			if err == nil {
				won++
				continue
			}
			require.ErrorIs(t, err, invites.ErrInviteGone)
		}
		require.Equal(t, 1, won)
		stored, err := repo.Find(ctx, token.Hash())
		require.NoError(t, err)
		assert.False(t, stored.UsedAt.IsZero())
		require.NotZero(t, stored.UserID)
		entries, err := grants.ListGrants(ctx, access.GrantFilter{Resource: app.Name})
		require.NoError(t, err)
		require.Len(t, entries, 1)
		user, ok := entries[0].Grant.Subject.User()
		require.True(t, ok)
		assert.Equal(t, stored.UserID, user)
		var created []users.ID
		for _, name := range logins {
			account, err := accounts.FindByLogin(ctx, name)
			if err == nil {
				created = append(created, account.ID)
				continue
			}
			require.ErrorIs(t, err, users.ErrNotFound)
		}
		assert.Equal(t, []users.ID{user}, created, "the losing acceptance MUST leave no account")
	})

	t.Run("an expired invite is refused", func(t *testing.T) {
		token, invite, err := service.Create(ctx, app.Name)
		require.NoError(t, err)
		later, err := invites.NewService(repo, func() time.Time { return invite.ExpiresAt })
		require.NoError(t, err)
		_, err = later.Open(ctx, token)
		require.ErrorIs(t, err, invites.ErrInviteGone)
		_, err = later.Accept(ctx, token, login("late"), password)
		require.ErrorIs(t, err, invites.ErrInviteGone)
		_, err = accounts.FindByLogin(ctx, login("late"))
		require.ErrorIs(t, err, users.ErrNotFound)
	})
}
