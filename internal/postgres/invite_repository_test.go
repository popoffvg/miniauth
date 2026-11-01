package postgres_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/groups"
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
	groupRepo, err := postgres.NewGroupRepository(pool)
	require.NoError(t, err)
	groupAdmin, err := postgres.NewGroupAdminRepository(pool)
	require.NoError(t, err)
	ops, err := groups.ParseName("ops")
	require.NoError(t, err)
	require.NoError(t, groupAdmin.CreateGroup(ctx, ops, time.Now()))
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

	t.Run("an unknown group is refused", func(t *testing.T) {
		missing, err := groups.ParseName("missing")
		require.NoError(t, err)
		_, _, err = service.Create(ctx, missing)
		require.ErrorIs(t, err, groups.ErrGroupNotFound)
	})

	t.Run("a zero group invites to users", func(t *testing.T) {
		_, invite, err := service.Create(ctx, groups.Name{})
		require.NoError(t, err)
		assert.Equal(t, groups.Users(), invite.Group)
	})

	t.Run("a taken login keeps the invite unused", func(t *testing.T) {
		token, _, err := service.Create(ctx, ops)
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
		token, _, err := service.Create(ctx, ops)
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
		user := stored.UserID
		names, err := groupRepo.List(ctx, user)
		require.NoError(t, err)
		assert.Equal(t, []groups.Name{ops, groups.Users()}, names, "the account joins the group of the invite and users")
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
		token, invite, err := service.Create(ctx, ops)
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
