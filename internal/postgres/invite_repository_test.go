package postgres_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/popoffvg/sfsm"
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
	service, err := invites.NewService(repo, func() time.Time { return now }, nil)
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
		later, err := invites.NewService(repo, func() time.Time { return invite.ExpiresAt }, nil)
		require.NoError(t, err)
		_, err = later.Open(ctx, token)
		require.ErrorIs(t, err, invites.ErrInviteGone)
		_, err = later.Accept(ctx, token, login("late"), password)
		require.ErrorIs(t, err, invites.ErrInviteGone)
		_, err = accounts.FindByLogin(ctx, login("late"))
		require.ErrorIs(t, err, users.ErrNotFound)
	})
}

// raceInviteStore makes the first two invite reads wait for each other, so both acceptances read an open invite.
type raceInviteStore struct {
	*postgres.InviteRepository
	reads *sync.WaitGroup
}

func (s raceInviteStore) InTransaction(ctx context.Context, fn func(invites.Transaction) error) error {
	return s.InviteRepository.InTransaction(ctx, func(tx invites.Transaction) error {
		return fn(raceInviteTransaction{Transaction: tx, reads: s.reads})
	})
}

type raceInviteTransaction struct {
	invites.Transaction
	reads *sync.WaitGroup
}

func (t raceInviteTransaction) Find(ctx context.Context, hash invites.TokenHash) (invites.Invite, error) {
	invite, err := t.Transaction.Find(ctx, hash)
	t.reads.Done()
	t.reads.Wait()
	return invite, err
}

func TestInviteAcceptanceRaceOneWins(t *testing.T) {
	ctx := t.Context()
	pool := migratedPool(t)
	repo, err := postgres.NewInviteRepository(pool)
	require.NoError(t, err)
	reads := &sync.WaitGroup{}
	reads.Add(2)
	service, err := invites.NewService(raceInviteStore{InviteRepository: repo, reads: reads}, nil, nil)
	require.NoError(t, err)
	token, _, err := service.Create(ctx, groups.Name{})
	require.NoError(t, err)
	password, err := users.NewPassword("invite-password-1")
	require.NoError(t, err)

	results := make(chan error, 2)
	for _, raw := range []string{"first", "second"} {
		name, err := users.ParseLogin(raw)
		require.NoError(t, err)
		go func() {
			_, err := service.Accept(ctx, token, name, password)
			results <- err
		}()
	}
	errs := []error{<-results, <-results}
	won := 0
	for _, err := range errs {
		if err == nil {
			won++
			continue
		}
		require.ErrorIs(t, err, sfsm.ErrStaleState)
		require.ErrorIs(t, err, invites.ErrInviteGone)
	}
	assert.Equal(t, 1, won, "exactly one acceptance MUST win: %v", errs)
}

// An acceptance that read its clock before the invite expired MUST still fail once the database time is past the expiry.
func TestInviteClaimChecksTheExpiryWithTheDatabaseTime(t *testing.T) {
	ctx := t.Context()
	pool := migratedPool(t)
	repo, err := postgres.NewInviteRepository(pool)
	require.NoError(t, err)
	late := time.Now().Add(-invites.Lifetime - time.Minute)
	service, err := invites.NewService(repo, func() time.Time { return late }, nil)
	require.NoError(t, err)
	token, _, err := service.Create(ctx, groups.Name{})
	require.NoError(t, err)
	password, err := users.NewPassword("invite-password-1")
	require.NoError(t, err)
	login, err := users.ParseLogin("bea")
	require.NoError(t, err)

	_, err = service.Accept(ctx, token, login, password)
	require.ErrorIs(t, err, invites.ErrInviteGone)
}
