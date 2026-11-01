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
	editors := createGroup(t, pool, "editors")
	missing, err := groups.ParseName("missing")
	require.NoError(t, err)

	t.Run("membership", func(t *testing.T) {
		require.NoError(t, repo.AddMember(ctx, ada.ID, editors))
		require.NoError(t, repo.AddMember(ctx, ada.ID, editors), "a stored pair changes nothing")
		require.NoError(t, repo.AddMember(ctx, ada.ID, groups.Admins()))
		require.ErrorIs(t, repo.AddMember(ctx, users.NewID(), editors), useradmin.ErrUserNotFound)
		require.ErrorIs(t, repo.AddMember(ctx, ada.ID, missing), groups.ErrGroupNotFound)
		require.ErrorIs(t, repo.RemoveMember(ctx, bob.ID, editors), useradmin.ErrNotMember)

		list, err := repo.ListAccounts(ctx)
		require.NoError(t, err)
		require.Len(t, list, 2)
		assert.Equal(t, "ada", list[0].User.Login.String())
		assert.Equal(t, []groups.Name{groups.Admins(), editors, groups.Users()}, list[0].Groups)
		assert.Equal(t, []groups.Name{groups.Users()}, list[1].Groups)
		assert.Zero(t, list[1].Devices)
		assert.True(t, list[1].LastSeen.IsZero())

		require.NoError(t, repo.RemoveMember(ctx, ada.ID, editors))
		list, err = repo.ListAccounts(ctx)
		require.NoError(t, err)
		assert.Equal(t, []groups.Name{groups.Admins(), groups.Users()}, list[0].Groups)
	})

	t.Run("disable deletes the sessions and enable clears the time", func(t *testing.T) {
		browser := sessions.NewService(postgres.NewSessionRepository(pool))
		id, _, err := browser.Start(ctx, bob.ID, loginflow.Factors(loginflow.FactorPassword))
		require.NoError(t, err)
		at := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

		active := useradmin.AccountState{User: bob.ID, Status: useradmin.StatusActive}
		disabled := useradmin.AccountState{User: bob.ID, Status: useradmin.StatusDisabled, DisabledAt: at}

		require.NoError(t, repo.Write(ctx, bob.ID, active, disabled))
		_, _, err = browser.Open(ctx, id)
		require.ErrorIs(t, err, sessions.ErrNotFound, "a disabled user keeps no session")
		later := disabled
		later.DisabledAt = at.Add(time.Hour)
		require.ErrorIs(t, repo.Write(ctx, bob.ID, active, later), sfsm.ErrStaleState, "a disable that read an active user loses")
		loaded, err := accounts.Find(ctx, bob.ID)
		require.NoError(t, err)
		assert.Equal(t, at, loaded.DisabledAt, "a second disable keeps the first time")

		require.NoError(t, repo.Write(ctx, bob.ID, disabled, active))
		loaded, err = accounts.Find(ctx, bob.ID)
		require.NoError(t, err)
		assert.False(t, loaded.Disabled())
		require.ErrorIs(t, repo.Write(ctx, bob.ID, disabled, active), sfsm.ErrStaleState, "an enable that read a disabled user loses")

		require.ErrorIs(t, repo.Write(ctx, users.NewID(), active, disabled), sfsm.ErrStaleState)
	})
}

// raceAccounts makes the first two reads of a user wait for each other, so both changes read the same status.
type raceAccounts struct {
	*users.Service
	reads sync.WaitGroup
}

func (a *raceAccounts) FindByLogin(ctx context.Context, login users.Login) (users.User, error) {
	user, err := a.Service.FindByLogin(ctx, login)
	a.reads.Done()
	a.reads.Wait()
	return user, err
}

func TestUserDisableRaceOneWins(t *testing.T) {
	ctx := t.Context()
	pool := migratedPool(t)
	accounts := users.NewService(postgres.NewUserRepository(pool))
	bob := createAccount(t, accounts, "bob")
	repo, err := postgres.NewUserAdminRepository(pool)
	require.NoError(t, err)
	race := &raceAccounts{Service: accounts}
	race.reads.Add(2)
	service := useradmin.NewService(repo, race, nil)

	results := make(chan error, 2)
	for range 2 {
		go func() { results <- service.Disable(ctx, useradmin.Actor{}, bob.Login) }()
	}
	errs := []error{<-results, <-results}
	won := 0
	for _, err := range errs {
		if err == nil {
			won++
			continue
		}
		require.ErrorIs(t, err, sfsm.ErrStaleState)
	}
	assert.Equal(t, 1, won, "exactly one disable MUST win: %v", errs)
	loaded, err := accounts.Find(ctx, bob.ID)
	require.NoError(t, err)
	assert.True(t, loaded.Disabled())
}
