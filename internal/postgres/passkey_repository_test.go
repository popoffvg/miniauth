package postgres_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/providers/passkey"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestPasskeyRepository(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))
	accounts := postgres.NewUserRepository(pool)
	ada := createAccount(t, users.NewService(accounts), "ada")
	bea := createAccount(t, users.NewService(accounts), "bea")
	repo := postgres.NewPasskeyRepository(pool)
	name, err := passkey.ParseName("laptop")
	require.NoError(t, err)
	created := time.Now().UTC().Truncate(time.Microsecond)
	passkeyRow := passkey.Passkey{
		ID:             passkey.NewID(),
		UserID:         ada.ID,
		CredentialID:   passkey.CredentialID("credential-1"),
		PublicKey:      passkey.PublicKey("cose-key"),
		SignCount:      3,
		Transports:     []passkey.Transport{"internal", "hybrid"},
		AAGUID:         passkey.AAGUID{1, 2, 3},
		BackupEligible: true,
		Name:           name,
		CreatedAt:      created,
	}
	require.NoError(t, repo.Create(ctx, passkeyRow))

	t.Run("a credential id is stored once", func(t *testing.T) {
		again := passkeyRow
		again.ID = passkey.NewID()
		again.UserID = bea.ID
		require.ErrorIs(t, repo.Create(ctx, again), passkey.ErrDuplicate)
	})

	t.Run("find by credential returns the row", func(t *testing.T) {
		got, err := repo.FindByCredential(ctx, passkeyRow.CredentialID)
		require.NoError(t, err)
		assert.Equal(t, passkeyRow, got)
		_, err = repo.FindByCredential(ctx, passkey.CredentialID("other"))
		require.ErrorIs(t, err, passkey.ErrUnknownCredential)
	})

	t.Run("one use wins for one counter value", func(t *testing.T) {
		var wins atomic.Int32
		var wg sync.WaitGroup
		for range 4 {
			wg.Go(func() {
				wrote, err := repo.RecordUse(ctx, passkeyRow.ID, 3, 4, created)
				assert.NoError(t, err)
				if wrote {
					wins.Add(1)
				}
			})
		}
		wg.Wait()
		assert.Equal(t, int32(1), wins.Load())
		got, err := repo.FindByCredential(ctx, passkeyRow.CredentialID)
		require.NoError(t, err)
		assert.Equal(t, passkey.SignCount(4), got.SignCount)
		assert.Equal(t, created, got.LastUsedAt)
	})

	t.Run("a passkey of another user is not deleted", func(t *testing.T) {
		require.ErrorIs(t, repo.Delete(ctx, bea.ID, passkeyRow.ID), passkey.ErrNotFound)
		list, err := repo.List(ctx, ada.ID)
		require.NoError(t, err)
		require.Len(t, list, 1)
		empty, err := repo.List(ctx, bea.ID)
		require.NoError(t, err)
		assert.Empty(t, empty)
	})

	t.Run("a disabled user has no credential", func(t *testing.T) {
		require.NoError(t, accounts.Disable(ctx, ada.ID, time.Now()))
		_, err := repo.FindByCredential(ctx, passkeyRow.CredentialID)
		require.ErrorIs(t, err, passkey.ErrUnknownCredential)
		require.NoError(t, repo.Delete(ctx, ada.ID, passkeyRow.ID))
		require.ErrorIs(t, repo.Delete(ctx, ada.ID, passkeyRow.ID), passkey.ErrNotFound)
	})
}

func TestFlowChallengeIsTakenOnce(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))
	store := postgres.NewFlowStore(pool)
	returnURL, err := loginflow.NewReturnURL("https://example.test/app")
	require.NoError(t, err)
	id, _, err := loginflow.NewLoginFlows(store).Start(ctx, returnURL)
	require.NoError(t, err)

	_, err = store.TakeChallenge(ctx, id)
	require.ErrorIs(t, err, loginflow.ErrChallengeNotFound)
	require.NoError(t, store.SaveChallenge(ctx, id, loginflow.Challenge("challenge-1")))

	var taken atomic.Int32
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			got, takeErr := store.TakeChallenge(ctx, id)
			if takeErr == nil {
				assert.Equal(t, loginflow.Challenge("challenge-1"), got)
				taken.Add(1)
				return
			}
			assert.ErrorIs(t, takeErr, loginflow.ErrChallengeNotFound)
		})
	}
	wg.Wait()
	assert.Equal(t, int32(1), taken.Load())

	flow, err := store.Load(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, loginflow.StateAwaiting, flow.State)

	missing, err := loginflow.NewFlowID()
	require.NoError(t, err)
	require.ErrorIs(t, store.SaveChallenge(ctx, missing, loginflow.Challenge("challenge-2")), loginflow.ErrFlowNotFound)
}
