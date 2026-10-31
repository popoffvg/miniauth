package postgres_test

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/totpstep"
	"github.com/popoffvg/miniauth/internal/users"
)

// A confirm that commits while a disable waits MUST NOT leave recovery codes without a credential.
func TestTOTPDisableWaitsForAConfirm(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))
	login, err := users.ParseLogin("ada")
	require.NoError(t, err)
	password, err := users.NewPassword("ada-password-1")
	require.NoError(t, err)
	user, err := users.NewService(postgres.NewUserRepository(pool)).Create(ctx, login, password)
	require.NoError(t, err)
	repo := postgres.NewTOTPRepository(pool)
	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	require.NoError(t, repo.SavePending(ctx, user.ID, totpstep.SealedSecret("sealed"), createdAt))
	userID := pgtype.UUID{Bytes: user.ID.Bytes(), Valid: true}
	stamp := func(at time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: at.UTC(), Valid: true} }

	// The confirm transaction takes the credential row first, as Confirm does, and commits after the disable starts.
	confirm, err := pool.Begin(ctx)
	require.NoError(t, err)
	q := sqlcgen.New(pool).WithTx(confirm)
	n, err := q.ConfirmTOTP(ctx, sqlcgen.ConfirmTOTPParams{ConfirmedAt: stamp(time.Now()), LastStep: 1, UserID: userID, CreatedAt: stamp(createdAt)})
	require.NoError(t, err)
	require.Equal(t, int64(1), n)

	disabled := make(chan error, 1)
	go func() { disabled <- repo.Delete(ctx, user.ID) }()
	require.Eventually(t, func() bool {
		var waiting int
		_ = pool.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()").Scan(&waiting)
		return waiting > 0
	}, 5*time.Second, 10*time.Millisecond, "the disable MUST wait for the credential row")

	code := sha256.Sum256([]byte("recovery-code"))
	require.NoError(t, q.DeleteRecoveryCodes(ctx, userID))
	require.NoError(t, q.InsertRecoveryCodes(ctx, sqlcgen.InsertRecoveryCodesParams{UserID: userID, CodeHashes: [][]byte{code[:]}}))
	require.NoError(t, confirm.Commit(ctx))
	require.NoError(t, <-disabled)

	var codes int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM recovery_codes").Scan(&codes))
	assert.Zero(t, codes, "the recovery codes of a disabled TOTP MUST be gone")
	_, err = repo.Find(ctx, user.ID)
	require.ErrorIs(t, err, totpstep.ErrNotEnrolled)
}
