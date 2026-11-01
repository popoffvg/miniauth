package postgres_test

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP uses HMAC-SHA-1.
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/popoffvg/sfsm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/providers/totp"
	"github.com/popoffvg/miniauth/internal/users"
)

// A disable that waits for a confirm MUST lose, so it neither deletes the new credential nor leaves its codes alone.
func TestTOTPDisableLosesToAConfirm(t *testing.T) {
	ctx := t.Context()
	pool := migratedPool(t)
	user := createAccount(t, users.NewService(postgres.NewUserRepository(pool)), "ada")
	repo := postgres.NewTOTPRepository(pool)
	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	none := totp.EnrollmentState{Stage: totp.StageNone}
	enrollment := totp.NewEnrollmentID()
	pending := totp.EnrollmentState{Stage: totp.StagePending, Version: 1, CreatedAt: createdAt, Enrollment: enrollment, Cause: &totp.EnrollmentEvent{Kind: totp.EventBegin, At: createdAt, Sealed: totp.SealedSecret("sealed"), Enrollment: enrollment}}
	require.NoError(t, repo.Write(ctx, user.ID, none, pending))
	userID := pgtype.UUID{Bytes: user.ID.Bytes(), Valid: true}
	stamp := func(at time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: at.UTC(), Valid: true} }

	// The confirm transaction takes the credential row first, as a confirm write does, and commits after the disable starts.
	confirm, err := pool.Begin(ctx)
	require.NoError(t, err)
	q := sqlcgen.New(pool).WithTx(confirm)
	n, err := q.ConfirmTOTP(ctx, sqlcgen.ConfirmTOTPParams{ConfirmedAt: stamp(time.Now()), LastStep: 1, NextVersion: 2, UserID: userID, EnrollmentID: pgtype.UUID{Bytes: enrollment.Bytes(), Valid: true}, PrevVersion: 1})
	require.NoError(t, err)
	require.Equal(t, int64(1), n)

	disabled := make(chan error, 1)
	go func() {
		disabled <- repo.Write(ctx, user.ID, pending, totp.EnrollmentState{Stage: totp.StageDisabled, Version: 2, Cause: &totp.EnrollmentEvent{Kind: totp.EventDisable}})
	}()
	require.Eventually(t, func() bool {
		var waiting int
		_ = pool.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()").Scan(&waiting)
		return waiting > 0
	}, 5*time.Second, 10*time.Millisecond, "the disable MUST wait for the credential row")

	code := sha256.Sum256([]byte("recovery-code"))
	require.NoError(t, q.DeleteRecoveryCodes(ctx, userID))
	require.NoError(t, q.InsertRecoveryCodes(ctx, sqlcgen.InsertRecoveryCodesParams{UserID: userID, CodeHashes: [][]byte{code[:]}}))
	require.NoError(t, confirm.Commit(ctx))
	require.ErrorIs(t, <-disabled, sfsm.ErrStaleState)

	var codes int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM recovery_codes").Scan(&codes))
	assert.Equal(t, 1, codes, "the recovery codes MUST stay with the confirmed credential")
	credential, err := repo.Find(ctx, user.ID)
	require.NoError(t, err)
	assert.True(t, credential.Confirmed())
}

// raceTOTPStore makes the first two Find calls wait for each other, so both requests read the same row.
type raceTOTPStore struct {
	*postgres.TOTPRepository
	reads sync.WaitGroup
}

func (s *raceTOTPStore) Find(ctx context.Context, userID users.ID) (totp.Credential, error) {
	credential, err := s.TOTPRepository.Find(ctx, userID)
	s.reads.Done()
	s.reads.Wait()
	return credential, err
}

func TestTOTPConfirmAndDisableOneWins(t *testing.T) {
	ctx := t.Context()
	pool := migratedPool(t)
	user := createAccount(t, users.NewService(postgres.NewUserRepository(pool)), "ada")
	repo := postgres.NewTOTPRepository(pool)
	attempts := postgres.NewAttemptRepository(pool)
	key := randomKey(t)
	now := time.Now()
	clock := func() time.Time { return now }
	plain, err := totp.NewServiceWithClock(repo, attempts, key, clock, nil)
	require.NoError(t, err)
	enrollment, err := plain.Begin(ctx, user)
	require.NoError(t, err)
	code, err := totp.ParseCode(rfc6238Code(t, enrollment.Secret.Reveal(), now))
	require.NoError(t, err)

	race := &raceTOTPStore{TOTPRepository: repo}
	race.reads.Add(2)
	service, err := totp.NewServiceWithClock(race, attempts, key, clock, nil)
	require.NoError(t, err)
	results := make(chan error, 2)
	go func() {
		_, err := service.Confirm(ctx, user.ID, code)
		results <- err
	}()
	go func() { results <- service.Disable(ctx, user.ID) }()

	errs := []error{<-results, <-results}
	won := 0
	for _, err := range errs {
		if err == nil {
			won++
			continue
		}
		require.ErrorIs(t, err, sfsm.ErrStaleState)
	}
	assert.Equal(t, 1, won, "exactly one of confirm and disable MUST win: %v", errs)
}

// A request that read one enrollment MUST NOT change the next enrollment of the same user.
func TestTOTPStaleRequestMissesANewEnrollment(t *testing.T) {
	ctx := t.Context()
	pool := migratedPool(t)
	user := createAccount(t, users.NewService(postgres.NewUserRepository(pool)), "ada")
	repo := postgres.NewTOTPRepository(pool)
	now := time.Now()
	service, err := totp.NewServiceWithClock(repo, postgres.NewAttemptRepository(pool), randomKey(t), func() time.Time { return now }, nil)
	require.NoError(t, err)
	enroll := func() totp.Credential {
		enrollment, beginErr := service.Begin(ctx, user)
		require.NoError(t, beginErr)
		code, codeErr := totp.ParseCode(rfc6238Code(t, enrollment.Secret.Reveal(), now))
		require.NoError(t, codeErr)
		_, confirmErr := service.Confirm(ctx, user.ID, code)
		require.NoError(t, confirmErr)
		credential, findErr := repo.Find(ctx, user.ID)
		require.NoError(t, findErr)
		return credential
	}
	old := enroll()
	require.NoError(t, service.Disable(ctx, user.ID))
	fresh := enroll()
	require.Equal(t, old.Version, fresh.Version, "the test needs a new enrollment at the old version")

	stale := totp.EnrollmentState{Stage: totp.StageConfirmed, Version: old.Version, CreatedAt: old.CreatedAt, Enrollment: old.Enrollment}
	err = repo.Write(ctx, user.ID, stale, totp.EnrollmentState{Stage: totp.StageDisabled, Version: old.Version + 1, Cause: &totp.EnrollmentEvent{Kind: totp.EventDisable}})
	require.ErrorIs(t, err, sfsm.ErrStaleState, "a disable of the old enrollment MUST NOT delete the new one")

	used, err := repo.UseStep(ctx, user.ID, old.Enrollment, fresh.LastStep+1)
	require.NoError(t, err)
	assert.False(t, used, "a code checked against the old secret MUST NOT move the new credential")
}

func randomKey(t *testing.T) totp.Key {
	t.Helper()
	raw := make([]byte, 32)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	key, err := totp.ParseKey(base64.StdEncoding.EncodeToString(raw))
	require.NoError(t, err)
	return key
}

// rfc6238Code is the code of the base32 secret at at: HMAC-SHA-1, 6 digits, 30 s.
func rfc6238Code(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	require.NoError(t, err)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/30)) //nolint:gosec // The test clock is after 1970.
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}
