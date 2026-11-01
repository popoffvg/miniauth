package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/popoffvg/sfsm"

	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/providers/totp"
	"github.com/popoffvg/miniauth/internal/users"
)

// TOTPRepository is the PostgreSQL adapter for TOTP credentials and recovery codes.
type TOTPRepository struct {
	q     *sqlcgen.Queries
	begin txBeginner
}

// NewTOTPRepository returns a repository that uses db for queries.
// A confirm and a delete need a db that can begin a transaction, such as a pool.
func NewTOTPRepository(db sqlcgen.DBTX) *TOTPRepository {
	begin, _ := db.(txBeginner)
	return &TOTPRepository{q: sqlcgen.New(db), begin: begin}
}

var _ totp.Store = (*TOTPRepository)(nil)

// Find returns the credential of userID.
func (r *TOTPRepository) Find(ctx context.Context, userID users.ID) (totp.Credential, error) {
	row, err := r.q.GetTOTPCredential(ctx, pgUUIDBytes(userID.Bytes()))
	if errors.Is(err, pgx.ErrNoRows) {
		return totp.Credential{}, totp.ErrNotEnrolled
	}
	if err != nil {
		return totp.Credential{}, fmt.Errorf("postgres: load TOTP: %w", err)
	}
	if !row.CreatedAt.Valid {
		return totp.Credential{}, errors.New("postgres: TOTP created_at is null")
	}
	return totp.Credential{
		UserID:      users.IDFromBytes(row.UserID.Bytes),
		Sealed:      row.SealedSecret,
		LastStep:    totp.TimeStep(row.LastStep),
		CreatedAt:   row.CreatedAt.Time.UTC(),
		ConfirmedAt: optionalTime(row.ConfirmedAt),
		Version:     totp.EnrollmentVersion(row.Version),
	}, nil
}

// Write stores one enrollment transition. Zero rows changed is sfsm.ErrStaleState.
func (r *TOTPRepository) Write(ctx context.Context, userID users.ID, prev, next totp.EnrollmentState) error {
	if next.Version != prev.Version+1 || next.Cause == nil {
		return fmt.Errorf("postgres: TOTP enrollment %d does not follow %d", next.Version, prev.Version)
	}
	id := pgUUIDBytes(userID.Bytes())
	var n int64
	var err error
	switch {
	case next.Stage == totp.StagePending && !prev.Stage.Stored():
		n, err = r.q.InsertPendingTOTP(ctx, sqlcgen.InsertPendingTOTPParams{
			UserID:       id,
			SealedSecret: next.Cause.Sealed,
			CreatedAt:    pgTime(next.CreatedAt),
			Version:      int64(next.Version),
		})
	case next.Stage == totp.StagePending:
		n, err = r.q.ReplacePendingTOTP(ctx, sqlcgen.ReplacePendingTOTPParams{
			SealedSecret: next.Cause.Sealed,
			CreatedAt:    pgTime(next.CreatedAt),
			NextVersion:  int64(next.Version),
			UserID:       id,
			PrevVersion:  int64(prev.Version),
		})
	case next.Stage == totp.StageConfirmed:
		n, err = r.confirm(ctx, id, prev, next)
	default:
		n, err = r.delete(ctx, id, prev.Version)
	}
	if err != nil {
		return fmt.Errorf("postgres: write TOTP %s: %w", next.Stage, err)
	}
	if n == 0 {
		return fmt.Errorf("postgres: write TOTP %s: %w", next.Stage, sfsm.ErrStaleState)
	}
	return nil
}

// confirm turns on the enrollment of prev and replaces the recovery codes in one transaction.
func (r *TOTPRepository) confirm(ctx context.Context, id pgtype.UUID, prev, next totp.EnrollmentState) (int64, error) {
	if r.begin == nil {
		return 0, errors.New("postgres: TOTP repository cannot begin a transaction")
	}
	hashes := make([][]byte, len(next.Cause.RecoveryCodes))
	for i := range next.Cause.RecoveryCodes {
		hashes[i] = next.Cause.RecoveryCodes[i][:]
	}
	var n int64
	err := pgx.BeginFunc(ctx, r.begin, func(tx pgx.Tx) error {
		q := r.q.WithTx(tx)
		var err error
		n, err = q.ConfirmTOTP(ctx, sqlcgen.ConfirmTOTPParams{
			ConfirmedAt: pgTime(next.Cause.At),
			LastStep:    int64(next.Cause.Step),
			NextVersion: int64(next.Version),
			UserID:      id,
			CreatedAt:   pgTime(prev.CreatedAt),
			PrevVersion: int64(prev.Version),
		})
		if err != nil || n == 0 {
			return err
		}
		if err = q.DeleteRecoveryCodes(ctx, id); err != nil {
			return fmt.Errorf("delete recovery codes: %w", err)
		}
		if err = q.InsertRecoveryCodes(ctx, sqlcgen.InsertRecoveryCodesParams{UserID: id, CodeHashes: hashes}); err != nil {
			return fmt.Errorf("insert recovery codes: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("confirm transaction: %w", err)
	}
	return n, nil
}

// UseStep stores step when it is later than the stored step.
func (r *TOTPRepository) UseStep(ctx context.Context, userID users.ID, step totp.TimeStep) (bool, error) {
	n, err := r.q.UseTOTPStep(ctx, sqlcgen.UseTOTPStepParams{Step: int64(step), UserID: pgUUIDBytes(userID.Bytes())})
	if err != nil {
		return false, fmt.Errorf("postgres: use TOTP step: %w", err)
	}
	return n == 1, nil
}

// UseRecoveryCode marks the unused code with hash as used at at.
func (r *TOTPRepository) UseRecoveryCode(ctx context.Context, userID users.ID, hash totp.RecoveryHash, at time.Time) (bool, error) {
	n, err := r.q.UseRecoveryCode(ctx, sqlcgen.UseRecoveryCodeParams{
		UsedAt:   pgTime(at),
		UserID:   pgUUIDBytes(userID.Bytes()),
		CodeHash: hash[:],
	})
	if err != nil {
		return false, fmt.Errorf("postgres: use recovery code: %w", err)
	}
	return n == 1, nil
}

// delete removes the credential at version and the recovery codes in one transaction.
// The credential goes first: its row lock makes a confirm that holds the row finish first.
// The confirm moves the version, so this delete then changes zero rows and the codes stay with their credential.
func (r *TOTPRepository) delete(ctx context.Context, id pgtype.UUID, version totp.EnrollmentVersion) (int64, error) {
	if r.begin == nil {
		return 0, errors.New("postgres: TOTP repository cannot begin a transaction")
	}
	var n int64
	err := pgx.BeginFunc(ctx, r.begin, func(tx pgx.Tx) error {
		q := r.q.WithTx(tx)
		var err error
		n, err = q.DeleteTOTP(ctx, sqlcgen.DeleteTOTPParams{UserID: id, Version: int64(version)})
		if err != nil || n == 0 {
			return err
		}
		if err = q.DeleteRecoveryCodes(ctx, id); err != nil {
			return fmt.Errorf("delete recovery codes: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("delete transaction: %w", err)
	}
	return n, nil
}
