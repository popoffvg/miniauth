package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

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
// Confirm and Delete need a db that can begin a transaction, such as a pool.
func NewTOTPRepository(db sqlcgen.DBTX) *TOTPRepository {
	begin, _ := db.(txBeginner)
	return &TOTPRepository{q: sqlcgen.New(db), begin: begin}
}

var _ totp.Store = (*TOTPRepository)(nil)

// SavePending stores sealed as the enrollment of userID that waits for its first code.
func (r *TOTPRepository) SavePending(ctx context.Context, userID users.ID, sealed totp.SealedSecret, createdAt time.Time) error {
	n, err := r.q.UpsertPendingTOTP(ctx, sqlcgen.UpsertPendingTOTPParams{
		UserID:       pgUUIDBytes(userID.Bytes()),
		SealedSecret: sealed,
		CreatedAt:    pgTime(createdAt),
	})
	if err != nil {
		return fmt.Errorf("postgres: save TOTP enrollment: %w", err)
	}
	if n == 0 {
		return totp.ErrEnrolled
	}
	return nil
}

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
	}, nil
}

// Confirm turns on the enrollment created at createdAt and replaces the recovery codes in one transaction.
func (r *TOTPRepository) Confirm(ctx context.Context, userID users.ID, createdAt time.Time, step totp.TimeStep, codes []totp.RecoveryHash, at time.Time) error {
	if r.begin == nil {
		return errors.New("postgres: TOTP repository cannot begin a transaction")
	}
	id := pgUUIDBytes(userID.Bytes())
	hashes := make([][]byte, len(codes))
	for i := range codes {
		hashes[i] = codes[i][:]
	}
	err := pgx.BeginFunc(ctx, r.begin, func(tx pgx.Tx) error {
		q := r.q.WithTx(tx)
		n, err := q.ConfirmTOTP(ctx, sqlcgen.ConfirmTOTPParams{
			ConfirmedAt: pgTime(at),
			LastStep:    int64(step),
			UserID:      id,
			CreatedAt:   pgTime(createdAt),
		})
		if err != nil {
			return fmt.Errorf("postgres: update TOTP: %w", err)
		}
		if n == 0 {
			return totp.ErrNoEnrollment
		}
		if err = q.DeleteRecoveryCodes(ctx, id); err != nil {
			return fmt.Errorf("postgres: delete recovery codes: %w", err)
		}
		if err = q.InsertRecoveryCodes(ctx, sqlcgen.InsertRecoveryCodesParams{UserID: id, CodeHashes: hashes}); err != nil {
			return fmt.Errorf("postgres: insert recovery codes: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("postgres: confirm TOTP: %w", err)
	}
	return nil
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

// Delete removes the credential and the recovery codes of userID in one transaction.
// The credential goes first: its row lock makes a Confirm that holds the row finish first,
// so the codes it inserts are deleted too. A later Confirm finds no row.
func (r *TOTPRepository) Delete(ctx context.Context, userID users.ID) error {
	if r.begin == nil {
		return errors.New("postgres: TOTP repository cannot begin a transaction")
	}
	id := pgUUIDBytes(userID.Bytes())
	err := pgx.BeginFunc(ctx, r.begin, func(tx pgx.Tx) error {
		q := r.q.WithTx(tx)
		if err := q.DeleteTOTP(ctx, id); err != nil {
			return fmt.Errorf("postgres: delete TOTP: %w", err)
		}
		if err := q.DeleteRecoveryCodes(ctx, id); err != nil {
			return fmt.Errorf("postgres: delete recovery codes: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("postgres: disable TOTP: %w", err)
	}
	return nil
}
