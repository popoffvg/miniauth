package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/recovery"
	"github.com/popoffvg/miniauth/internal/users"
)

// txStarter opens a transaction. *pgxpool.Pool and pgx.Tx fit.
type txStarter interface {
	sqlcgen.DBTX
	Begin(ctx context.Context) (pgx.Tx, error)
}

// PasswordResetRepository is the PostgreSQL adapter for reset links.
type PasswordResetRepository struct {
	db txStarter
	q  *sqlcgen.Queries
}

// NewPasswordResetRepository returns a repository that uses db for queries and transactions.
func NewPasswordResetRepository(db txStarter) *PasswordResetRepository {
	return &PasswordResetRepository{db: db, q: sqlcgen.New(db)}
}

var _ recovery.Store = (*PasswordResetRepository)(nil)

// FindAccount returns the user with login, active or disabled.
func (r *PasswordResetRepository) FindAccount(ctx context.Context, login users.Login) (users.User, error) {
	return userFromRow(r.q.GetUserByLogin(ctx, login.String()))
}

// Create inserts the hash of a reset link.
func (r *PasswordResetRepository) Create(ctx context.Context, reset recovery.Reset) error {
	err := r.q.InsertPasswordReset(ctx, sqlcgen.InsertPasswordResetParams{
		TokenHash: reset.Hash[:],
		UserID:    pgUUIDBytes(reset.UserID.Bytes()),
		CreatedAt: pgTime(reset.CreatedAt),
		ExpiresAt: pgTime(reset.ExpiresAt),
	})
	if err != nil {
		return resetError("create password reset", err)
	}
	return nil
}

// FindOpen returns the open link stored under hash.
// The returned hash is the column value, so the caller can compare it in constant time.
func (r *PasswordResetRepository) FindOpen(ctx context.Context, hash recovery.TokenHash, now time.Time) (recovery.Reset, error) {
	row, err := r.q.GetOpenPasswordReset(ctx, sqlcgen.GetOpenPasswordResetParams{
		TokenHash: hash[:],
		Now:       pgTime(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return recovery.Reset{}, recovery.ErrInvalidToken
	}
	if err != nil {
		return recovery.Reset{}, resetError("load password reset", err)
	}
	if !row.UserID.Valid || !row.CreatedAt.Valid || !row.ExpiresAt.Valid {
		return recovery.Reset{}, errors.New("postgres: password reset row is incomplete")
	}
	var stored recovery.TokenHash
	if len(row.TokenHash) != len(stored) {
		return recovery.Reset{}, fmt.Errorf("postgres: password reset hash length %d", len(row.TokenHash))
	}
	copy(stored[:], row.TokenHash)
	return recovery.Reset{
		Hash:      stored,
		UserID:    users.IDFromBytes(row.UserID.Bytes),
		CreatedAt: row.CreatedAt.Time.UTC(),
		ExpiresAt: row.ExpiresAt.Time.UTC(),
	}, nil
}

// Redeem sets the password through the open link under hash in one transaction.
// The row lock makes a second, concurrent use of the link wait and then find it used.
// The expiry is checked with the database time. now is the used time only.
func (r *PasswordResetRepository) Redeem(ctx context.Context, hash recovery.TokenHash, password users.PasswordHash, now time.Time) (users.User, error) {
	encoded := password.Encoded()
	if encoded == "" {
		return users.User{}, errors.New("postgres: password hash is empty")
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return users.User{}, resetError("begin password reset", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	q := r.q.WithTx(tx)

	userID, err := q.LockOpenPasswordReset(ctx, hash[:])
	if errors.Is(err, pgx.ErrNoRows) {
		return users.User{}, recovery.ErrInvalidToken
	}
	if err != nil {
		return users.User{}, resetError("lock password reset", err)
	}
	n, err := q.SetPasswordHash(ctx, sqlcgen.SetPasswordHashParams{PasswordHash: encoded, UserID: userID})
	if err != nil {
		return users.User{}, resetError("set password hash", err)
	}
	if n != 1 {
		return users.User{}, errors.New("postgres: user has no password identity")
	}
	if err = q.MarkPasswordResetUsed(ctx, sqlcgen.MarkPasswordResetUsedParams{UsedAt: pgTime(now), TokenHash: hash[:]}); err != nil {
		return users.User{}, resetError("mark password reset used", err)
	}
	if err = q.DeleteUserSessions(ctx, userID); err != nil {
		return users.User{}, resetError("delete user sessions", err)
	}
	if err = q.DeleteOpenPasswordResets(ctx, userID); err != nil {
		return users.User{}, resetError("delete open password resets", err)
	}
	account, err := userFromRow(q.GetUserByID(ctx, userID))
	if err != nil {
		return users.User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return users.User{}, resetError("commit password reset", err)
	}
	return account, nil
}

// Cleanup deletes the links that expired before before.
func (r *PasswordResetRepository) Cleanup(ctx context.Context, before time.Time) error {
	if err := r.q.DeletePasswordResetsBefore(ctx, pgTime(before)); err != nil {
		return resetError("delete expired password resets", err)
	}
	return nil
}

// resetError does not return the PostgreSQL message: a constraint failure can echo the row,
// and the row holds the token hash or the password hash.
func resetError(action string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return fmt.Errorf("postgres: %s: %s (SQLSTATE %s)", action, pgErr.ConstraintName, pgErr.Code)
	}
	return fmt.Errorf("postgres: %s: %w", action, err)
}
