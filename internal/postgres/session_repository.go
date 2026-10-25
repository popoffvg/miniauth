package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

// PostgreSQL foreign_key_violation. The message is not returned:
// a constraint failure can echo the row, and the row holds the session hash.
const pgForeignKeyViolation = "23503"

// SessionRepository is the PostgreSQL adapter for browser sessions.
type SessionRepository struct {
	q *sqlcgen.Queries
}

// NewSessionRepository returns a repository that uses db for queries.
func NewSessionRepository(db sqlcgen.DBTX) *SessionRepository {
	return &SessionRepository{q: sqlcgen.New(db)}
}

var _ sessions.Repository = (*SessionRepository)(nil)

// Create inserts the session hash.
func (r *SessionRepository) Create(ctx context.Context, session sessions.Session, hash sessions.Hash) error {
	err := r.q.InsertSession(ctx, sqlcgen.InsertSessionParams{
		SecretHash: hash[:],
		UserID:     pgUUIDBytes(session.UserID.Bytes()),
		Factors:    int32(session.Factors),
		AuthAt:     pgTime(session.AuthAt),
		ExpiresAt:  pgTime(session.ExpiresAt),
	})
	if err != nil {
		return sessionError("create session", err)
	}
	return nil
}

// Find returns the session stored under hash.
// The returned hash is the column value, so the caller can compare it in constant time.
func (r *SessionRepository) Find(ctx context.Context, hash sessions.Hash) (sessions.Session, sessions.Hash, error) {
	row, err := r.q.GetSession(ctx, hash[:])
	if errors.Is(err, pgx.ErrNoRows) {
		return sessions.Session{}, sessions.Hash{}, sessions.ErrNotFound
	}
	if err != nil {
		return sessions.Session{}, sessions.Hash{}, sessionError("load session", err)
	}
	session, stored, err := sessionFromRow(row)
	if err != nil {
		return sessions.Session{}, sessions.Hash{}, err
	}
	return session, stored, nil
}

// Extend moves expires_at when the stored expiry is still at or before extendBefore.
func (r *SessionRepository) Extend(ctx context.Context, hash sessions.Hash, expiresAt, extendBefore time.Time) (bool, error) {
	n, err := r.q.ExtendSession(ctx, sqlcgen.ExtendSessionParams{
		ExpiresAt:    pgTime(expiresAt),
		SecretHash:   hash[:],
		ExtendBefore: pgTime(extendBefore),
	})
	if err != nil {
		return false, sessionError("extend session", err)
	}
	return n > 0, nil
}

// Delete removes one session. A missing row is success.
func (r *SessionRepository) Delete(ctx context.Context, hash sessions.Hash) error {
	if err := r.q.DeleteSession(ctx, hash[:]); err != nil {
		return sessionError("delete session", err)
	}
	return nil
}

// DeleteUser removes every session of the user.
func (r *SessionRepository) DeleteUser(ctx context.Context, userID users.ID) error {
	if err := r.q.DeleteUserSessions(ctx, pgUUIDBytes(userID.Bytes())); err != nil {
		return sessionError("delete user sessions", err)
	}
	return nil
}

func sessionFromRow(row sqlcgen.GetSessionRow) (sessions.Session, sessions.Hash, error) {
	if !row.UserID.Valid || !row.AuthAt.Valid || !row.ExpiresAt.Valid {
		return sessions.Session{}, sessions.Hash{}, errors.New("postgres: session row is incomplete")
	}
	factors, err := factorsFrom(row.Factors)
	if err != nil {
		return sessions.Session{}, sessions.Hash{}, err
	}
	hash, err := sessionHash(row.SecretHash)
	if err != nil {
		return sessions.Session{}, sessions.Hash{}, err
	}
	return sessions.Session{
		UserID:    users.IDFromBytes(row.UserID.Bytes),
		Factors:   factors,
		AuthAt:    row.AuthAt.Time.UTC(),
		ExpiresAt: row.ExpiresAt.Time.UTC(),
	}, hash, nil
}

func sessionHash(raw []byte) (sessions.Hash, error) {
	var hash sessions.Hash
	if len(raw) != len(hash) {
		return sessions.Hash{}, fmt.Errorf("postgres: session hash length %d", len(raw))
	}
	copy(hash[:], raw)
	return hash, nil
}

func sessionError(action string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if pgErr.Code == pgForeignKeyViolation && pgErr.ConstraintName == "sessions_user_id_fkey" {
			return sessions.ErrUnknownUser
		}
		return fmt.Errorf("postgres: %s: %s (SQLSTATE %s)", action, pgErr.ConstraintName, pgErr.Code)
	}
	return fmt.Errorf("postgres: %s: %w", action, err)
}
