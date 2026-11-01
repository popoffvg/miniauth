package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/providers/password"
	"github.com/popoffvg/miniauth/internal/users"
)

// AttemptRepository is the PostgreSQL adapter for login attempts.
type AttemptRepository struct {
	q *sqlcgen.Queries
}

// NewAttemptRepository returns a repository that uses db for queries.
func NewAttemptRepository(db sqlcgen.DBTX) *AttemptRepository {
	return &AttemptRepository{q: sqlcgen.New(db)}
}

var _ password.AttemptStore = (*AttemptRepository)(nil)

// Record inserts one attempt.
func (r *AttemptRepository) Record(ctx context.Context, attempt password.Attempt) error {
	err := r.q.InsertLoginAttempt(ctx, sqlcgen.InsertLoginAttemptParams{
		Login:       attempt.Login.String(),
		Ip:          attempt.IP.Addr(),
		Succeeded:   attempt.Succeeded,
		AttemptedAt: pgTime(attempt.AttemptedAt),
		Kind:        string(attempt.Kind),
	})
	if err != nil {
		return fmt.Errorf("postgres: record login attempt: %w", err)
	}
	return nil
}

// CountFailures counts the failures of login for kind, and of ip for every kind, at or after since.
func (r *AttemptRepository) CountFailures(ctx context.Context, kind password.AttemptKind, login users.Login, ip password.ClientIP, since time.Time) (password.RecentFailures, error) {
	byLogin, err := r.q.CountLoginFailures(ctx, sqlcgen.CountLoginFailuresParams{
		Login: login.String(),
		Kind:  string(kind),
		Since: pgTime(since),
	})
	if err != nil {
		return password.RecentFailures{}, fmt.Errorf("postgres: count login failures: %w", err)
	}
	byIP, err := r.q.CountIPFailures(ctx, sqlcgen.CountIPFailuresParams{
		Ip:    ip.Addr(),
		Since: pgTime(since),
	})
	if err != nil {
		return password.RecentFailures{}, fmt.Errorf("postgres: count IP failures: %w", err)
	}
	return password.RecentFailures{
		Login: failureCount(byLogin.Failures, byLogin.LastFailure),
		IP:    failureCount(byIP.Failures, byIP.LastFailure),
	}, nil
}

// Cleanup deletes the attempts before before.
func (r *AttemptRepository) Cleanup(ctx context.Context, before time.Time) error {
	if err := r.q.DeleteLoginAttemptsBefore(ctx, pgTime(before)); err != nil {
		return fmt.Errorf("postgres: delete old login attempts: %w", err)
	}
	return nil
}

func failureCount(failures int64, last pgtype.Timestamptz) password.FailureCount {
	count := password.FailureCount{Failures: int(failures)}
	if last.Valid {
		count.LastFailure = last.Time.UTC()
	}
	return count
}
