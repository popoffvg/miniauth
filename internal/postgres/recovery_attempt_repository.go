package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/popoffvg/miniauth/internal/passwordstep"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/users"
)

// RecoveryAttemptRepository keeps recovery requests in their own table,
// so a recovery request does not slow down a password login.
type RecoveryAttemptRepository struct {
	q *sqlcgen.Queries
}

// NewRecoveryAttemptRepository returns a repository that uses db for queries.
func NewRecoveryAttemptRepository(db sqlcgen.DBTX) *RecoveryAttemptRepository {
	return &RecoveryAttemptRepository{q: sqlcgen.New(db)}
}

var _ passwordstep.AttemptStore = (*RecoveryAttemptRepository)(nil)

// Record inserts one request.
func (r *RecoveryAttemptRepository) Record(ctx context.Context, attempt passwordstep.Attempt) error {
	err := r.q.InsertRecoveryAttempt(ctx, sqlcgen.InsertRecoveryAttemptParams{
		Login:       attempt.Login.String(),
		Ip:          attempt.IP.Addr(),
		Succeeded:   attempt.Succeeded,
		AttemptedAt: pgTime(attempt.AttemptedAt),
	})
	if err != nil {
		return fmt.Errorf("postgres: record recovery attempt: %w", err)
	}
	return nil
}

// CountFailures counts the failures of login and of ip at or after since.
func (r *RecoveryAttemptRepository) CountFailures(ctx context.Context, login users.Login, ip passwordstep.ClientIP, since time.Time) (passwordstep.RecentFailures, error) {
	byLogin, err := r.q.CountRecoveryLoginFailures(ctx, sqlcgen.CountRecoveryLoginFailuresParams{
		Login: login.String(),
		Since: pgTime(since),
	})
	if err != nil {
		return passwordstep.RecentFailures{}, fmt.Errorf("postgres: count recovery login failures: %w", err)
	}
	byIP, err := r.q.CountRecoveryIPFailures(ctx, sqlcgen.CountRecoveryIPFailuresParams{
		Ip:    ip.Addr(),
		Since: pgTime(since),
	})
	if err != nil {
		return passwordstep.RecentFailures{}, fmt.Errorf("postgres: count recovery IP failures: %w", err)
	}
	return passwordstep.RecentFailures{
		Login: failureCount(byLogin.Failures, byLogin.LastFailure),
		IP:    failureCount(byIP.Failures, byIP.LastFailure),
	}, nil
}

// Cleanup deletes the requests before before.
func (r *RecoveryAttemptRepository) Cleanup(ctx context.Context, before time.Time) error {
	if err := r.q.DeleteRecoveryAttemptsBefore(ctx, pgTime(before)); err != nil {
		return fmt.Errorf("postgres: delete old recovery attempts: %w", err)
	}
	return nil
}
