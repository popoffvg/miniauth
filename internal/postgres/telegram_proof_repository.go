package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/telegramstep"
)

// TelegramProofRepository is the PostgreSQL adapter for used Telegram widget logins.
type TelegramProofRepository struct {
	q *sqlcgen.Queries
}

// NewTelegramProofRepository returns a repository that uses db for queries.
func NewTelegramProofRepository(db sqlcgen.DBTX) *TelegramProofRepository {
	return &TelegramProofRepository{q: sqlcgen.New(db)}
}

var _ telegramstep.ProofStore = (*TelegramProofRepository)(nil)

// Use inserts hash. A hash that is already stored is telegramstep.ErrReplay.
func (r *TelegramProofRepository) Use(ctx context.Context, hash telegramstep.ProofHash, expiresAt time.Time) error {
	n, err := r.q.InsertTelegramLoginProof(ctx, sqlcgen.InsertTelegramLoginProofParams{
		ProofHash: hash[:],
		ExpiresAt: pgTime(expiresAt),
	})
	if err != nil {
		return fmt.Errorf("postgres: insert telegram login proof: %w", err)
	}
	if n == 0 {
		return telegramstep.ErrReplay
	}
	return nil
}

// Cleanup deletes the proofs that expired at or before now.
func (r *TelegramProofRepository) Cleanup(ctx context.Context, now time.Time) error {
	if err := r.q.DeleteExpiredTelegramLoginProofs(ctx, pgTime(now)); err != nil {
		return fmt.Errorf("postgres: cleanup telegram login proofs: %w", err)
	}
	return nil
}

// Release deletes hash, so the same data can sign in again.
func (r *TelegramProofRepository) Release(ctx context.Context, hash telegramstep.ProofHash) error {
	if err := r.q.DeleteTelegramLoginProof(ctx, hash[:]); err != nil {
		return fmt.Errorf("postgres: delete telegram login proof: %w", err)
	}
	return nil
}
