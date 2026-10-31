package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
)

var _ loginflow.ChallengeStore = (*FlowStore)(nil)

// SaveChallenge writes the challenge of a live flow.
func (s *FlowStore) SaveChallenge(ctx context.Context, id loginflow.FlowID, challenge loginflow.Challenge) error {
	pgID, err := pgUUID(id)
	if err != nil {
		return err
	}
	n, err := s.q.SetLoginFlowChallenge(ctx, sqlcgen.SetLoginFlowChallengeParams{Challenge: challenge, ID: pgID})
	if err != nil {
		return fmt.Errorf("postgres: save login flow challenge: %w", err)
	}
	if n == 0 {
		return loginflow.ErrFlowNotFound
	}
	return nil
}

// TakeChallenge returns the challenge and clears it.
func (s *FlowStore) TakeChallenge(ctx context.Context, id loginflow.FlowID) (loginflow.Challenge, error) {
	pgID, err := pgUUID(id)
	if err != nil {
		return nil, err
	}
	challenge, err := s.q.TakeLoginFlowChallenge(ctx, pgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, loginflow.ErrChallengeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: take login flow challenge: %w", err)
	}
	return challenge, nil
}
