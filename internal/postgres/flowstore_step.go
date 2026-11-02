package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
)

var _ loginflow.StepStore = (*FlowStore)(nil)

// BeginStep writes the start state of a pass on a live flow.
func (s *FlowStore) BeginStep(ctx context.Context, id loginflow.FlowID, start loginflow.StepState) error {
	pgID, err := pgUUID(id)
	if err != nil {
		return err
	}
	n, err := s.q.SetLoginFlowStepState(ctx, sqlcgen.SetLoginFlowStepStateParams{StepState: string(start), ID: pgID})
	if err != nil {
		return fmt.Errorf("postgres: begin login flow step: %w", err)
	}
	if n == 0 {
		return loginflow.ErrFlowNotFound
	}
	return nil
}

// LoadStep returns the step state of a live flow.
func (s *FlowStore) LoadStep(ctx context.Context, id loginflow.FlowID) (loginflow.StepState, error) {
	pgID, err := pgUUID(id)
	if err != nil {
		return "", err
	}
	state, err := s.q.GetLoginFlowStepState(ctx, pgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", loginflow.ErrFlowNotFound
	}
	if err != nil {
		return "", fmt.Errorf("postgres: load login flow step: %w", err)
	}
	return loginflow.StepState(state), nil
}

// MoveStep writes to while the stored step state is still from.
// Zero rows is loginflow.ErrStepMoved, also for a flow that expired since LoadStep.
func (s *FlowStore) MoveStep(ctx context.Context, id loginflow.FlowID, from, to loginflow.StepState) error {
	pgID, err := pgUUID(id)
	if err != nil {
		return err
	}
	n, err := s.q.MoveLoginFlowStepState(ctx, sqlcgen.MoveLoginFlowStepStateParams{NextState: string(to), ID: pgID, PrevState: string(from)})
	if err != nil {
		return fmt.Errorf("postgres: move login flow step: %w", err)
	}
	if n == 0 {
		return loginflow.ErrStepMoved
	}
	return nil
}
