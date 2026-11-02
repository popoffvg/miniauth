// Package loginflowtest holds in-memory stores of the loginflow ports for tests.
package loginflowtest

import (
	"context"
	"sync"

	"github.com/popoffvg/miniauth/internal/loginflow"
)

// StepStore is a loginflow.StepStore in memory. Every flow id is live.
type StepStore struct {
	mu     sync.Mutex
	states map[loginflow.FlowID]loginflow.StepState
}

var _ loginflow.StepStore = (*StepStore)(nil)

// NewStepStore returns an empty store.
func NewStepStore() *StepStore {
	return &StepStore{states: map[loginflow.FlowID]loginflow.StepState{}}
}

// BeginStep replaces the step state of id.
func (s *StepStore) BeginStep(_ context.Context, id loginflow.FlowID, start loginflow.StepState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[id] = start
	return nil
}

// LoadStep returns the step state of id, or the empty state.
func (s *StepStore) LoadStep(_ context.Context, id loginflow.FlowID) (loginflow.StepState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.states[id], nil
}

// MoveStep writes to while the step state of id is still from.
func (s *StepStore) MoveStep(_ context.Context, id loginflow.FlowID, from, to loginflow.StepState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states[id] != from {
		return loginflow.ErrStepMoved
	}
	s.states[id] = to
	return nil
}
