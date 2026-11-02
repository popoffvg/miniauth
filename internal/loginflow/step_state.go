package loginflow

import (
	"context"
	"errors"
)

// ErrStepMoved means the stored step state is no longer the state the callback read: another callback moved it.
var ErrStepMoved = errors.New("loginflow: step state moved")

// StepState is the stored state of the child machine of one pass that spans requests, such as a Google
// redirect and its callback. Each provider names its own values. The empty state means no pass began.
type StepState string

// StepStore keeps the step state of a live flow, next to the flow row.
// BeginStep replaces the step state. LoadStep returns it. A missing or expired flow is ErrFlowNotFound for both.
// MoveStep writes to only while the stored state is still from. Else it returns ErrStepMoved.
type StepStore interface {
	BeginStep(ctx context.Context, id FlowID, start StepState) error
	LoadStep(ctx context.Context, id FlowID) (StepState, error)
	MoveStep(ctx context.Context, id FlowID, from, to StepState) error
}
