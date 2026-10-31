package loginflow

import (
	"time"

	"github.com/popoffvg/miniauth/internal/users"
)

// FlowVersion is the optimistic-lock counter of one flow.
// A write stores the next version only when the row still has the previous one.
type FlowVersion int64

// FlowTTL is how long a login in progress stays stored.
// After this the row is cleaned up and Open reports ErrFlowNotFound.
const FlowTTL = 15 * time.Minute

// LoginFlow is one login in progress. It is comparable so a PersistedSFSM can store it.
// The secret is not a field: the database keeps only SecretHash.
type LoginFlow struct {
	ID            FlowID
	ReturnURL     ReturnURL
	ExpiresAt     time.Time
	State         FlowState
	Factors       Factors
	PendingFactor Factor
	Version       FlowVersion
	NeedsSecond   bool
	Kind          FlowKind
	// UserID is the user a KindStepUp flow verifies. It is zero for KindLogin.
	UserID users.ID
}

// EventKind is what a step reports to the flow.
type EventKind string

const (
	// EventStepPassed means the step accepted a factor.
	EventStepPassed EventKind = "step_passed"
	// EventStepFailed means the step rejected the attempt. The flow stays as it is.
	EventStepFailed EventKind = "step_failed"
	// EventCancel abandons the flow.
	EventCancel EventKind = "cancel"
)

// Event is one input to the policy.
// NeedsSecond is set when the identified user has TOTP enrolled.
// UnknownAccount is set when an external account is not linked to a user.
// UserID is the user the factor belongs to. A KindStepUp flow refuses a pass for another user.
type Event struct {
	Kind           EventKind
	Factor         Factor
	NeedsSecond    bool
	UnknownAccount bool
	UserID         users.ID
}

// Next is the login policy. It is a pure function of the flow and the event.
//
// One collected factor completes the flow. A passkey counts as two, so it completes on its own.
// When NeedsSecond is set, the flow needs two: the password, then TOTP or a recovery code.
// TOTP and a recovery code do not count until NeedsSecond is set.
// An unknown external account moves the flow to pending_link and records the factor.
// A later known factor can then complete the flow. The pending factor stays on the value
// so the caller can link the account; a final state is not stored.
// A final state accepts no event. The version increases only when the flow changes.
func (f LoginFlow) Next(event Event) (LoginFlow, error) {
	if f.State.Final() {
		return f, ErrNoTransition
	}
	switch event.Kind {
	case EventCancel:
		f.State = StateCancelled
		f.Version++
		return f, nil
	case EventStepFailed:
		return f, nil
	case EventStepPassed:
		return f.pass(event)
	default:
		return f, ErrNoTransition
	}
}

func (f LoginFlow) pass(event Event) (LoginFlow, error) {
	if event.Factor == 0 || f.Kind == KindStepUp && event.UserID != f.UserID {
		return f, ErrNoTransition
	}
	next := f
	if event.UnknownAccount {
		next.State = StatePendingLink
		next.PendingFactor = event.Factor
		if next.State == f.State && next.PendingFactor == f.PendingFactor {
			return f, nil
		}
		next.Version++
		return next, nil
	}
	if event.NeedsSecond {
		next.NeedsSecond = true
	}
	next.Factors = next.Factors.With(event.Factor)
	switch {
	case next.satisfied():
		next.State = StateComplete
	case next.NeedsSecond:
		next.State = StateAwaitingSecond
	}
	if next.State == f.State && next.Factors == f.Factors && next.NeedsSecond == f.NeedsSecond && next.PendingFactor == f.PendingFactor {
		return f, nil
	}
	next.Version = f.Version + 1
	return next, nil
}

// satisfied reports whether the collected factors meet the policy.
func (f LoginFlow) satisfied() bool {
	n := 0
	if f.Factors.Has(FactorPassword) {
		n++
	}
	if f.Factors.Has(FactorGoogle) {
		n++
	}
	if f.Factors.Has(FactorTelegram) {
		n++
	}
	if f.Factors.Has(FactorPasskey) {
		n += 2
	}
	need := 1
	if f.NeedsSecond {
		need = 2
		if f.Factors.Has(FactorPassword) && (f.Factors.Has(FactorTOTP) || f.Factors.Has(FactorRecovery)) {
			n++
		}
	}
	return n >= need
}
