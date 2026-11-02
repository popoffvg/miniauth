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
	ID        FlowID
	ReturnURL ReturnURL
	ExpiresAt time.Time
	State     FlowState
	Factors   Factors
	// PendingFactor marks an external account that waits for a link. It is a marker, not a state.
	PendingFactor Factor
	Version       FlowVersion
	NeedsSecond   bool
	Kind          FlowKind
	// UserID is the user a KindStepUp flow verifies. A KindLogin flow takes it from its first passed factor.
	// Once set, only a factor of this user counts.
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
// UnknownAccount is set when an external account is not linked to a user. It carries no UserID.
// UserID is the user the factor belongs to. A KindStepUp flow refuses a pass for another user.
type Event struct {
	Kind           EventKind
	Factor         Factor
	NeedsSecond    bool
	UnknownAccount bool
	UserID         users.ID
}

// loginPolicy is every factor that counts in each state of a KindLogin flow. A missing pair is ErrNoTransition.
// StateAwaiting has no TOTP and no recovery code, so a second factor before a first one is refused.
// In StateAwaitingSecond a first factor of the same user changes nothing but Factors.
var loginPolicy = map[FlowState]map[Factor]FlowState{
	StateAwaiting:       {FactorPassword: StateComplete, FactorGoogle: StateComplete, FactorTelegram: StateComplete, FactorPasskey: StateComplete},
	StateAwaitingSecond: {FactorTOTP: StateComplete, FactorRecovery: StateComplete, FactorPasskey: StateComplete, FactorPassword: StateAwaitingSecond, FactorGoogle: StateAwaitingSecond, FactorTelegram: StateAwaitingSecond},
}

// stepUpPolicy is every factor that counts in a KindStepUp flow: the password only.
// It has no StateAwaitingSecond, so TOTP never applies to a step-up.
var stepUpPolicy = map[FlowState]map[Factor]FlowState{
	StateAwaiting: {FactorPassword: StateComplete},
}

// policies is the table of each flow kind. A flow of another kind, such as the empty one, accepts no event.
var policies = map[FlowKind]map[FlowState]map[Factor]FlowState{
	KindLogin:  loginPolicy,
	KindStepUp: stepUpPolicy,
}

// Next is the login policy. It is a pure function of the flow and the event.
// A final state accepts no event. The version increases only when the flow changes.
func (f LoginFlow) Next(event Event) (LoginFlow, error) {
	policy, ok := policies[f.Kind]
	if !ok || f.State.Final() {
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
		return f.pass(policy, event)
	default:
		return f, ErrNoTransition
	}
}

func (f LoginFlow) pass(policy map[FlowState]map[Factor]FlowState, event Event) (LoginFlow, error) {
	// The table names the factors that count in this state.
	target, ok := policy[f.State][event.Factor]
	if !ok {
		return f, ErrNoTransition
	}
	// A flow bound to a user counts a factor of that user only. A known factor MUST carry its user.
	if f.UserID != (users.ID{}) && event.UserID != f.UserID || !event.UnknownAccount && event.UserID == (users.ID{}) {
		return f, ErrNoTransition
	}
	next := f
	// An unknown external account sets the PendingFactor marker and keeps the state, so the caller can link it.
	if event.UnknownAccount {
		next.PendingFactor = event.Factor
		return next.nextVersion(f), nil
	}
	next.UserID = event.UserID
	next.Factors = next.Factors.With(event.Factor)
	_, twoSteps := policy[StateAwaitingSecond]
	next.NeedsSecond = next.NeedsSecond || event.NeedsSecond && twoSteps
	// The one rule outside the table: a user with TOTP needs a second step after a first factor.
	// A passkey counts as two factors.
	if next.NeedsSecond && f.State == StateAwaiting && event.Factor != FactorPasskey {
		target = StateAwaitingSecond
	}
	next.State = target
	return next.nextVersion(f), nil
}

// nextVersion returns f with the version after prev when f differs from prev, else prev.
func (f LoginFlow) nextVersion(prev LoginFlow) LoginFlow {
	if f == prev {
		return prev
	}
	f.Version = prev.Version + 1
	return f
}
