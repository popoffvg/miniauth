package google

import "github.com/popoffvg/miniauth/internal/loginflow"

// StepState is the stage of one Google pass of a login flow. Begin starts it. The callback ends it.
type StepState string

const (
	// StepStarted waits for the callback.
	StepStarted StepState = "google_started"
	// StepPassed found a linked account. It is final.
	StepPassed StepState = "google_passed"
	// StepUnknownAccount found an account with no user. It is final.
	StepUnknownAccount StepState = "google_unknown_account"
	// StepFailed got a callback that does not match the flow, or a bad ID token. It is final.
	StepFailed StepState = "google_failed"
)

// StepEvent is what one callback found.
type StepEvent string

const (
	// EventCallbackKnown is a valid callback for a linked account.
	EventCallbackKnown StepEvent = "callback_known"
	// EventCallbackUnknown is a valid callback for an account with no user.
	EventCallbackUnknown StepEvent = "callback_unknown"
	// EventCallbackBad is a callback with no challenge, a wrong state, verifier, or code, or a bad ID token.
	EventCallbackBad StepEvent = "callback_bad"
)

// stepPolicy is every allowed transition of a Google pass. A missing pair is ErrNoTransition.
// A final state has no row, so a second callback is refused.
var stepPolicy = map[StepState]map[StepEvent]StepState{
	StepStarted: {EventCallbackKnown: StepPassed, EventCallbackUnknown: StepUnknownAccount, EventCallbackBad: StepFailed},
}

// NextStep reads no store: Finish turns the callback into the event.
func NextStep(state StepState, event StepEvent) (StepState, error) {
	next, ok := stepPolicy[state][event]
	if !ok {
		return state, ErrNoTransition
	}
	return next, nil
}

func (s StepState) stored() loginflow.StepState {
	return loginflow.StepState(s)
}
