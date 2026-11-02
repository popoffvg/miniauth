package passkey

import (
	"errors"

	"github.com/popoffvg/miniauth/internal/loginflow"
)

// StepState is the stage of one passkey pass of a login flow. BeginLogin starts it. Verify ends it.
type StepState string

const (
	// StepChallenged waits for the assertion of the stored challenge.
	StepChallenged StepState = "passkey_challenged"
	// StepPassed got a valid assertion. It is final.
	StepPassed StepState = "passkey_passed"
	// StepFailed got an assertion that does not pass the checks, or found no challenge. It is final.
	StepFailed StepState = "passkey_failed"
)

// StepEvent is what one assertion was.
type StepEvent string

const (
	// EventAssertionValid is an assertion that passes every check.
	EventAssertionValid StepEvent = "assertion_valid"
	// EventAssertionBad is an assertion that fails a check of the ceremony, the user, the credential, or the counter.
	EventAssertionBad StepEvent = "assertion_bad"
)

// stepPolicy is every allowed transition of a passkey pass. A missing pair is ErrNoTransition.
// A final state has no row, so a second assertion is refused.
var stepPolicy = map[StepState]map[StepEvent]StepState{
	StepChallenged: {EventAssertionValid: StepPassed, EventAssertionBad: StepFailed},
}

// NextStep reads no store: Verify turns the assertion into the event.
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

// badAssertions is every error of an assertion that ends the pass in StepFailed.
// Another error, such as a store failure, leaves the pass in its state.
var badAssertions = []error{
	ErrCeremony,
	ErrUserNotVerified,
	ErrUnknownCredential,
	ErrClonedAuthenticator,
	loginflow.ErrChallengeNotFound,
}

func assertionBad(err error) bool {
	for _, bad := range badAssertions {
		if errors.Is(err, bad) {
			return true
		}
	}
	return false
}
