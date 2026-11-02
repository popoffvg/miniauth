package passkey

import (
	"errors"
	"testing"
)

// TestNextStepEveryPair lists each (state, event) pair of the passkey step. An empty want is ErrNoTransition.
func TestNextStepEveryPair(t *testing.T) {
	want := map[StepState]map[StepEvent]StepState{
		StepChallenged: {EventAssertionValid: StepPassed, EventAssertionBad: StepFailed},
	}
	for _, state := range []StepState{"", StepChallenged, StepPassed, StepFailed} {
		for _, event := range []StepEvent{EventAssertionValid, EventAssertionBad} {
			got, err := NextStep(state, event)
			wantState, ok := want[state][event]
			if !ok {
				if !errors.Is(err, ErrNoTransition) || got != state {
					t.Errorf("NextStep(%q, %s) = %q, %v, want %v", state, event, got, err, ErrNoTransition)
				}
				continue
			}
			if err != nil || got != wantState {
				t.Errorf("NextStep(%q, %s) = %q, %v, want %q", state, event, got, err, wantState)
			}
		}
	}
}
