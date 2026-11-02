package telegram

import (
	"errors"
	"testing"
)

// TestNextStepEveryPair lists each (state, event) pair of the Telegram step. An empty want is ErrNoTransition.
func TestNextStepEveryPair(t *testing.T) {
	want := map[StepState]map[StepEvent]StepState{
		StepWidgetShown: {EventDataKnown: StepPassed, EventDataUnknown: StepUnknownAccount, EventDataBad: StepFailed},
	}
	for _, state := range []StepState{"", StepWidgetShown, StepPassed, StepUnknownAccount, StepFailed} {
		for _, event := range []StepEvent{EventDataKnown, EventDataUnknown, EventDataBad} {
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
