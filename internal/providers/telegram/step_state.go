package telegram

import (
	"errors"

	"github.com/popoffvg/miniauth/internal/loginflow"
)

// StepState is the stage of one Telegram pass of a login flow. Show starts it. Finish ends it.
type StepState string

const (
	// StepWidgetShown waits for the widget data.
	StepWidgetShown StepState = "telegram_widget_shown"
	// StepPassed got data of a linked account. It is final.
	StepPassed StepState = "telegram_passed"
	// StepUnknownAccount got data of an account with no user. It is final.
	StepUnknownAccount StepState = "telegram_unknown_account"
	// StepFailed got data with a bad hash, stale data, or data used before. It is final.
	StepFailed StepState = "telegram_failed"
)

// StepEvent is what one widget data was.
type StepEvent string

const (
	// EventDataKnown is valid data of a linked account.
	EventDataKnown StepEvent = "data_known"
	// EventDataUnknown is valid data of an account with no user.
	EventDataUnknown StepEvent = "data_unknown"
	// EventDataBad is data with a bad hash, stale data, or a replay.
	EventDataBad StepEvent = "data_bad"
)

// stepPolicy is every allowed transition of a Telegram pass. A missing pair is ErrNoTransition.
// A final state has no row, so a second callback is refused.
var stepPolicy = map[StepState]map[StepEvent]StepState{
	StepWidgetShown: {EventDataKnown: StepPassed, EventDataUnknown: StepUnknownAccount, EventDataBad: StepFailed},
}

// NextStep reads no store: Finish turns the widget data into the event.
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

// badData is every error of widget data that ends the pass in StepFailed.
var badData = []error{ErrBadHash, ErrStale, ErrReplay}

func dataBad(err error) bool {
	for _, bad := range badData {
		if errors.Is(err, bad) {
			return true
		}
	}
	return false
}
