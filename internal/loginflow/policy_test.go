package loginflow

import (
	"errors"
	"testing"

	"github.com/popoffvg/miniauth/internal/users"
)

// TestPolicyEveryPair lists each (kind, state, factor) pair of the parent tables for a user without TOTP.
// An empty want is ErrNoTransition.
func TestPolicyEveryPair(t *testing.T) {
	kinds := []FlowKind{KindLogin, KindStepUp}
	states := []FlowState{StateAwaiting, StateAwaitingSecond, StateComplete, StateCancelled}
	factors := []Factor{FactorPassword, FactorTOTP, FactorRecovery, FactorPasskey, FactorGoogle, FactorTelegram}
	want := map[FlowKind]map[FlowState]map[Factor]FlowState{
		KindLogin: {
			StateAwaiting: {
				FactorPassword: StateComplete, FactorPasskey: StateComplete, FactorGoogle: StateComplete, FactorTelegram: StateComplete,
			},
			StateAwaitingSecond: {
				FactorPassword: StateAwaitingSecond, FactorTOTP: StateComplete, FactorRecovery: StateComplete,
				FactorPasskey: StateComplete, FactorGoogle: StateAwaitingSecond, FactorTelegram: StateAwaitingSecond,
			},
		},
		KindStepUp: {
			StateAwaiting: {FactorPassword: StateComplete},
		},
	}
	ada := users.NewID()
	for _, kind := range kinds {
		for _, state := range states {
			for _, factor := range factors {
				flow := LoginFlow{ReturnURL: "https://example.test/", State: state, Kind: kind, UserID: ada}
				if state == StateAwaitingSecond {
					flow.Factors = Factors(FactorPassword)
					flow.NeedsSecond = true
				}
				got, err := flow.Next(Event{Kind: EventStepPassed, Factor: factor, UserID: ada})
				wantState, ok := want[kind][state][factor]
				if !ok {
					if !errors.Is(err, ErrNoTransition) || got != flow {
						t.Errorf("%s %s %d: got %s, %v, want %v", kind, state, factor, got.State, err, ErrNoTransition)
					}
					continue
				}
				if err != nil || got.State != wantState {
					t.Errorf("%s %s %d: got %s, %v, want %s", kind, state, factor, got.State, err, wantState)
				}
			}
		}
	}
}

func TestUnknownGoogleThenTOTPIsRefused(t *testing.T) {
	flow := LoginFlow{ReturnURL: "https://example.test/", State: StateAwaiting, Kind: KindLogin}
	pending, err := flow.Next(Event{Kind: EventStepPassed, Factor: FactorGoogle, UnknownAccount: true})
	if err != nil {
		t.Fatal(err)
	}
	if pending.State != StateAwaiting || pending.PendingFactor != FactorGoogle {
		t.Fatalf("unknown google: state %s, pending %d, want %s with the google marker", pending.State, pending.PendingFactor, StateAwaiting)
	}
	for _, factor := range []Factor{FactorTOTP, FactorRecovery} {
		got, err := pending.Next(Event{Kind: EventStepPassed, Factor: factor, UserID: users.NewID()})
		if !errors.Is(err, ErrNoTransition) || got != pending {
			t.Fatalf("factor %d after an unknown google: state %s, error %v, want %v", factor, got.State, err, ErrNoTransition)
		}
	}
}
