package loginflow

import (
	"errors"
	"testing"

	"github.com/popoffvg/miniauth/internal/users"
)

func TestSecondFactorPolicy(t *testing.T) {
	ada, bea := users.NewID(), users.NewID()
	passed := func(factor Factor, user users.ID, needsSecond bool) Event {
		return Event{Kind: EventStepPassed, Factor: factor, UserID: user, NeedsSecond: needsSecond}
	}
	unknown := func(factor Factor) Event {
		return Event{Kind: EventStepPassed, Factor: factor, UnknownAccount: true}
	}
	login := LoginFlow{ReturnURL: "https://example.test/", State: StateAwaiting, Kind: KindLogin}
	stepUp := LoginFlow{ReturnURL: "https://example.test/", State: StateAwaiting, Kind: KindStepUp, UserID: ada}
	tests := []struct {
		name    string
		flow    LoginFlow
		events  []Event
		want    FlowState
		wantErr error
	}{
		{name: "password of a user with TOTP waits", flow: login, events: []Event{passed(FactorPassword, ada, true)}, want: StateAwaitingSecond},
		{name: "google of a user with TOTP waits", flow: login, events: []Event{passed(FactorGoogle, ada, true)}, want: StateAwaitingSecond},
		{name: "telegram of a user with TOTP waits", flow: login, events: []Event{passed(FactorTelegram, ada, true)}, want: StateAwaitingSecond},
		{name: "google without TOTP completes", flow: login, events: []Event{passed(FactorGoogle, ada, false)}, want: StateComplete},
		{name: "password then google is one factor", flow: login, events: []Event{passed(FactorPassword, ada, true), passed(FactorGoogle, ada, true)}, want: StateAwaitingSecond},
		{name: "google then telegram is one factor", flow: login, events: []Event{passed(FactorGoogle, ada, true), passed(FactorTelegram, ada, true)}, want: StateAwaitingSecond},
		{name: "google then TOTP completes", flow: login, events: []Event{passed(FactorGoogle, ada, true), passed(FactorTOTP, ada, false)}, want: StateComplete},
		{name: "telegram then a recovery code completes", flow: login, events: []Event{passed(FactorTelegram, ada, true), passed(FactorRecovery, ada, false)}, want: StateComplete},
		{name: "TOTP without a first factor is refused", flow: login, events: []Event{passed(FactorTOTP, ada, false)}, want: StateAwaiting, wantErr: ErrNoTransition},
		{name: "a recovery code without a first factor is refused", flow: login, events: []Event{passed(FactorRecovery, ada, false)}, want: StateAwaiting, wantErr: ErrNoTransition},
		{name: "a passkey alone completes", flow: login, events: []Event{passed(FactorPasskey, ada, true)}, want: StateComplete},
		{name: "a passkey after the password completes", flow: login, events: []Event{passed(FactorPassword, ada, true), passed(FactorPasskey, ada, true)}, want: StateComplete},
		{name: "TOTP of another user is refused", flow: login, events: []Event{passed(FactorPassword, ada, true), passed(FactorTOTP, bea, false)}, want: StateAwaitingSecond, wantErr: ErrNoTransition},
		{name: "google of another user is refused", flow: login, events: []Event{passed(FactorPassword, ada, true), passed(FactorGoogle, bea, true)}, want: StateAwaitingSecond, wantErr: ErrNoTransition},
		{name: "a passkey of another user is refused", flow: login, events: []Event{passed(FactorPassword, ada, true), passed(FactorPasskey, bea, false)}, want: StateAwaitingSecond, wantErr: ErrNoTransition},
		{name: "an unknown account after a known user is refused", flow: login, events: []Event{passed(FactorPassword, ada, true), unknown(FactorGoogle)}, want: StateAwaitingSecond, wantErr: ErrNoTransition},
		{name: "a known factor without a user is refused", flow: login, events: []Event{passed(FactorGoogle, users.ID{}, false)}, want: StateAwaiting, wantErr: ErrNoTransition},
		{name: "two factors in one event are refused", flow: login, events: []Event{passed(FactorPassword|FactorTOTP, ada, false)}, want: StateAwaiting, wantErr: ErrNoTransition},
		{name: "password then telegram is one factor", flow: login, events: []Event{passed(FactorPassword, ada, true), passed(FactorTelegram, ada, true)}, want: StateAwaitingSecond},
		{name: "two second factors in one event after the password are refused", flow: login, events: []Event{passed(FactorPassword, ada, true), passed(FactorTOTP|FactorRecovery, ada, false)}, want: StateAwaitingSecond, wantErr: ErrNoTransition},
		{name: "telegram of another user after google is refused", flow: login, events: []Event{passed(FactorGoogle, ada, true), passed(FactorTelegram, bea, true)}, want: StateAwaitingSecond, wantErr: ErrNoTransition},
		{name: "a recovery code of another user is refused", flow: login, events: []Event{passed(FactorTelegram, ada, true), passed(FactorRecovery, bea, false)}, want: StateAwaitingSecond, wantErr: ErrNoTransition},
		{name: "an unknown factor is refused", flow: login, events: []Event{passed(FactorTelegram<<1, ada, false)}, want: StateAwaiting, wantErr: ErrNoTransition},
		{name: "a pending link then the password still needs TOTP", flow: login, events: []Event{unknown(FactorGoogle), passed(FactorPassword, ada, true)}, want: StateAwaitingSecond},
		{name: "a pending link then the password and TOTP completes", flow: login, events: []Event{unknown(FactorTelegram), passed(FactorPassword, ada, true), passed(FactorTOTP, ada, false)}, want: StateComplete},
		{name: "step-up google of its user is refused", flow: stepUp, events: []Event{passed(FactorGoogle, ada, true)}, want: StateAwaiting, wantErr: ErrNoTransition},
		{name: "step-up telegram of its user is refused", flow: stepUp, events: []Event{passed(FactorTelegram, ada, false)}, want: StateAwaiting, wantErr: ErrNoTransition},
		{name: "step-up passkey of its user is refused", flow: stepUp, events: []Event{passed(FactorPasskey, ada, false)}, want: StateAwaiting, wantErr: ErrNoTransition},
		{name: "step-up TOTP of its user is refused", flow: stepUp, events: []Event{passed(FactorTOTP, ada, false)}, want: StateAwaiting, wantErr: ErrNoTransition},
		{name: "step-up telegram of another user is refused", flow: stepUp, events: []Event{passed(FactorTelegram, bea, false)}, want: StateAwaiting, wantErr: ErrNoTransition},
		{name: "step-up google without a user is refused", flow: stepUp, events: []Event{passed(FactorGoogle, users.ID{}, false)}, want: StateAwaiting, wantErr: ErrNoTransition},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow := tt.flow
			var err error
			for i, event := range tt.events {
				flow, err = flow.Next(event)
				if err != nil && i < len(tt.events)-1 {
					t.Fatalf("event %d: %v", i, err)
				}
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("last event error = %v, want %v", err, tt.wantErr)
			}
			if flow.State != tt.want {
				t.Fatalf("state = %s, want %s", flow.State, tt.want)
			}
		})
	}
}

func TestSecondFactorBeforeFirstDoesNotCount(t *testing.T) {
	ada := users.NewID()
	flow := LoginFlow{ReturnURL: "https://example.test/", State: StateAwaiting, Kind: KindLogin}
	flow, _ = flow.Next(Event{Kind: EventStepPassed, Factor: FactorTOTP, UserID: ada})
	got, err := flow.Next(Event{Kind: EventStepPassed, Factor: FactorPassword, UserID: ada, NeedsSecond: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateAwaitingSecond {
		t.Fatalf("state = %s, want %s", got.State, StateAwaitingSecond)
	}
}
