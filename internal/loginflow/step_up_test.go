package loginflow

import (
	"errors"
	"testing"
	"time"

	"github.com/popoffvg/miniauth/internal/users"
)

func TestStepUpCountsOnlyItsUser(t *testing.T) {
	owner := users.NewID()
	flow := LoginFlow{
		ID:        "22222222-2222-4222-8222-222222222222",
		ReturnURL: "https://example.test/tokens",
		ExpiresAt: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC),
		State:     StateAwaiting,
		Version:   1,
		Kind:      KindStepUp,
		UserID:    owner,
	}
	tests := []struct {
		name    string
		event   Event
		want    FlowState
		wantErr error
	}{
		{name: "same user completes", event: Event{Kind: EventStepPassed, Factor: FactorPassword, UserID: owner}, want: StateComplete},
		{name: "another user is refused", event: Event{Kind: EventStepPassed, Factor: FactorPassword, UserID: users.NewID()}, want: StateAwaiting, wantErr: ErrNoTransition},
		{name: "no user is refused", event: Event{Kind: EventStepPassed, Factor: FactorPassword}, want: StateAwaiting, wantErr: ErrNoTransition},
		{name: "unknown account is refused", event: Event{Kind: EventStepPassed, Factor: FactorGoogle, UnknownAccount: true}, want: StateAwaiting, wantErr: ErrNoTransition},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := flow.Next(tt.event)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Next() error = %v, want %v", err, tt.wantErr)
			}
			if got.State != tt.want {
				t.Fatalf("Next() state = %s, want %s", got.State, tt.want)
			}
		})
	}
}

func TestLoginKindIgnoresEventUser(t *testing.T) {
	flow := LoginFlow{ReturnURL: "https://example.test/", State: StateAwaiting, Kind: KindLogin}
	got, err := flow.Next(Event{Kind: EventStepPassed, Factor: FactorPassword, UserID: users.NewID()})
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateComplete {
		t.Fatalf("Next() state = %s, want %s", got.State, StateComplete)
	}
}

func TestParseFlowKind(t *testing.T) {
	for _, raw := range []string{"login", "step_up"} {
		if kind, err := ParseFlowKind(raw); err != nil || string(kind) != raw {
			t.Fatalf("ParseFlowKind(%q) = %q, %v", raw, kind, err)
		}
	}
	for _, raw := range []string{"", "Login", "admin"} {
		if _, err := ParseFlowKind(raw); err == nil {
			t.Fatalf("ParseFlowKind(%q) accepted", raw)
		}
	}
}
