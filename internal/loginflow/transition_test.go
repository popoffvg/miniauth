package loginflow

import (
	"errors"
	"testing"
	"time"
)

func TestLoginFlowNext(t *testing.T) {
	expires := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	base := LoginFlow{
		ID:        "11111111-1111-4111-8111-111111111111",
		ReturnURL: "https://example.test/back",
		ExpiresAt: expires,
		State:     StateAwaiting,
		Version:   3,
	}
	second := base
	second.State = StateAwaitingSecond
	second.Factors = Factors(FactorPassword)
	second.NeedsSecond = true
	second.Version = 4

	pending := base
	pending.State = StatePendingLink
	pending.PendingFactor = FactorGoogle
	pending.Version = 4

	tests := []struct {
		name    string
		state   LoginFlow
		event   Event
		want    LoginFlow
		wantErr error
	}{
		{
			name:  "cancel",
			state: base,
			event: Event{Kind: EventCancel},
			want:  with(base, func(f *LoginFlow) { f.State = StateCancelled; f.Version = 4 }),
		},
		{
			name:  "failed step stays",
			state: base,
			event: Event{Kind: EventStepFailed, Factor: FactorPassword},
			want:  base,
		},
		{
			name:  "password completes",
			state: base,
			event: Event{Kind: EventStepPassed, Factor: FactorPassword},
			want: with(base, func(f *LoginFlow) {
				f.State = StateComplete
				f.Factors = Factors(FactorPassword)
				f.Version = 4
			}),
		},
		{
			name:  "password with totp enrolled waits",
			state: base,
			event: Event{Kind: EventStepPassed, Factor: FactorPassword, NeedsSecond: true},
			want: with(base, func(f *LoginFlow) {
				f.State = StateAwaitingSecond
				f.Factors = Factors(FactorPassword)
				f.NeedsSecond = true
				f.Version = 4
			}),
		},
		{
			name:  "totp completes the second factor",
			state: second,
			event: Event{Kind: EventStepPassed, Factor: FactorTOTP},
			want: with(second, func(f *LoginFlow) {
				f.State = StateComplete
				f.Factors = Factors(FactorPassword).With(FactorTOTP)
				f.Version = 5
			}),
		},
		{
			name:  "recovery code completes the second factor",
			state: second,
			event: Event{Kind: EventStepPassed, Factor: FactorRecovery},
			want: with(second, func(f *LoginFlow) {
				f.State = StateComplete
				f.Factors = Factors(FactorPassword).With(FactorRecovery)
				f.Version = 5
			}),
		},
		{
			name:  "failed second step stays",
			state: second,
			event: Event{Kind: EventStepFailed},
			want:  second,
		},
		{
			name:  "passkey counts as two factors",
			state: base,
			event: Event{Kind: EventStepPassed, Factor: FactorPasskey},
			want: with(base, func(f *LoginFlow) {
				f.State = StateComplete
				f.Factors = Factors(FactorPasskey)
				f.Version = 4
			}),
		},
		{
			name:  "passkey satisfies a flow that still needs a second factor",
			state: second,
			event: Event{Kind: EventStepPassed, Factor: FactorPasskey},
			want: with(second, func(f *LoginFlow) {
				f.State = StateComplete
				f.Factors = Factors(FactorPassword).With(FactorPasskey)
				f.Version = 5
			}),
		},
		{
			name:  "recovery alone does not complete",
			state: base,
			event: Event{Kind: EventStepPassed, Factor: FactorRecovery},
			want: with(base, func(f *LoginFlow) {
				f.Factors = Factors(FactorRecovery)
				f.Version = 4
			}),
		},
		{
			name:  "totp alone does not complete",
			state: base,
			event: Event{Kind: EventStepPassed, Factor: FactorTOTP},
			want: with(base, func(f *LoginFlow) {
				f.Factors = Factors(FactorTOTP)
				f.Version = 4
			}),
		},
		{
			name:  "google completes",
			state: base,
			event: Event{Kind: EventStepPassed, Factor: FactorGoogle},
			want: with(base, func(f *LoginFlow) {
				f.State = StateComplete
				f.Factors = Factors(FactorGoogle)
				f.Version = 4
			}),
		},
		{
			name:  "telegram completes",
			state: base,
			event: Event{Kind: EventStepPassed, Factor: FactorTelegram},
			want: with(base, func(f *LoginFlow) {
				f.State = StateComplete
				f.Factors = Factors(FactorTelegram)
				f.Version = 4
			}),
		},
		{
			name:  "unknown google waits to link",
			state: base,
			event: Event{Kind: EventStepPassed, Factor: FactorGoogle, UnknownAccount: true},
			want: with(base, func(f *LoginFlow) {
				f.State = StatePendingLink
				f.PendingFactor = FactorGoogle
				f.Version = 4
			}),
		},
		{
			name:  "known password completes a pending link",
			state: pending,
			event: Event{Kind: EventStepPassed, Factor: FactorPassword},
			want: with(pending, func(f *LoginFlow) {
				f.State = StateComplete
				f.Factors = Factors(FactorPassword)
				f.Version = 5
			}),
		},
		{
			name:  "pending link still needs totp",
			state: pending,
			event: Event{Kind: EventStepPassed, Factor: FactorPassword, NeedsSecond: true},
			want: with(pending, func(f *LoginFlow) {
				f.State = StateAwaitingSecond
				f.Factors = Factors(FactorPassword)
				f.NeedsSecond = true
				f.Version = 5
			}),
		},
		{
			name:  "same unknown account again stays",
			state: pending,
			event: Event{Kind: EventStepPassed, Factor: FactorGoogle, UnknownAccount: true},
			want:  pending,
		},
		{
			name:  "same password again stays",
			state: second,
			event: Event{Kind: EventStepPassed, Factor: FactorPassword, NeedsSecond: true},
			want:  second,
		},
		{
			name:    "complete accepts nothing",
			state:   with(base, func(f *LoginFlow) { f.State = StateComplete }),
			event:   Event{Kind: EventStepPassed, Factor: FactorPassword},
			wantErr: ErrNoTransition,
		},
		{
			name:    "cancelled accepts nothing",
			state:   with(base, func(f *LoginFlow) { f.State = StateCancelled }),
			event:   Event{Kind: EventCancel},
			wantErr: ErrNoTransition,
		},
		{
			name:    "unknown event",
			state:   base,
			event:   Event{Kind: "nope"},
			wantErr: ErrNoTransition,
		},
		{
			name:    "step passed without a factor",
			state:   base,
			event:   Event{Kind: EventStepPassed},
			wantErr: ErrNoTransition,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.state.Next(tt.event)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Next() error = %v, want %v", err, tt.wantErr)
				}
				if got != tt.state {
					t.Fatalf("Next() state changed on error: %#v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("Next()\n got %#v\nwant %#v", got, tt.want)
			}
		})
	}
}

func with(flow LoginFlow, edit func(*LoginFlow)) LoginFlow {
	edit(&flow)
	return flow
}
