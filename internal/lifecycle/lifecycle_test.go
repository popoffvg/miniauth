package lifecycle

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProbeFitsTheReadinessWindow(t *testing.T) {
	const window = 10 * time.Second
	assert.Less(t, ProbeInterval+ProbeTimeout, window)
	assert.Equal(t, 5*time.Second, ProbeInterval)
}

func TestNext(t *testing.T) {
	tests := []struct {
		name    string
		state   State
		event   Event
		want    State
		wantErr error
	}{
		{name: "start migration", state: StateStarting, event: EventMigrate, want: StateMigrating},
		{name: "drain while starting", state: StateStarting, event: EventDrain, want: StateDraining},
		{name: "ignore database up while starting", state: StateStarting, event: EventDatabaseUp, want: StateStarting},
		{name: "ignore database down while starting", state: StateStarting, event: EventDatabaseDown, want: StateStarting},
		{name: "migration done", state: StateMigrating, event: EventMigrated, want: StateReady},
		{name: "drain while migrating", state: StateMigrating, event: EventDrain, want: StateDraining},
		{name: "ready goes degraded", state: StateReady, event: EventDatabaseDown, want: StateDegraded},
		{name: "ready stays ready when the database is up", state: StateReady, event: EventDatabaseUp, want: StateReady},
		{name: "drain while ready", state: StateReady, event: EventDrain, want: StateDraining},
		{name: "degraded recovers", state: StateDegraded, event: EventDatabaseUp, want: StateReady},
		{name: "degraded stays down", state: StateDegraded, event: EventDatabaseDown, want: StateDegraded},
		{name: "drain while degraded", state: StateDegraded, event: EventDrain, want: StateDraining},
		{name: "draining ignores recovery", state: StateDraining, event: EventDatabaseUp, want: StateDraining},
		{name: "draining ignores another drain", state: StateDraining, event: EventDrain, want: StateDraining},
		{name: "migrated too early", state: StateStarting, event: EventMigrated, want: StateStarting, wantErr: ErrNoTransition},
		{name: "migrate twice", state: StateMigrating, event: EventMigrate, want: StateMigrating, wantErr: ErrNoTransition},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Next(tt.state, tt.event)
			assert.Equal(t, tt.want, got)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestMachineReachesReadyAndDrains(t *testing.T) {
	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	machine := New(logger)
	t.Cleanup(func() { require.NoError(t, machine.Close()) })
	ctx := t.Context()

	require.Equal(t, StateStarting, machine.State())
	require.False(t, machine.Ready())
	require.NoError(t, machine.BeginMigration(ctx))
	require.Equal(t, StateMigrating, machine.State())
	require.NoError(t, machine.MigrationDone(ctx))
	require.True(t, machine.Ready())
	require.NoError(t, machine.Drain(ctx))
	require.Equal(t, StateDraining, machine.State())
	require.False(t, machine.Ready())
	require.NoError(t, machine.fsm.Apply(ctx, EventDatabaseUp))
	require.Equal(t, StateDraining, machine.State())

	text := logs.String()
	assert.Contains(t, text, "starting")
	assert.Contains(t, text, "ready")
	assert.Contains(t, text, "draining")
	assert.NotContains(t, text, "password")
}

func TestDatabaseEventsBeforeReadyDoNotBlockMigration(t *testing.T) {
	machine := New(nil)
	t.Cleanup(func() { require.NoError(t, machine.Close()) })
	ctx := t.Context()

	require.NoError(t, machine.fsm.Apply(ctx, EventDatabaseDown))
	require.Equal(t, StateStarting, machine.State())
	require.NoError(t, machine.BeginMigration(ctx))
	require.NoError(t, machine.fsm.Apply(ctx, EventDatabaseDown))
	require.Equal(t, StateMigrating, machine.State())
	require.NoError(t, machine.MigrationDone(ctx))
	require.Equal(t, StateReady, machine.State())
}

func TestApplyRejectsABadTransition(t *testing.T) {
	machine := New(nil)
	t.Cleanup(func() { require.NoError(t, machine.Close()) })
	err := machine.MigrationDone(t.Context())
	require.ErrorIs(t, err, ErrNoTransition)
	require.Equal(t, StateStarting, machine.State())
	assert.NotContains(t, err.Error(), "secret")
}

func TestWatchDatabaseMovesBetweenReadyAndDegraded(t *testing.T) {
	machine := New(nil)
	t.Cleanup(func() { require.NoError(t, machine.Close()) })
	ctx := t.Context()
	require.NoError(t, machine.BeginMigration(ctx))
	require.NoError(t, machine.MigrationDone(ctx))

	var up atomic.Bool
	up.Store(true)
	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		machine.WatchDatabase(watchCtx, func(context.Context) error {
			if up.Load() {
				return nil
			}
			return errors.New("down")
		}, 15*time.Millisecond)
	}()

	up.Store(false)
	require.Eventually(t, func() bool {
		return machine.State() == StateDegraded
	}, time.Second, 5*time.Millisecond)
	require.False(t, machine.Ready())

	up.Store(true)
	require.Eventually(t, func() bool {
		return machine.State() == StateReady
	}, time.Second, 5*time.Millisecond)

	cancel()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("watch did not stop")
	}
}

func TestBeginMigrationHonoursACancelledContext(t *testing.T) {
	machine := New(nil)
	t.Cleanup(func() { require.NoError(t, machine.Close()) })
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := machine.BeginMigration(ctx)
	require.Error(t, err)
	require.Equal(t, StateStarting, machine.State())
}
