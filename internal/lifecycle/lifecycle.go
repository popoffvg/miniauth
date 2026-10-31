package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/avast/retry-go"

	"github.com/popoffvg/sfsm"
)

const (
	// ProbeInterval is the pause between database pings.
	ProbeInterval = 5 * time.Second
	// ProbeTimeout is how long one ping may run.
	// ProbeInterval plus ProbeTimeout is under 10s, so /readyz can turn 503 within 10s after PostgreSQL stops.
	ProbeTimeout = 2 * time.Second
)

// State is one stage of the process.
type State string

const (
	// StateStarting is the state before migration begins.
	StateStarting State = "starting"
	// StateMigrating means the schema migration is in progress.
	StateMigrating State = "migrating"
	// StateReady means the process can take traffic.
	StateReady State = "ready"
	// StateDegraded means PostgreSQL did not answer the last ping.
	StateDegraded State = "degraded"
	// StateDraining means the process is shutting down.
	// Draining is final.
	StateDraining State = "draining"
)

// Event is an input to the lifecycle policy.
type Event string

const (
	// EventMigrate starts the migration.
	EventMigrate Event = "migrate"
	// EventMigrated means the migration has finished.
	EventMigrated Event = "migrated"
	// EventDatabaseUp means a ping reached PostgreSQL.
	EventDatabaseUp Event = "database_up"
	// EventDatabaseDown means a ping did not reach PostgreSQL.
	EventDatabaseDown Event = "database_down"
	// EventDrain starts the shutdown.
	EventDrain Event = "drain"
)

// ErrNoTransition means the policy refuses the event in the current state.
var ErrNoTransition = errors.New("lifecycle: no transition")

// Next is the lifecycle policy.
// A database event moves only between Ready and Degraded.
// Any other database event leaves the state as it is.
// Drain is final: later events stay in Draining.
func Next(state State, event Event) (State, error) {
	if state == StateDraining {
		return state, nil
	}
	switch state {
	case StateStarting:
		switch event {
		case EventMigrate:
			return StateMigrating, nil
		case EventDrain:
			return StateDraining, nil
		}
	case StateMigrating:
		switch event {
		case EventMigrated:
			return StateReady, nil
		case EventDrain:
			return StateDraining, nil
		}
	case StateReady:
		switch event {
		case EventDatabaseDown:
			return StateDegraded, nil
		case EventDrain:
			return StateDraining, nil
		}
	case StateDegraded:
		switch event {
		case EventDatabaseUp:
			return StateReady, nil
		case EventDrain:
			return StateDraining, nil
		}
	}
	if event == EventDatabaseUp || event == EventDatabaseDown {
		return state, nil
	}
	return state, ErrNoTransition
}

// Machine is the process lifecycle.
// It applies events one at a time through sfsm.SFSM.
type Machine struct {
	fsm *sfsm.SFSM[State, Event]
}

// New starts the machine in Starting.
// A nil logger discards the transition log.
func New(logger *slog.Logger) *Machine {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	fsm := sfsm.NewSFSM(StateStarting, Next, &sfsm.SFSMOptions[State, Event]{
		AfterStateChanged: func(from, to State, event Event) {
			logger.Info("miniauth: lifecycle",
				"from", from,
				"to", to,
				"event", event,
			)
		},
	})
	return &Machine{fsm: fsm}
}

// State returns the current stage.
func (m *Machine) State() State {
	return m.fsm.Get()
}

// Ready reports whether the process can take traffic.
func (m *Machine) Ready() bool {
	return m.State() == StateReady
}

// BeginMigration moves Starting to Migrating.
func (m *Machine) BeginMigration(ctx context.Context) error {
	return m.apply(ctx, EventMigrate)
}

// MigrationDone moves Migrating to Ready.
func (m *Machine) MigrationDone(ctx context.Context) error {
	return m.apply(ctx, EventMigrated)
}

// Drain moves the process to Draining.
// Later events stay in Draining.
func (m *Machine) Drain(ctx context.Context) error {
	return m.apply(ctx, EventDrain)
}

// WatchDatabase pings the database and applies each result.
// It blocks until ctx is cancelled or the machine is closed.
// every is the pause between pings. The process uses ProbeInterval.
// ping MUST return when ctx is done.
// ping MUST NOT log its error: the error can hold a connection string.
func (m *Machine) WatchDatabase(ctx context.Context, ping func(context.Context) error, every time.Duration) {
	sfsm.ObserveExternalState(ctx, m.fsm, func(ctx context.Context) Event {
		probe, cancel := context.WithTimeout(ctx, ProbeTimeout)
		defer cancel()
		if err := ping(probe); err != nil {
			return EventDatabaseDown
		}
		return EventDatabaseUp
	}, retry.Delay(every), retry.DelayType(retry.FixedDelay))
}

// Close stops the machine.
// Close stops WatchDatabase. Call Close only once.
func (m *Machine) Close() error {
	if err := m.fsm.Close(); err != nil {
		return fmt.Errorf("lifecycle: close: %w", err)
	}
	return nil
}

func (m *Machine) apply(ctx context.Context, event Event) error {
	// sfsm.Apply can still send the event when ctx is done: its select picks a ready case at random.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("lifecycle: apply: %w", err)
	}
	if err := m.fsm.Apply(ctx, event); err != nil {
		return fmt.Errorf("lifecycle: apply: %w", err)
	}
	return nil
}
