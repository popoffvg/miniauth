package useradmin

import (
	"time"

	"github.com/popoffvg/miniauth/internal/users"
)

// AccountStatus is whether a user may authenticate.
type AccountStatus string

const (
	// StatusActive may sign in.
	StatusActive AccountStatus = "active"
	// StatusDisabled has no session and is refused at each login.
	StatusDisabled AccountStatus = "disabled"
)

// AccountEventKind is one input to the account policy.
type AccountEventKind string

const (
	// EventDisable signs the user out everywhere and refuses each next login.
	EventDisable AccountEventKind = "disable"
	// EventEnable lets the user sign in again.
	EventEnable AccountEventKind = "enable"
)

// AccountEvent is one change an administrator asks for. At is the disabled time of EventDisable.
type AccountEvent struct {
	Kind  AccountEventKind
	Actor Actor
	At    time.Time
}

// AccountState is the state of the account machine of one user. A zero DisabledAt is an active account.
type AccountState struct {
	User       users.ID
	Status     AccountStatus
	DisabledAt time.Time
}

func accountStateOf(user users.User) AccountState {
	if user.Disabled() {
		return AccountState{User: user.ID, Status: StatusDisabled, DisabledAt: user.DisabledAt}
	}
	return AccountState{User: user.ID, Status: StatusActive}
}

// accountPolicy is every allowed transition. A missing pair is ErrNoTransition.
var accountPolicy = map[AccountStatus]map[AccountEventKind]AccountStatus{
	StatusActive:   {EventDisable: StatusDisabled},
	StatusDisabled: {EventEnable: StatusActive},
}

// Next refuses a disable by the user itself with ErrSelfDisable, so the last admin cannot lock all admins out by mistake.
// It reads no clock: the disabled time comes with the event.
func Next(state AccountState, event AccountEvent) (AccountState, error) {
	if event.Kind == EventDisable && event.Actor.ID == state.User {
		return state, ErrSelfDisable
	}
	status, ok := accountPolicy[state.Status][event.Kind]
	if !ok {
		return state, ErrNoTransition
	}
	next := AccountState{User: state.User, Status: status}
	if status == StatusDisabled {
		next.DisabledAt = event.At
	}
	return next, nil
}
