package invites

// InviteState is the stage of one invite.
type InviteState string

const (
	// StateOpen can be accepted.
	StateOpen InviteState = "open"
	// StateUsed was accepted once. It is final.
	StateUsed InviteState = "used"
	// StateExpired passed its expiry before an acceptance. It is final. No column stores it: expires_at decides.
	StateExpired InviteState = "expired"
)

// InviteEvent is one input to the invite policy.
type InviteEvent string

const (
	// EventAccept claims the invite for one new account.
	EventAccept InviteEvent = "accept"
	// EventExpire ends an open invite at its expiry.
	EventExpire InviteEvent = "expire"
)

// invitePolicy is every allowed transition. A missing pair is ErrNoTransition.
var invitePolicy = map[InviteState]map[InviteEvent]InviteState{
	StateOpen: {EventAccept: StateUsed, EventExpire: StateExpired},
}

// Next reads no clock and no store: the service sends EventExpire when the clock passed the expiry.
func Next(state InviteState, event InviteEvent) (InviteState, error) {
	next, ok := invitePolicy[state][event]
	if !ok {
		return state, ErrNoTransition
	}
	return next, nil
}
