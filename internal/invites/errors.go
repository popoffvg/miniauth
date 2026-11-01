package invites

import "errors"

// ErrInviteGone means the token is unknown, malformed, used, or expired.
// The four cases share one error, so a guess learns nothing.
var ErrInviteGone = errors.New("invites: invite is not valid")

// ErrNoTransition means the invite policy refuses the event in the current state.
var ErrNoTransition = errors.New("invites: no transition")
