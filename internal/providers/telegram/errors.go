package telegram

import "errors"

var (
	// ErrBadData means the callback query is not widget data: a field is missing, repeated, or malformed.
	ErrBadData = errors.New("telegram: callback data is not valid")
	// ErrBadHash means the hash does not match the fields for the bot token.
	ErrBadHash = errors.New("telegram: callback hash does not match")
	// ErrStale means auth_date is MaxAge old or more, or more than MaxClockSkew in the future.
	ErrStale = errors.New("telegram: callback data is too old")
	// ErrReplay means the same widget data was already used for a login.
	ErrReplay = errors.New("telegram: callback data was already used")
	// ErrNoTransition means the step policy refuses the data in the stored step state, such as a second callback.
	ErrNoTransition = errors.New("telegram: no step transition")
	// ErrConfig means the bot name or the bot token is missing or not valid.
	ErrConfig = errors.New("telegram: config is not complete")
)
