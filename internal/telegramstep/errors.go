package telegramstep

import "errors"

var (
	// ErrBadData means the callback query is not widget data: a field is missing, repeated, or malformed.
	ErrBadData = errors.New("telegramstep: callback data is not valid")
	// ErrBadHash means the hash does not match the fields for the bot token.
	ErrBadHash = errors.New("telegramstep: callback hash does not match")
	// ErrStale means auth_date is MaxAge old or more, or more than MaxClockSkew in the future.
	ErrStale = errors.New("telegramstep: callback data is too old")
	// ErrReplay means the same widget data was already used for a login.
	ErrReplay = errors.New("telegramstep: callback data was already used")
	// ErrConfig means the bot name or the bot token is missing or not valid.
	ErrConfig = errors.New("telegramstep: config is not complete")
)
