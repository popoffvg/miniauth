package devices

import "errors"

// ErrNotFound means the device is missing or belongs to another user.
var ErrNotFound = errors.New("devices: device is not found")
