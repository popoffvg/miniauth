package loginflow

import "strings"

// ReturnURL is where the browser goes after a completed login.
// The host check lives with the login page.
type ReturnURL string

// NewReturnURL rejects an empty URL.
func NewReturnURL(raw string) (ReturnURL, error) {
	if strings.TrimSpace(raw) == "" {
		return "", ErrReturnURL
	}
	return ReturnURL(raw), nil
}

func (u ReturnURL) String() string {
	return string(u)
}
