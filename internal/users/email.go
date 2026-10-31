package users

import (
	"fmt"
	"strings"
)

// Email is a login that contains '@'. The account has no separate email column.
// The value is set only by ParseEmail and Login.Email.
type Email struct {
	login Login
}

// ParseEmail parses raw with ParseLogin and requires '@'.
func ParseEmail(raw string) (Email, error) {
	login, err := ParseLogin(raw)
	if err != nil {
		return Email{}, err
	}
	email, ok := login.Email()
	if !ok {
		return Email{}, fmt.Errorf("users: email: %w", ErrInvalidLogin)
	}
	return email, nil
}

// Email returns the login as an address when it contains '@'.
func (l Login) Email() (Email, bool) {
	if !strings.Contains(l.value, "@") {
		return Email{}, false
	}
	return Email{login: l}, true
}

// Login is the login equal to the address.
func (e Email) Login() Login {
	return e.login
}

func (e Email) String() string {
	return e.login.value
}
