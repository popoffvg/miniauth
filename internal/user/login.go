package user

import (
	"fmt"
	"strings"
	"unicode"
)

// MaxLoginLength is the longest login, in characters.
const MaxLoginLength = 64

// Login is the name a person types to sign in.
// It is stored in lower case. It is not a secret.
type Login string

// ParseLogin trims raw, folds it to lower case, and checks the login rules.
// A login has 1 to 64 characters. The first and last are a letter or a digit.
// The rest may also be '.', '_', '@', '+', or '-'.
func ParseLogin(raw string) (Login, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if !validLogin(s) {
		return "", fmt.Errorf("user: login: %w", ErrInvalidLogin)
	}
	return Login(s), nil
}

func (l Login) String() string {
	return string(l)
}

func validLogin(s string) bool {
	n := len([]rune(s))
	if n < 1 || n > MaxLoginLength {
		return false
	}
	for i, r := range s {
		if r > unicode.MaxASCII || !loginRune(r) {
			return false
		}
		edge := i == 0 || i == len(s)-1
		if edge && !letterOrDigit(r) {
			return false
		}
	}
	return true
}

func loginRune(r rune) bool {
	return letterOrDigit(r) || r == '.' || r == '_' || r == '@' || r == '+' || r == '-'
}

func letterOrDigit(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}
