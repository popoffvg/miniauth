package groups

import (
	"strings"
	"unicode"
)

// MaxNameLength is the longest group name, in characters.
const MaxNameLength = 64

// Name is one group. It is stored in lower case. It is not a secret.
type Name struct {
	value string
}

// ParseName trims raw, folds it to lower case, and checks the name rules.
// A name has 1 to 64 characters. The first and last are a letter or a digit.
// The rest may also be '.', '_', or '-'.
func ParseName(raw string) (Name, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if !validName(s) {
		return Name{}, ErrName
	}
	return Name{value: s}, nil
}

// String returns the stored name.
func (n Name) String() string {
	return n.value
}

func validName(s string) bool {
	n := len([]rune(s))
	if n < 1 || n > MaxNameLength {
		return false
	}
	for i, r := range s {
		if r > unicode.MaxASCII || !nameRune(r) {
			return false
		}
		edge := i == 0 || i == len(s)-1
		if edge && !letterOrDigit(r) {
			return false
		}
	}
	return true
}

func nameRune(r rune) bool {
	return letterOrDigit(r) || r == '.' || r == '_' || r == '-'
}

func letterOrDigit(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}
