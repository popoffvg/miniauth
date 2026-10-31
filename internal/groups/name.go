package groups

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxNameLengthRunes is the longest group name.
const MaxNameLengthRunes = 64

// Name is a lower-case group name, not a secret.
type Name struct {
	value string
}

// ParseName parses a group name.
// A name has 1 to 64 characters. The first and last are a letter or a digit.
// The rest may also be '.', '_', or '-'.
func ParseName(raw string) (Name, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if !validName(s) {
		return Name{}, ErrName
	}
	return Name{value: s}, nil
}

func (n Name) String() string {
	return n.value
}

func validName(s string) bool {
	n := utf8.RuneCountInString(s)
	if n < 1 || n > MaxNameLengthRunes {
		return false
	}
	for i, r := range s {
		if r > unicode.MaxASCII || !nameRune(r) {
			return false
		}
		isEdge := i == 0 || i == len(s)-1
		if isEdge && !letterOrDigit(r) {
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

// MarshalText encodes the stored name.
func (n Name) MarshalText() ([]byte, error) {
	return []byte(n.value), nil
}

// UnmarshalText parses text with ParseName.
func (n *Name) UnmarshalText(text []byte) error {
	parsed, err := ParseName(string(text))
	if err != nil {
		return err
	}
	*n = parsed
	return nil
}
