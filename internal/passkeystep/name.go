package passkeystep

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxNameLengthRunes is the longest passkey name.
const MaxNameLengthRunes = 64

// Name is the label a person gives a passkey. It is not a secret.
type Name struct {
	value string
}

// ParseName trims raw. A name has 1 to 64 characters and no control character.
func ParseName(raw string) (Name, error) {
	s := strings.TrimSpace(raw)
	n := utf8.RuneCountInString(s)
	if !utf8.ValidString(s) || n < 1 || n > MaxNameLengthRunes {
		return Name{}, ErrName
	}
	if strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return Name{}, ErrName
	}
	return Name{value: s}, nil
}

func (n Name) String() string {
	return n.value
}
