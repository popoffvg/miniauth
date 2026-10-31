package access

import (
	"strings"
	"unicode/utf8"
)

// MaxResourceNameRunes is the longest resource name.
const MaxResourceNameRunes = 64

// ResourceName is the unique lower-case name of a resource.
type ResourceName struct {
	value string
}

// ParseResourceName parses a resource name.
// A name has 1 to 64 characters. The first and last are a letter or a digit.
// The rest may also be '.', '_', or '-'.
func ParseResourceName(raw string) (ResourceName, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if !validResourceName(s) {
		return ResourceName{}, ErrResourceName
	}
	return ResourceName{value: s}, nil
}

func (n ResourceName) String() string {
	return n.value
}

func validResourceName(s string) bool {
	n := utf8.RuneCountInString(s)
	if n < 1 || n > MaxResourceNameRunes {
		return false
	}
	for i, r := range s {
		edge := i == 0 || i == len(s)-1
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
		case !edge && (r == '.' || r == '_' || r == '-'):
		default:
			return false
		}
	}
	return true
}

// MarshalText encodes the stored name.
func (n ResourceName) MarshalText() ([]byte, error) {
	return []byte(n.value), nil
}

// UnmarshalText parses text with ParseResourceName.
func (n *ResourceName) UnmarshalText(text []byte) error {
	parsed, err := ParseResourceName(string(text))
	if err != nil {
		return err
	}
	*n = parsed
	return nil
}
