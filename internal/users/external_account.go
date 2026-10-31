package users

import (
	"fmt"
	"strings"
)

// MaxSubjectLength is the longest subject, in characters.
const MaxSubjectLength = 255

// Subject is the id of an account at an outside provider, such as the Google `sub` claim.
// It is not a secret. It is the only value that links an outside account to a user.
type Subject struct {
	value string
}

// ParseSubject accepts 1 to MaxSubjectLength characters. It does not change the case.
func ParseSubject(raw string) (Subject, error) {
	if raw == "" || len([]rune(raw)) > MaxSubjectLength || strings.TrimSpace(raw) != raw {
		return Subject{}, fmt.Errorf("users: subject: %w", ErrInvalidSubject)
	}
	return Subject{value: raw}, nil
}

func (s Subject) String() string {
	return s.value
}

// ExternalAccount is one account at an outside provider. Kind names the provider.
type ExternalAccount struct {
	Kind    Kind
	Subject Subject
}
