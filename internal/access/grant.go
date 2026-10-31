package access

import (
	"fmt"
	"slices"
	"time"
	"uuid"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/users"
)

// GrantID identifies one grant. It is not a secret.
type GrantID uuid.UUID

// NewGrantID returns a random UUID.
func NewGrantID() GrantID {
	return GrantID(uuid.New())
}

// GrantIDFromBytes returns the id for the 16 UUID bytes.
func GrantIDFromBytes(b [16]byte) GrantID {
	return GrantID(b)
}

// Bytes returns the 16-byte UUID form.
func (id GrantID) Bytes() [16]byte {
	return uuid.UUID(id)
}

func (id GrantID) String() string {
	return uuid.UUID(id).String()
}

// MarshalText encodes the UUID text form.
func (id GrantID) MarshalText() ([]byte, error) {
	text, err := uuid.UUID(id).MarshalText()
	if err != nil {
		return nil, fmt.Errorf("access: grant id: %w", err)
	}
	return text, nil
}

// UnmarshalText reads the UUID text form.
func (id *GrantID) UnmarshalText(text []byte) error {
	parsed, err := uuid.Parse(string(text))
	if err != nil {
		return fmt.Errorf("access: grant id: %w", err)
	}
	*id = GrantID(parsed)
	return nil
}

// Subject is the one user or the one group a grant is for.
// The zero value names nobody and is not valid.
type Subject struct {
	user  users.ID
	group groups.Name
}

// UserSubject is a grant to one user.
func UserSubject(id users.ID) Subject {
	return Subject{user: id}
}

// GroupSubject is a grant to every member of one group.
func GroupSubject(name groups.Name) Subject {
	return Subject{group: name}
}

// User returns the user and true for a user subject.
func (s Subject) User() (users.ID, bool) {
	return s.user, s.user != users.ID{}
}

// Group returns the group and true for a group subject.
func (s Subject) Group() (groups.Name, bool) {
	return s.group, s.group != groups.Name{}
}

// Valid reports a subject with exactly one of a user and a group.
func (s Subject) Valid() bool {
	_, isUser := s.User()
	_, isGroup := s.Group()
	return isUser != isGroup
}

// Covers reports whether the subject is the user or one of the user's groups.
func (s Subject) Covers(user users.ID, userGroups []groups.Name) bool {
	if id, ok := s.User(); ok {
		return id == user
	}
	name, ok := s.Group()
	if !ok {
		return false
	}
	return slices.Contains(userGroups, name)
}

// Expiry is the time a grant stops counting. The zero value never expires.
type Expiry struct {
	at time.Time
}

// ExpiresAt is an expiry at t.
func ExpiresAt(t time.Time) Expiry {
	return Expiry{at: t.UTC()}
}

// Time returns the expiry time and true, or false for a grant that never expires.
func (e Expiry) Time() (time.Time, bool) {
	return e.at, !e.at.IsZero()
}

// MarshalText encodes the expiry as an RFC 3339 time. The zero value is empty.
func (e Expiry) MarshalText() ([]byte, error) {
	if e.at.IsZero() {
		return nil, nil
	}
	return []byte(e.at.Format(time.RFC3339Nano)), nil
}

// UnmarshalText reads an RFC 3339 time.
// The zero time is refused with ErrExpiry: as an Expiry it would mean "never".
func (e *Expiry) UnmarshalText(text []byte) error {
	at, err := time.Parse(time.RFC3339Nano, string(text))
	if err != nil {
		return ErrExpiryTime
	}
	if at.IsZero() {
		return ErrExpiry
	}
	*e = ExpiresAt(at)
	return nil
}

// ActiveAt reports whether a grant with this expiry counts at now.
// A grant stops counting at its expiry time.
func (e Expiry) ActiveAt(now time.Time) bool {
	return e.at.IsZero() || now.Before(e.at)
}

// Grant gives one subject one resource until it expires or is revoked.
type Grant struct {
	ID        GrantID
	Resource  ResourceName
	Subject   Subject
	Expiry    Expiry
	CreatedAt time.Time
}
