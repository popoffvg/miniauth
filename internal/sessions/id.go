package sessions

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

// Hash is the SHA-256 of a session id. The database stores this, never the id.
type Hash [sha256.Size]byte

// valueLength is the base64 raw URL length of a 32-byte id.
const valueLength = 43

// ID is the session id from the cookie.
// Printing it yields "redacted".
type ID struct {
	raw [32]byte
}

// NewID returns 32 random bytes.
// The id is not zero.
func NewID() (ID, error) {
	var id ID
	if _, err := rand.Read(id.raw[:]); err != nil {
		return ID{}, fmt.Errorf("sessions: id: %w", err)
	}
	if id.isZero() {
		return ID{}, errors.New("sessions: id is empty")
	}
	return id, nil
}

// ParseID reads the cookie value.
// A value that is not a session id is ErrNotFound.
// The error MUST NOT contain the value.
func ParseID(value string) (ID, error) {
	if len(value) != valueLength {
		return ID{}, ErrNotFound
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != len(ID{}.raw) {
		return ID{}, ErrNotFound
	}
	var id ID
	copy(id.raw[:], raw)
	if id.isZero() {
		return ID{}, ErrNotFound
	}
	return id, nil
}

// Bytes returns a copy of the id. The caller MUST NOT log it.
func (id ID) Bytes() [32]byte {
	return id.raw
}

// CookieValue is the value of the session cookie. The caller MUST NOT log it.
func (id ID) CookieValue() string {
	return base64.RawURLEncoding.EncodeToString(id.raw[:])
}

// Hash returns the value to store.
func (id ID) Hash() Hash {
	return Hash(sha256.Sum256(id.raw[:]))
}

// Matches reports whether id hashes to hash. The comparison is constant time.
func (id ID) Matches(hash Hash) bool {
	sum := sha256.Sum256(id.raw[:])
	return subtle.ConstantTimeCompare(sum[:], hash[:]) == 1
}

func (id ID) isZero() bool {
	return id.raw == [32]byte{}
}

// String returns "redacted".
func (id ID) String() string {
	return "redacted"
}

// GoString returns "redacted".
func (id ID) GoString() string {
	return "redacted"
}

// Format prints "redacted" for every verb, so a log cannot show the id.
func (id ID) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "redacted")
}

// LogValue keeps the id out of slog.
func (id ID) LogValue() slog.Value {
	return slog.StringValue("redacted")
}
