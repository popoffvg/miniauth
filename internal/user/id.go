package user

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// UserID identifies one user. It is not a secret.
//
//nolint:revive // UserID is the domain name. ID would collide with IdentityID in this package.
type UserID string

// IdentityID identifies one identity. It is not a secret.
type IdentityID string

// NewUserID returns a random UUID.
func NewUserID() (UserID, error) {
	b, err := newUUID()
	if err != nil {
		return "", err
	}
	return UserID(formatUUID(b)), nil
}

// NewIdentityID returns a random UUID.
func NewIdentityID() (IdentityID, error) {
	b, err := newUUID()
	if err != nil {
		return "", err
	}
	return IdentityID(formatUUID(b)), nil
}

// UserIDFromBytes returns the canonical form of a UUID.
//
//nolint:revive // UserID is the domain name. IDFromBytes would not say which id.
func UserIDFromBytes(b [16]byte) UserID {
	return UserID(formatUUID(b))
}

// IdentityIDFromBytes returns the canonical form of a UUID.
func IdentityIDFromBytes(b [16]byte) IdentityID {
	return IdentityID(formatUUID(b))
}

func (id UserID) String() string {
	return string(id)
}

// Bytes returns the 16-byte UUID form.
func (id UserID) Bytes() ([16]byte, error) {
	b, err := parseUUID(string(id))
	if err != nil {
		return b, fmt.Errorf("user: user id: %w", err)
	}
	return b, nil
}

func (id IdentityID) String() string {
	return string(id)
}

// Bytes returns the 16-byte UUID form.
func (id IdentityID) Bytes() ([16]byte, error) {
	b, err := parseUUID(string(id))
	if err != nil {
		return b, fmt.Errorf("user: identity id: %w", err)
	}
	return b, nil
}

func newUUID() ([16]byte, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return b, fmt.Errorf("user: id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return b, nil
}

func formatUUID(b [16]byte) string {
	var buf [36]byte
	hex.Encode(buf[0:8], b[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], b[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], b[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], b[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:], b[10:])
	return string(buf[:])
}

func parseUUID(s string) ([16]byte, error) {
	s = strings.ToLower(s)
	var out [16]byte
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return out, fmt.Errorf("invalid uuid %q", s)
	}
	plain := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:]
	decoded, err := hex.DecodeString(plain)
	if err != nil || len(decoded) != 16 {
		return out, fmt.Errorf("invalid uuid %q", s)
	}
	copy(out[:], decoded)
	return out, nil
}
