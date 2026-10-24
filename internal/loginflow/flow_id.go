package loginflow

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// FlowID identifies one login in progress. It is not a secret.
type FlowID string

// NewFlowID returns a random UUID.
func NewFlowID() (FlowID, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("loginflow: flow id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return FlowID(formatUUID(b)), nil
}

// ParseFlowID checks that raw is a UUID and returns it in canonical form.
func ParseFlowID(raw string) (FlowID, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	b, err := parseUUID(s)
	if err != nil {
		return "", fmt.Errorf("loginflow: flow id: %w", err)
	}
	return FlowID(formatUUID(b)), nil
}

func (id FlowID) String() string {
	return string(id)
}

// Bytes returns the 16-byte UUID form.
func (id FlowID) Bytes() ([16]byte, error) {
	b, err := parseUUID(string(id))
	if err != nil {
		return b, fmt.Errorf("loginflow: flow id: %w", err)
	}
	return b, nil
}

// FlowIDFromBytes returns the canonical form of a UUID.
func FlowIDFromBytes(b [16]byte) FlowID {
	return FlowID(formatUUID(b))
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
