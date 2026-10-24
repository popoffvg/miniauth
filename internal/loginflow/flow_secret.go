package loginflow

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
)

// SecretHash is the SHA-256 of a flow secret. The database stores this, never the secret.
type SecretHash [sha256.Size]byte

// FlowSecret is the unguessable part of one login in progress.
// Printing it yields "redacted".
type FlowSecret struct {
	raw [32]byte
}

// NewFlowSecret returns 32 random bytes.
func NewFlowSecret() (FlowSecret, error) {
	var secret FlowSecret
	if _, err := rand.Read(secret.raw[:]); err != nil {
		return FlowSecret{}, fmt.Errorf("loginflow: flow secret: %w", err)
	}
	return secret, nil
}

// ParseFlowSecret copies raw. raw MUST be 32 bytes.
func ParseFlowSecret(raw []byte) (FlowSecret, error) {
	if len(raw) != len(FlowSecret{}.raw) {
		return FlowSecret{}, fmt.Errorf("loginflow: flow secret: want %d bytes, got %d", len(FlowSecret{}.raw), len(raw))
	}
	var secret FlowSecret
	copy(secret.raw[:], raw)
	return secret, nil
}

// Bytes returns a copy of the secret. The caller MUST NOT log it.
func (s FlowSecret) Bytes() [32]byte {
	return s.raw
}

// Hash returns the value to store.
func (s FlowSecret) Hash() SecretHash {
	return sha256.Sum256(s.raw[:])
}

// Matches reports whether secret hashes to hash. The comparison is constant time.
func (s FlowSecret) Matches(hash SecretHash) bool {
	sum := sha256.Sum256(s.raw[:])
	return subtle.ConstantTimeCompare(sum[:], hash[:]) == 1
}

// String returns "redacted".
func (s FlowSecret) String() string {
	return "redacted"
}

// GoString returns "redacted".
func (s FlowSecret) GoString() string {
	return "redacted"
}

// Format prints "redacted" for every verb, so a log cannot show the secret.
func (s FlowSecret) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "redacted")
}
