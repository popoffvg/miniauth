package loginflow

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
)

// SecretSalt is random per flow. It is not secret, but it MUST NOT be logged.
type SecretSalt [16]byte

// SecretDigest is the SHA-256 of a salt followed by a flow secret.
type SecretDigest [sha256.Size]byte

// SecretHash is what the database stores for a flow secret, never the secret.
type SecretHash struct {
	Salt   SecretSalt
	Digest SecretDigest
}

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

// Hash returns the value to store, salted with a new random salt.
func (s FlowSecret) Hash() (SecretHash, error) {
	var salt SecretSalt
	if _, err := rand.Read(salt[:]); err != nil {
		return SecretHash{}, fmt.Errorf("loginflow: secret salt: %w", err)
	}
	return s.hashWith(salt), nil
}

func (s FlowSecret) hashWith(salt SecretSalt) SecretHash {
	var input [len(SecretSalt{}) + len(FlowSecret{}.raw)]byte
	copy(input[:], salt[:])
	copy(input[len(salt):], s.raw[:])
	return SecretHash{Salt: salt, Digest: sha256.Sum256(input[:])}
}

// Matches reports whether secret hashes to hash under hash.Salt. The comparison is constant time.
func (s FlowSecret) Matches(hash SecretHash) bool {
	got := s.hashWith(hash.Salt)
	return subtle.ConstantTimeCompare(got.Digest[:], hash.Digest[:]) == 1
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
