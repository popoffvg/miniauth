package identitylink

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
)

// SecretHash is the SHA-256 of a LinkSecret. The database stores this, never the secret.
type SecretHash [sha256.Size]byte

// secretLength is the base64 raw URL length of a 32-byte secret.
const secretLength = 43

// LinkSecret binds a pending link to one browser. Only that browser's cookie holds it.
// Printing it yields "redacted".
type LinkSecret struct {
	raw [32]byte
}

// NewLinkSecret returns 32 random bytes.
func NewLinkSecret() (LinkSecret, error) {
	var secret LinkSecret
	if _, err := rand.Read(secret.raw[:]); err != nil {
		return LinkSecret{}, fmt.Errorf("identitylink: secret: %w", err)
	}
	return secret, nil
}

// ParseLinkSecret reads the cookie value. A value that is not a secret is ErrNotFound.
// The error MUST NOT contain the value.
func ParseLinkSecret(value string) (LinkSecret, error) {
	if len(value) != secretLength {
		return LinkSecret{}, ErrNotFound
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != len(LinkSecret{}.raw) {
		return LinkSecret{}, ErrNotFound
	}
	var secret LinkSecret
	copy(secret.raw[:], raw)
	return secret, nil
}

// CookieValue is the value of the browser cookie. The caller MUST NOT log it.
func (s LinkSecret) CookieValue() string {
	return base64.RawURLEncoding.EncodeToString(s.raw[:])
}

// Hash returns the value to store.
func (s LinkSecret) Hash() SecretHash {
	return SecretHash(sha256.Sum256(s.raw[:]))
}

// String returns "redacted".
func (LinkSecret) String() string {
	return "redacted"
}

// GoString returns "redacted".
func (LinkSecret) GoString() string {
	return "redacted"
}

// Format prints "redacted" for every verb, so a log cannot show the secret.
func (LinkSecret) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "redacted")
}

// LogValue keeps the secret out of slog.
func (LinkSecret) LogValue() slog.Value {
	return slog.StringValue("redacted")
}
