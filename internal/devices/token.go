package devices

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/popoffvg/miniauth/internal/users"
)

// TokenHash is the SHA-256 of a device token. The database stores this, never the token.
type TokenHash [sha256.Size]byte

// tokenValueLength is the base64 raw URL length of a 32-byte token.
const tokenValueLength = 43

// Token is the value of the device cookie.
// Printing it yields "redacted".
type Token struct {
	users.Redacted
	raw [32]byte
}

// NewToken returns 32 random bytes. The token is not zero.
func NewToken() (Token, error) {
	var token Token
	if _, err := rand.Read(token.raw[:]); err != nil {
		return Token{}, fmt.Errorf("devices: token: %w", err)
	}
	if token.raw == [32]byte{} {
		return Token{}, errors.New("devices: token is empty")
	}
	return token, nil
}

// ParseToken reads the cookie value.
// A value that is not a device token is ErrNotFound.
// The error MUST NOT contain the value.
func ParseToken(value string) (Token, error) {
	if len(value) != tokenValueLength {
		return Token{}, ErrNotFound
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != len(Token{}.raw) {
		return Token{}, ErrNotFound
	}
	var token Token
	copy(token.raw[:], raw)
	if token.raw == [32]byte{} {
		return Token{}, ErrNotFound
	}
	return token, nil
}

// CookieValue is the value of the device cookie. The caller MUST NOT log it.
func (t Token) CookieValue() string {
	return base64.RawURLEncoding.EncodeToString(t.raw[:])
}

// Hash returns the value to store.
func (t Token) Hash() TokenHash {
	return TokenHash(sha256.Sum256(t.raw[:]))
}
