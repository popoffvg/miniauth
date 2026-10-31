package recovery

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/popoffvg/miniauth/internal/users"
)

// tokenTextLength is the base64 raw URL length of 32 bytes.
const tokenTextLength = 43

// TokenHash is the SHA-256 of a reset token. The database stores this, never the token.
type TokenHash [sha256.Size]byte

// Token is the random secret in a reset link. Printing it yields "redacted".
type Token struct {
	users.Redacted
	raw [32]byte
}

// NewToken returns 32 random bytes.
func NewToken() (Token, error) {
	var token Token
	if _, err := rand.Read(token.raw[:]); err != nil {
		return Token{}, fmt.Errorf("recovery: token: %w", err)
	}
	if token.raw == [32]byte{} {
		return Token{}, errors.New("recovery: token is empty")
	}
	return token, nil
}

// ParseToken reads the link form. A value that is not a token is ErrInvalidToken.
// The error MUST NOT contain the value.
func ParseToken(value string) (Token, error) {
	if len(value) != tokenTextLength {
		return Token{}, ErrInvalidToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != len(Token{}.raw) {
		return Token{}, ErrInvalidToken
	}
	var token Token
	copy(token.raw[:], raw)
	if token.raw == [32]byte{} {
		return Token{}, ErrInvalidToken
	}
	return token, nil
}

// LinkValue is the path segment of the reset link. The caller MUST NOT log it.
func (t Token) LinkValue() string {
	return base64.RawURLEncoding.EncodeToString(t.raw[:])
}

// Hash returns the value to store.
func (t Token) Hash() TokenHash {
	return TokenHash(sha256.Sum256(t.raw[:]))
}

// Matches reports whether t hashes to hash. The comparison is constant time.
func (t Token) Matches(hash TokenHash) bool {
	sum := t.Hash()
	return subtle.ConstantTimeCompare(sum[:], hash[:]) == 1
}

// MarshalText does not write the token.
func (Token) MarshalText() ([]byte, error) {
	return []byte("redacted"), nil
}
