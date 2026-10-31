package invites

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/popoffvg/miniauth/internal/users"
)

// TokenHash is the SHA-256 of a token. The database stores this, never the token.
type TokenHash [sha256.Size]byte

// tokenLength is the base64 raw URL length of 32 bytes.
const tokenLength = 43

// Token is the secret in an invite link. Printing it yields "redacted".
type Token struct {
	users.Redacted
	raw [32]byte
}

// NewToken returns 32 random bytes.
func NewToken() (Token, error) {
	var token Token
	if _, err := rand.Read(token.raw[:]); err != nil {
		return Token{}, fmt.Errorf("invites: token: %w", err)
	}
	return token, nil
}

// ParseToken reads the token from a link or a form.
// A value that is not a token is ErrInviteGone. The error MUST NOT contain the value.
func ParseToken(value string) (Token, error) {
	if len(value) != tokenLength {
		return Token{}, ErrInviteGone
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != len(Token{}.raw) {
		return Token{}, ErrInviteGone
	}
	var token Token
	copy(token.raw[:], raw)
	return token, nil
}

// Reveal returns the text form for the link. The caller MUST NOT log it or store it.
func (t Token) Reveal() string {
	return base64.RawURLEncoding.EncodeToString(t.raw[:])
}

// Hash returns the value to store.
func (t Token) Hash() TokenHash {
	return TokenHash(sha256.Sum256(t.raw[:]))
}
