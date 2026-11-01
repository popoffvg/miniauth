package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/popoffvg/miniauth/internal/users"
)

// CodeLifetime is how long an authorization code waits for the exchange.
const CodeLifetime = time.Minute

// codeLength is the base64 raw URL length of 32 bytes.
const codeLength = 43

// CodeHash is the SHA-256 of an authorization code. The database stores this, never the code.
type CodeHash [sha256.Size]byte

// Code is the one-time authorization code in the redirect to the client. Printing it yields "redacted".
type Code struct {
	users.Redacted
	raw [32]byte
}

// NewCode makes a code the token endpoint takes once and within CodeLifetime.
func NewCode() (Code, error) {
	var code Code
	if _, err := rand.Read(code.raw[:]); err != nil {
		return Code{}, fmt.Errorf("oauth: code: %w", err)
	}
	return code, nil
}

// ParseCode reads the code of a token request. A value that is not a code is ErrInvalidGrant.
// The error MUST NOT contain the value.
func ParseCode(value string) (Code, error) {
	if len(value) != codeLength {
		return Code{}, ErrInvalidGrant
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != len(Code{}.raw) {
		return Code{}, ErrInvalidGrant
	}
	var code Code
	copy(code.raw[:], raw)
	return code, nil
}

// Reveal returns the text form for the redirect. The caller MUST NOT log it or store it.
func (c Code) Reveal() string {
	return base64.RawURLEncoding.EncodeToString(c.raw[:])
}

// Hash is the only form of the code the database keeps.
func (c Code) Hash() CodeHash {
	return CodeHash(sha256.Sum256(c.raw[:]))
}

// AuthorizationCode is the stored side of a code: the consent, and the redirect URI and challenge
// that the exchange MUST repeat. A zero UsedAt was not exchanged.
type AuthorizationCode struct {
	Hash        CodeHash
	ConsentID   ConsentID
	RedirectURI RedirectURI
	Challenge   Challenge
	CreatedAt   time.Time
	ExpiresAt   time.Time
	UsedAt      time.Time
}

// IsRedeemableWith reports whether the code is unexpired at now and the exchange repeats the redirect URI and the verifier.
// The redirect URI compares exactly: a loopback port that matched at the authorization MUST be the same here.
func (c AuthorizationCode) IsRedeemableWith(redirectURI RedirectURI, verifier Verifier, now time.Time) bool {
	return c.ExpiresAt.After(now) && c.RedirectURI.value == redirectURI.value && c.Challenge.Verifies(verifier)
}
