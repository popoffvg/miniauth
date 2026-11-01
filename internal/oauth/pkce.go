package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"

	"golang.org/x/oauth2"

	"github.com/popoffvg/miniauth/internal/users"
)

const (
	// ChallengeMethodS256 is the one PKCE method the server takes. "plain" is refused.
	ChallengeMethodS256 = "S256"
	// challengeLength is the base64 raw URL length of a SHA-256.
	challengeLength   = 43
	minVerifierLength = 43
	maxVerifierLength = 128
	verifierAlphabet  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)

// Challenge is the S256 PKCE code challenge: the base64url SHA-256 of the verifier.
type Challenge struct {
	value string
}

// ParseChallenge reads code_challenge and code_challenge_method. Only S256 is taken.
func ParseChallenge(raw, method string) (Challenge, error) {
	if method != ChallengeMethodS256 || len(raw) != challengeLength {
		return Challenge{}, ErrChallenge
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(decoded) != sha256.Size {
		return Challenge{}, ErrChallenge
	}
	return Challenge{value: raw}, nil
}

// Verifies reports whether verifier hashes to the challenge. The comparison is constant time.
func (c Challenge) Verifies(verifier Verifier) bool {
	if c.value == "" || verifier.raw == "" {
		return false
	}
	encoded := oauth2.S256ChallengeFromVerifier(verifier.raw)
	return subtle.ConstantTimeCompare([]byte(encoded), []byte(c.value)) == 1
}

func (c Challenge) String() string {
	return c.value
}

// Verifier is the PKCE code verifier: 43 to 128 unreserved characters. Printing it yields "redacted".
type Verifier struct {
	users.Redacted
	raw string
}

// ParseVerifier reads code_verifier. A malformed verifier is ErrInvalidGrant. The error MUST NOT contain the value.
func ParseVerifier(raw string) (Verifier, error) {
	if len(raw) < minVerifierLength || len(raw) > maxVerifierLength {
		return Verifier{}, ErrInvalidGrant
	}
	for i := range len(raw) {
		if !strings.ContainsRune(verifierAlphabet, rune(raw[i])) {
			return Verifier{}, ErrInvalidGrant
		}
	}
	return Verifier{raw: raw}, nil
}
