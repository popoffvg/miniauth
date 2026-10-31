package googlestep

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"

	"golang.org/x/oauth2"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/users"
)

// State is the OAuth state. It travels in the URL, so it binds the callback to the flow and is not a secret.
type State string

// Nonce is the OIDC nonce. The ID token MUST carry the same value.
type Nonce string

// Code is the authorization code from the callback URL. It is good for one exchange.
type Code string

// Verifier is the PKCE code verifier. Only the browser cookie holds it. Printing it yields "redacted".
type Verifier struct {
	users.Redacted
	value string
}

// ParseVerifier reads the cookie value. An empty value is not a verifier.
// The error MUST NOT contain the value.
func ParseVerifier(raw string) (Verifier, error) {
	if raw == "" {
		return Verifier{}, ErrBadCallback
	}
	return Verifier{value: raw}, nil
}

// CookieValue is the value of the verifier cookie. The caller MUST NOT log it.
func (v Verifier) CookieValue() string {
	return v.value
}

type digest [sha256.Size]byte

// challenge is the stored part of one Google step: three SHA-256 digests.
type challenge struct {
	state    digest
	nonce    digest
	verifier digest
}

// newChallenge makes a random state, nonce, and verifier, and the challenge that hashes them.
func newChallenge() (State, Nonce, Verifier, challenge) {
	state := State(rand.Text())
	nonce := Nonce(rand.Text())
	verifier := Verifier{value: oauth2.GenerateVerifier()}
	return state, nonce, verifier, challenge{
		state:    sha256.Sum256([]byte(state)),
		nonce:    sha256.Sum256([]byte(nonce)),
		verifier: sha256.Sum256([]byte(verifier.value)),
	}
}

func (c challenge) encode() loginflow.Challenge {
	out := make(loginflow.Challenge, 0, 3*sha256.Size)
	out = append(out, c.state[:]...)
	out = append(out, c.nonce[:]...)
	return append(out, c.verifier[:]...)
}

func decodeChallenge(raw loginflow.Challenge) (challenge, error) {
	if len(raw) != 3*sha256.Size {
		return challenge{}, errors.New("googlestep: stored challenge has a wrong length")
	}
	var c challenge
	copy(c.state[:], raw[:sha256.Size])
	copy(c.nonce[:], raw[sha256.Size:2*sha256.Size])
	copy(c.verifier[:], raw[2*sha256.Size:])
	return c, nil
}

// matches compares the callback values with the stored digests in constant time.
func (c challenge) matches(state State, verifier Verifier) bool {
	return sameDigest(c.state, string(state))&sameDigest(c.verifier, verifier.value) == 1
}

func (c challenge) matchesNonce(nonce string) bool {
	return sameDigest(c.nonce, nonce) == 1
}

func sameDigest(want digest, value string) int {
	got := sha256.Sum256([]byte(value))
	return subtle.ConstantTimeCompare(got[:], want[:])
}
