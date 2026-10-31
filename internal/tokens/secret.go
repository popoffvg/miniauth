package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"math/big"
	"strings"

	"github.com/popoffvg/miniauth/internal/users"
)

const (
	// SecretMarker starts every token, so a scanner can find a leaked token.
	SecretMarker = "idp_"
	base62Digits = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	// bodyLength is the base62 length of 32 bytes: 62^43 > 2^256.
	bodyLength   = 43
	randomBytes  = 32
	prefixLength = 8
)

// Hash is the SHA-256 of the clear token. The database stores this, never the token.
type Hash [sha256.Size]byte

// Secret is the clear token. Printing it yields "redacted".
type Secret struct {
	users.Redacted
	raw string
}

// NewSecret returns "idp_" and 32 random bytes in base62.
func NewSecret() (Secret, error) {
	var raw [randomBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return Secret{}, fmt.Errorf("tokens: secret: %w", err)
	}
	body := new(big.Int).SetBytes(raw[:]).Text(62)
	return Secret{raw: SecretMarker + strings.Repeat("0", bodyLength-len(body)) + body}, nil
}

// ParseSecret checks the token format. It does not look the token up.
// The error MUST NOT contain the value.
func ParseSecret(value string) (Secret, error) {
	body, ok := strings.CutPrefix(value, SecretMarker)
	if !ok || len(body) != bodyLength {
		return Secret{}, ErrInvalid
	}
	for i := range len(body) {
		if !strings.ContainsRune(base62Digits, rune(body[i])) {
			return Secret{}, ErrInvalid
		}
	}
	return Secret{raw: value}, nil
}

// MarshalText does not write the token.
func (Secret) MarshalText() ([]byte, error) {
	return []byte("redacted"), nil
}

// UnmarshalText parses text with ParseSecret.
func (s *Secret) UnmarshalText(text []byte) error {
	parsed, err := ParseSecret(string(text))
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// Hash returns the value to store.
func (s Secret) Hash() Hash {
	return Hash(sha256.Sum256([]byte(s.raw)))
}

// Matches reports whether s hashes to hash. The comparison is constant time.
func (s Secret) Matches(hash Hash) bool {
	sum := s.Hash()
	return subtle.ConstantTimeCompare(sum[:], hash[:]) == 1
}

// Prefix returns the part a person sees in a token list.
func (s Secret) Prefix() Prefix {
	return Prefix{value: s.raw[:prefixLength]}
}

// Reveal returns the clear token. The caller MUST NOT log it or store it.
func (s Secret) Reveal() string {
	return s.raw
}

// Prefix is the first characters of a token. It is not a secret.
type Prefix struct {
	value string
}

// ParsePrefix reads a stored prefix.
func ParsePrefix(value string) (Prefix, error) {
	if len(value) != prefixLength || !strings.HasPrefix(value, SecretMarker) {
		return Prefix{}, fmt.Errorf("tokens: prefix length %d", len(value))
	}
	return Prefix{value: value}, nil
}

func (p Prefix) String() string {
	return p.value
}

// MarshalText encodes the prefix.
func (p Prefix) MarshalText() ([]byte, error) {
	return []byte(p.value), nil
}

// UnmarshalText parses text with ParsePrefix.
func (p *Prefix) UnmarshalText(text []byte) error {
	parsed, err := ParsePrefix(string(text))
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}
