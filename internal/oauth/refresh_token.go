package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/popoffvg/miniauth/internal/users"
)

const (
	// RefreshMarker starts every refresh token, so a scanner can find a leaked one.
	// It differs from the access token marker, so /auth/check never reads a refresh token.
	RefreshMarker = "idr_"
	// RefreshLifetime is how long a refresh token waits for its use. Each use gives a new one.
	RefreshLifetime = 30 * 24 * time.Hour
	// refreshBodyLength is the base64 raw URL length of 32 bytes.
	refreshBodyLength = 43
)

// RefreshHash is the SHA-256 of a refresh token. The database stores this, never the token.
type RefreshHash [sha256.Size]byte

// RefreshSecret is the clear refresh token. Printing it yields "redacted".
type RefreshSecret struct {
	users.Redacted
	raw string
}

// NewRefreshSecret returns "idr_" and 32 random bytes in base64url.
func NewRefreshSecret() (RefreshSecret, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return RefreshSecret{}, fmt.Errorf("oauth: refresh token: %w", err)
	}
	return RefreshSecret{raw: RefreshMarker + base64.RawURLEncoding.EncodeToString(raw[:])}, nil
}

// ParseRefreshSecret checks the format. A value that is not a refresh token is ErrInvalidGrant.
// The error MUST NOT contain the value.
func ParseRefreshSecret(value string) (RefreshSecret, error) {
	body, ok := strings.CutPrefix(value, RefreshMarker)
	if !ok || len(body) != refreshBodyLength {
		return RefreshSecret{}, ErrInvalidGrant
	}
	if _, err := base64.RawURLEncoding.Strict().DecodeString(body); err != nil {
		return RefreshSecret{}, ErrInvalidGrant
	}
	return RefreshSecret{raw: value}, nil
}

// Reveal returns the clear token for the token response. The caller MUST NOT log it or store it.
func (s RefreshSecret) Reveal() string {
	return s.raw
}

// Hash returns the value to store.
func (s RefreshSecret) Hash() RefreshHash {
	return RefreshHash(sha256.Sum256([]byte(s.raw)))
}

// RefreshToken is the stored side of a refresh token. A zero UsedAt was not rotated.
type RefreshToken struct {
	Hash      RefreshHash
	ConsentID ConsentID
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    time.Time
}
