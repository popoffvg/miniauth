package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// AdminTokenHash is the SHA-256 of the bootstrap admin token.
// The token itself is not stored.
type AdminTokenHash struct {
	sum [sha256.Size]byte
}

// ParseAdminTokenHash reads 64 hex characters.
// hexEncoded MUST be the SHA-256 of the token, not the token.
func ParseAdminTokenHash(hexEncoded string) (AdminTokenHash, error) {
	raw := strings.TrimSpace(hexEncoded)
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != sha256.Size {
		return AdminTokenHash{}, errors.New("api: admin token hash must be 64 hex characters")
	}
	var sum [sha256.Size]byte
	copy(sum[:], decoded)
	return AdminTokenHash{sum: sum}, nil
}

// Matches reports whether token hashes to h.
// The comparison is constant time.
func (h AdminTokenHash) Matches(token BearerToken) bool {
	sum := sha256.Sum256([]byte(token.raw))
	return subtle.ConstantTimeCompare(sum[:], h.sum[:]) == 1
}

// BearerToken is the secret from an Authorization header.
// Printing it yields "redacted".
type BearerToken struct {
	raw string
}

// String returns "redacted".
func (t BearerToken) String() string {
	return "redacted"
}

// GoString returns "redacted".
func (t BearerToken) GoString() string {
	return "redacted"
}

// Format prints "redacted" for every verb, so a log cannot show the token.
func (t BearerToken) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "redacted")
}

// bearerToken reads Authorization: Bearer <token>.
// The token MUST NOT be written to a URL, a log, or an error.
func bearerToken(r *http.Request) (BearerToken, bool) {
	scheme, secret, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || scheme != "Bearer" || secret == "" || strings.Contains(secret, " ") {
		return BearerToken{}, false
	}
	return BearerToken{raw: secret}, true
}
