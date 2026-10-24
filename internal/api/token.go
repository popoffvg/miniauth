package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/popoffvg/miniauth/internal/user"
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
type BearerToken struct {
	user.Redacted
	raw string
}

// requireAdmin rejects a missing or wrong bearer token.
// The token MUST NOT reach a log or an error.
func requireAdmin(admin AdminTokenHash, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok || !admin.Matches(token) {
			writeProblem(w, http.StatusUnauthorized, "The bearer token is missing or wrong.")
			return
		}
		next(w, r)
	}
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
