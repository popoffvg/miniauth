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

// requireAdmin allows the request only when the bearer token matches the bootstrap hash.
// The token MUST NOT reach a log or an error.
func (r *Router) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		token, ok := bearerToken(req)
		if !ok || !r.admin.Matches(token) {
			writeProblem(w, http.StatusUnauthorized, "The bearer token is missing or wrong.")
			return
		}
		next.ServeHTTP(w, req)
	})
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
