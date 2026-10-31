package totpstep

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/popoffvg/miniauth/internal/users"
)

const (
	// RecoveryCodeCount is how many recovery codes one enrollment makes.
	RecoveryCodeCount = 10
	// recoveryBytes is 80 random bits. A guess cannot find a code, so a fast hash is enough.
	recoveryBytes = 10
	recoveryChars = 16
	recoveryGroup = 4
)

var recoveryText = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// RecoveryHash is the SHA-256 of a recovery code. The database stores this, never the code.
type RecoveryHash [sha256.Size]byte

// RecoveryCode is one one-time code that replaces TOTP once. Printing it yields "redacted".
type RecoveryCode struct {
	users.Redacted
	raw string
}

// newRecoveryCodes returns RecoveryCodeCount random codes.
func newRecoveryCodes() ([]RecoveryCode, error) {
	codes := make([]RecoveryCode, RecoveryCodeCount)
	for i := range codes {
		var raw [recoveryBytes]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return nil, fmt.Errorf("totpstep: recovery code: %w", err)
		}
		codes[i] = RecoveryCode{raw: recoveryText.EncodeToString(raw[:])}
	}
	return codes, nil
}

// ParseRecoveryCode reads a code. Case, spaces, and dashes are ignored.
func ParseRecoveryCode(text string) (RecoveryCode, error) {
	raw := strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		return r
	}, strings.ToLower(strings.TrimSpace(text)))
	if len(raw) != recoveryChars {
		return RecoveryCode{}, ErrInvalidCode
	}
	if _, err := recoveryText.DecodeString(raw); err != nil {
		return RecoveryCode{}, ErrInvalidCode
	}
	return RecoveryCode{raw: raw}, nil
}

// Hash returns the value to store.
func (c RecoveryCode) Hash() RecoveryHash {
	return RecoveryHash(sha256.Sum256([]byte(c.raw)))
}

// Reveal returns the code in groups of 4, such as "abcd-efgh-ijkl-mnop".
// The caller MUST NOT log it or store it.
func (c RecoveryCode) Reveal() string {
	groups := make([]string, 0, recoveryChars/recoveryGroup)
	for i := 0; i < len(c.raw); i += recoveryGroup {
		groups = append(groups, c.raw[i:min(i+recoveryGroup, len(c.raw))])
	}
	return strings.Join(groups, "-")
}
