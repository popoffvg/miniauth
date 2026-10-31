package totpstep

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 authenticator apps use HMAC-SHA-1. HMAC keeps it safe here.
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/popoffvg/miniauth/internal/users"
)

const (
	// Period is the length of one time step.
	Period = 30 * time.Second
	// Skew is how many steps before and after the current step a code still counts.
	Skew = 1
	// Issuer is the account issuer an authenticator app shows.
	Issuer     = "miniauth"
	secretSize = 20
	codeDigits = 6
)

// base32Text is the alphabet authenticator apps read: upper case, no padding.
var base32Text = base32.StdEncoding.WithPadding(base32.NoPadding)

// TimeStep is the RFC 6238 counter: whole Periods since the Unix epoch.
type TimeStep int64

// StepAt returns the time step of t.
func StepAt(t time.Time) TimeStep {
	return TimeStep(t.Unix() / int64(Period/time.Second))
}

// Secret is the shared TOTP key of one user. Printing it yields "redacted".
type Secret struct {
	users.Redacted
	raw [secretSize]byte
}

// NewSecret returns 20 random bytes.
func NewSecret() (Secret, error) {
	var s Secret
	if _, err := rand.Read(s.raw[:]); err != nil {
		return Secret{}, fmt.Errorf("totpstep: secret: %w", err)
	}
	return s, nil
}

// Reveal returns the base32 text a person types into an authenticator app.
// The caller MUST NOT log it or store it.
func (s Secret) Reveal() string {
	return base32Text.EncodeToString(s.raw[:])
}

// KeyURI returns the otpauth URI that a QR code carries.
func (s Secret) KeyURI(account users.Login) KeyURI {
	query := url.Values{
		"secret":    {s.Reveal()},
		"issuer":    {Issuer},
		"algorithm": {"SHA1"},
		"digits":    {strconv.Itoa(codeDigits)},
		"period":    {strconv.Itoa(int(Period / time.Second))},
	}
	label := url.PathEscape(Issuer + ":" + account.String())
	return KeyURI{raw: "otpauth://totp/" + label + "?" + query.Encode()}
}

// codeAt is the RFC 4226 HOTP value of step.
func (s Secret) codeAt(step TimeStep) Code {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step)) // #nosec G115 -- A time step after 1970 is not negative.
	mac := hmac.New(sha1.New, s.raw[:])
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return Code{digits: fmt.Sprintf("%0*d", codeDigits, value%1_000_000)}
}

// Match returns the step of code when it matches a step within Skew of now that is later than after.
// Every candidate step is compared, in constant time, so the time does not show which step matched.
func (s Secret) Match(code Code, now time.Time, after TimeStep) (TimeStep, bool) {
	current := StepAt(now)
	var found TimeStep
	for step := current - Skew; step <= current+Skew; step++ {
		equal := subtle.ConstantTimeCompare([]byte(s.codeAt(step).digits), []byte(code.digits)) == 1
		if equal && step > after && found == 0 {
			found = step
		}
	}
	return found, found != 0
}

// KeyURI is the otpauth URI of a secret. Printing it yields "redacted".
type KeyURI struct {
	users.Redacted
	raw string
}

// Reveal returns the URI. The caller MUST NOT log it, store it, or put it in a link.
func (u KeyURI) Reveal() string {
	return u.raw
}

// Code is one 6-digit TOTP code. Printing it yields "redacted".
type Code struct {
	users.Redacted
	digits string
}

// ParseCode reads 6 digits. Spaces are ignored.
func ParseCode(raw string) (Code, error) {
	digits := strings.Join(strings.Fields(raw), "")
	if len(digits) != codeDigits {
		return Code{}, ErrInvalidCode
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return Code{}, ErrInvalidCode
		}
	}
	return Code{digits: digits}, nil
}
