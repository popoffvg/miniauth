package user

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// MaxPasswordBytes is the longest password the service accepts.
const MaxPasswordBytes = 1024

// OWASP argon2id baseline: 19 MiB, 2 iterations, 1 lane.
// The PHC string carries these values, so a later change can still verify old hashes.
const (
	argonMemoryKiB  = 19 * 1024
	argonIterations = 2
	argonLanes      = 1
	argonSaltLen    = 16
	argonKeyLen     = 32
)

// Caps stop a stored string from asking argon2 for unbounded work.
const (
	argonMaxMemoryKiB  = 256 * 1024
	argonMaxIterations = 8
	argonMaxLanes      = 4
	argonMaxSaltLen    = 64
)

// Password is the clear-text password.
type Password struct {
	Redacted
	raw string
}

// NewPassword returns a password. An empty password and a password over MaxPasswordBytes are refused.
func NewPassword(raw string) (Password, error) {
	if raw == "" {
		return Password{}, ErrEmptyPassword
	}
	if len(raw) > MaxPasswordBytes {
		return Password{}, ErrPasswordTooLong
	}
	return Password{raw: raw}, nil
}

// MarshalText does not write the password.
func (Password) MarshalText() ([]byte, error) {
	return []byte("redacted"), nil
}

// UnmarshalText parses text with NewPassword.
func (p *Password) UnmarshalText(text []byte) error {
	parsed, err := NewPassword(string(text))
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

// PasswordHash is a PHC argon2id string.
// The database stores Encoded. It never stores the password.
type PasswordHash struct {
	Redacted
	encoded string
}

// HashPassword returns an argon2id PHC string for password.
func HashPassword(password Password) (PasswordHash, error) {
	if password.raw == "" {
		return PasswordHash{}, ErrEmptyPassword
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return PasswordHash{}, fmt.Errorf("user: password hash: %w", err)
	}
	key := argon2.IDKey([]byte(password.raw), salt, argonIterations, argonMemoryKiB, argonLanes, argonKeyLen)
	encoded := encodePHC(argonMemoryKiB, argonIterations, argonLanes, salt, key)
	return PasswordHash{encoded: encoded}, nil
}

// ParsePasswordHash checks that encoded is an argon2id PHC string.
func ParsePasswordHash(encoded string) (PasswordHash, error) {
	if _, _, _, _, _, err := decodePHC(encoded); err != nil {
		return PasswordHash{}, err
	}
	return PasswordHash{encoded: encoded}, nil
}

// Encoded returns the PHC string. The caller MUST NOT log it.
func (h PasswordHash) Encoded() string {
	return h.encoded
}

// Matches reports whether password produces this hash. The comparison is constant time.
func (h PasswordHash) Matches(password Password) (bool, error) {
	memory, iterations, lanes, salt, want, err := decodePHC(h.encoded)
	if err != nil {
		return false, err
	}
	keyLen, err := argonKeyLength(len(want))
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password.raw), salt, iterations, memory, lanes, keyLen)
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// MarshalText does not write the PHC string.
func (PasswordHash) MarshalText() ([]byte, error) {
	return []byte("redacted"), nil
}

func encodePHC(memory, iterations uint32, lanes uint8, salt, key []byte) string {
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		memory,
		iterations,
		lanes,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

func decodePHC(encoded string) (memory, iterations uint32, lanes uint8, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return 0, 0, 0, nil, nil, errors.New("user: password hash: not argon2id")
	}
	version, err := strconv.Atoi(strings.TrimPrefix(parts[2], "v="))
	if err != nil || !strings.HasPrefix(parts[2], "v=") || version != argon2.Version {
		return 0, 0, 0, nil, nil, errors.New("user: password hash: bad version")
	}
	memory, iterations, lanes, err = parseArgonParams(parts[3])
	if err != nil {
		return 0, 0, 0, nil, nil, err
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 || len(salt) > argonMaxSaltLen {
		return 0, 0, 0, nil, nil, errors.New("user: password hash: bad salt")
	}
	key, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return 0, 0, 0, nil, nil, errors.New("user: password hash: bad key")
	}
	if _, err = argonKeyLength(len(key)); err != nil {
		return 0, 0, 0, nil, nil, err
	}
	return memory, iterations, lanes, salt, key, nil
}

// argonKeyLength accepts the tag sizes this service writes. 16 and 32 stay inside uint32.
func argonKeyLength(n int) (uint32, error) {
	switch n {
	case 16:
		return 16, nil
	case 32:
		return 32, nil
	default:
		return 0, errors.New("user: password hash: bad key")
	}
}

func parseArgonParams(raw string) (memory, iterations uint32, lanes uint8, err error) {
	var m, t, p uint64
	var seenM, seenT, seenP bool
	for _, field := range strings.Split(raw, ",") {
		name, value, ok := strings.Cut(field, "=")
		if !ok {
			return 0, 0, 0, errors.New("user: password hash: bad parameters")
		}
		n, parseErr := strconv.ParseUint(value, 10, 32)
		if parseErr != nil {
			return 0, 0, 0, errors.New("user: password hash: bad parameters")
		}
		switch name {
		case "m":
			m, seenM = n, true
		case "t":
			t, seenT = n, true
		case "p":
			p, seenP = n, true
		default:
			return 0, 0, 0, errors.New("user: password hash: bad parameters")
		}
	}
	if !seenM || !seenT || !seenP || m == 0 || m > argonMaxMemoryKiB || t == 0 || t > argonMaxIterations || p == 0 || p > argonMaxLanes {
		return 0, 0, 0, errors.New("user: password hash: bad parameters")
	}
	return uint32(m), uint32(t), uint8(p), nil
}
