package telegramstep

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/popoffvg/miniauth/internal/users"
)

const (
	fieldHash     = "hash"
	fieldID       = "id"
	fieldAuthDate = "auth_date"
	// maxFields is more than the widget sends: id, first_name, last_name, username, photo_url, auth_date, hash.
	maxFields = 16
)

// AuthData is the query of the widget callback. It holds every field Telegram sent.
// An unknown field still takes part in the hash check.
type AuthData struct {
	fields   map[string]string
	hash     []byte
	subject  users.Subject
	authDate time.Time
}

// ParseAuthData reads the callback query. Each field MUST appear once, with a key of [a-z_]+ and a value with no "\n".
// `hash` MUST be the hex of 32 bytes, `id` a positive decimal integer, and `auth_date` positive Unix seconds.
// The error MUST NOT contain a value.
func ParseAuthData(query url.Values) (AuthData, error) {
	if len(query) == 0 || len(query) > maxFields {
		return AuthData{}, ErrBadData
	}
	fields := make(map[string]string, len(query))
	for key, values := range query {
		if !validKey(key) || len(values) != 1 || strings.Contains(values[0], "\n") {
			return AuthData{}, ErrBadData
		}
		fields[key] = values[0]
	}
	hash, err := hex.DecodeString(fields[fieldHash])
	if err != nil || len(hash) != sha256.Size {
		return AuthData{}, ErrBadData
	}
	subject, err := parseUserID(fields[fieldID])
	if err != nil {
		return AuthData{}, ErrBadData
	}
	seconds, err := strconv.ParseInt(fields[fieldAuthDate], 10, 64)
	if err != nil || seconds <= 0 {
		return AuthData{}, ErrBadData
	}
	return AuthData{fields: fields, hash: hash, subject: subject, authDate: time.Unix(seconds, 0).UTC()}, nil
}

// validKey reports whether key is [a-z_]+. A key with "=" or "\n", or a value with "\n",
// could move a field to another line of the check string and keep the hash.
func validKey(key string) bool {
	if key == "" {
		return false
	}
	for _, r := range key {
		if (r < 'a' || r > 'z') && r != '_' {
			return false
		}
	}
	return true
}

// parseUserID accepts only the canonical decimal form, so one account has one subject.
func parseUserID(raw string) (users.Subject, error) {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 || strconv.FormatInt(id, 10) != raw {
		return users.Subject{}, ErrBadData
	}
	return users.ParseSubject(raw)
}

// Account is the Telegram account of the data.
func (d AuthData) Account() users.ExternalAccount {
	return users.ExternalAccount{Kind: users.KindTelegram, Subject: d.subject}
}

// AuthDate is when Telegram signed the data.
func (d AuthData) AuthDate() time.Time {
	return d.authDate
}

// checkString is every field but `hash`, sorted by key, as key=value lines joined with "\n".
func (d AuthData) checkString() string {
	keys := make([]string, 0, len(d.fields))
	for key := range d.fields {
		if key != fieldHash {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	lines := make([]string, len(keys))
	for i, key := range keys {
		lines[i] = key + "=" + d.fields[key]
	}
	return strings.Join(lines, "\n")
}

// ProofHash is the SHA-256 of the id, the auth_date, and the hash of one widget login.
// The database stores it to refuse a second use of the same data.
type ProofHash [sha256.Size]byte

// proof returns the ProofHash of the data.
func (d AuthData) proof() ProofHash {
	return ProofHash(sha256.Sum256([]byte(d.fields[fieldID] + "\n" + d.fields[fieldAuthDate] + "\n" + hex.EncodeToString(d.hash))))
}
