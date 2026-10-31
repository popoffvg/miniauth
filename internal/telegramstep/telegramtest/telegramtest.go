// Package telegramtest signs widget data the way Telegram does, for tests.
package telegramtest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// BotToken is the bot token of the tests. It is not a real token.
const BotToken = "123456789:test-bot-token-for-miniauth" // #nosec G101 -- a fake token for tests.

// BotName is the bot name of the tests.
const BotName = "miniauth_test_bot"

// Fields returns widget fields for the user id at authDate, with no hash.
func Fields(userID int64, authDate time.Time) url.Values {
	return url.Values{
		"id":         {strconv.FormatInt(userID, 10)},
		"first_name": {"Ada"},
		"username":   {"ada_test"},
		"auth_date":  {strconv.FormatInt(authDate.Unix(), 10)},
	}
}

// Sign returns a copy of fields with the hash for token.
func Sign(token string, fields url.Values) url.Values {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		if key != "hash" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	lines := make([]string, len(keys))
	for i, key := range keys {
		lines[i] = key + "=" + fields.Get(key)
	}
	secret := sha256.Sum256([]byte(token))
	mac := hmac.New(sha256.New, secret[:])
	mac.Write([]byte(strings.Join(lines, "\n")))
	signed := url.Values{}
	for key, values := range fields {
		signed[key] = append([]string(nil), values...)
	}
	signed.Set("hash", hex.EncodeToString(mac.Sum(nil)))
	return signed
}
