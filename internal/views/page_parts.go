package views

import (
	"net/url"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/popoffvg/miniauth/internal/users"
)

// Tone is the colour of a status badge. It is the suffix of a CSS class in app.css.
type Tone string

// The badge tones. Each one is a badge-<tone> class in app.css.
const (
	ToneActive   Tone = "active"
	ToneRevoked  Tone = "revoked"
	ToneExpired  Tone = "expired"
	ToneDisabled Tone = "disabled"
	ToneAdmin    Tone = "admin"
	ToneOn       Tone = "on"
	ToneOff      Tone = "off"
	ToneCurrent  Tone = "current"
	ToneNeutral  Tone = "neutral"
	// ToneConfig marks a row from the resources file.
	ToneConfig Tone = "config"
)

// FilterChip is one status filter above a table. An empty Value is the chip that shows every row.
type FilterChip struct {
	Value string
	Label string
}

func (c FilterChip) href(path, query string) string {
	values := url.Values{}
	if query != "" {
		values.Set("q", query)
	}
	if c.Value != "" {
		values.Set("status", c.Value)
	}
	if len(values) == 0 {
		return path
	}
	return path + "?" + values.Encode()
}

// Timestamp is a time a page shows in UTC. The zero time is "Never".
type Timestamp time.Time

const pageTimeLayout = "2006-01-02 15:04 UTC"

func (t Timestamp) zero() bool {
	return time.Time(t).IsZero()
}

func (t Timestamp) human() string {
	return time.Time(t).UTC().Format(pageTimeLayout)
}

func (t Timestamp) machine() string {
	return time.Time(t).UTC().Format(time.RFC3339)
}

// initial is the first letter of login for the avatar.
func initial(login users.Login) string {
	first, _ := utf8.DecodeRuneInString(login.String())
	if first == utf8.RuneError {
		return "?"
	}
	return string(unicode.ToUpper(first))
}

// countText is "1 grant" or "3 grants".
func countText(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

func (t Timestamp) date() string {
	return time.Time(t).UTC().Format(time.DateOnly)
}

func (t Timestamp) clock() string {
	return time.Time(t).UTC().Format("15:04 UTC")
}
