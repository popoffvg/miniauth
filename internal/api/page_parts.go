package api

import (
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/popoffvg/miniauth/internal/users"
)

// badgeTone is the colour of a status badge. It is the suffix of a CSS class in app.css.
type badgeTone string

const (
	toneActive   badgeTone = "active"
	toneRevoked  badgeTone = "revoked"
	toneExpired  badgeTone = "expired"
	toneDisabled badgeTone = "disabled"
	toneAdmin    badgeTone = "admin"
	toneOn       badgeTone = "on"
	toneOff      badgeTone = "off"
	toneCurrent  badgeTone = "current"
	toneNeutral  badgeTone = "neutral"
	// toneConfig marks a row from the resources file.
	toneConfig badgeTone = "config"
)

// filterChip is one status filter above a table. An empty Value is the chip that shows every row.
type filterChip struct {
	Value string
	Label string
}

func (c filterChip) href(path, query string) string {
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

// timeText is a time a page shows in UTC. The zero time is "Never".
type timeText time.Time

const pageTimeLayout = "2006-01-02 15:04 UTC"

func (t timeText) Zero() bool {
	return time.Time(t).IsZero()
}

func (t timeText) Human() string {
	return time.Time(t).UTC().Format(pageTimeLayout)
}

func (t timeText) Machine() string {
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

// matchesQuery reports whether one of fields contains query, ignoring case. An empty query matches.
func matchesQuery(query string, fields ...string) bool {
	if query == "" {
		return true
	}
	query = strings.ToLower(query)
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), query) {
			return true
		}
	}
	return false
}

// countText is "1 grant" or "3 grants".
func countText(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

func (t timeText) Date() string {
	return time.Time(t).UTC().Format(time.DateOnly)
}

func (t timeText) Clock() string {
	return time.Time(t).UTC().Format("15:04 UTC")
}
