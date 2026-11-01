package telegram

import (
	"strings"

	"github.com/popoffvg/miniauth/internal/loginflow"

	"github.com/popoffvg/miniauth/internal/users"
)

// BotName is the username of the bot that the widget shows. It is not a secret.
type BotName struct {
	value string
}

// ParseBotName trims raw and accepts 5 to 32 letters, digits, and underscores.
// An empty value is the zero BotName.
func ParseBotName(raw string) (BotName, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return BotName{}, nil
	}
	if len(raw) < 5 || len(raw) > 32 {
		return BotName{}, ErrConfig
	}
	for _, r := range raw {
		if !botNameRune(r) {
			return BotName{}, ErrConfig
		}
	}
	return BotName{value: raw}, nil
}

func botNameRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_'
}

func (b BotName) String() string {
	return b.value
}

// BotToken is the token of the bot. Its SHA-256 is the key of the widget hash.
// Printing it yields "redacted".
type BotToken struct {
	users.Redacted
	value string
}

// ParseBotToken trims raw. An empty value is the zero BotToken.
func ParseBotToken(raw string) BotToken {
	return BotToken{value: strings.TrimSpace(raw)}
}

// Empty reports whether no token is set.
func (t BotToken) Empty() bool {
	return t.value == ""
}

// Config is the bot that the step checks the widget data for.
// SecondFactors tells which linked users need a second step. Nil means none.
type Config struct {
	BotName       BotName
	BotToken      BotToken
	SecondFactors loginflow.SecondFactors
}
