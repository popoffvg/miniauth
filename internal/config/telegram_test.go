package config

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadTelegramBot(t *testing.T) {
	const token = "123456:telegram-token-must-stay-out-of-a-log" // #nosec G101 -- a fake token for tests.
	env := func(name, botToken, public string) func(string) string {
		return func(key string) string {
			switch key {
			case envDatabase:
				return "postgres://miniauth@127.0.0.1:5432/miniauth"
			case envAdmin:
				return adminHash(t, "bootstrap-token")
			case envPublic:
				return public
			case envTelegramBot:
				return name
			case envTelegramToken:
				return botToken
			default:
				return ""
			}
		}
	}

	cfg, err := Load(env("", "", ""))
	require.NoError(t, err)
	assert.False(t, cfg.Telegram.Enabled())

	cfg, err = Load(env("miniauth_bot", token, "https://id.example.test"))
	require.NoError(t, err)
	assert.True(t, cfg.Telegram.Enabled())
	assert.Equal(t, "miniauth_bot", cfg.Telegram.Name.String())
	assert.NotContains(t, fmt.Sprintf("%v %+v %#v", cfg, cfg.Telegram, cfg.Telegram), token)
	var logs strings.Builder
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("config", "value", cfg, "telegram", cfg.Telegram)
	assert.NotContains(t, logs.String(), token)

	for _, bad := range []func(string) string{
		env("miniauth_bot", "", "https://id.example.test"),
		env("", token, "https://id.example.test"),
		env("miniauth_bot", token, ""),
		env("bad bot", token, "https://id.example.test"),
	} {
		_, err := Load(bad)
		require.ErrorIs(t, err, errTelegram)
		assert.NotContains(t, err.Error(), token)
	}
}
