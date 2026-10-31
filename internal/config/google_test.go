package config

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadGoogleClient(t *testing.T) {
	const secret = "google-secret-must-stay-out-of-a-log"
	env := func(id, clientSecret, public string) func(string) string {
		return func(key string) string {
			switch key {
			case envDatabase:
				return "postgres://miniauth@127.0.0.1:5432/miniauth"
			case envAdmin:
				return adminHash(t, "bootstrap-token")
			case envPublic:
				return public
			case envGoogleID:
				return id
			case envGoogleSecret:
				return clientSecret
			default:
				return ""
			}
		}
	}

	cfg, err := Load(env("", "", ""))
	require.NoError(t, err)
	assert.False(t, cfg.Google.Enabled())

	cfg, err = Load(env("client.example.test", secret, "https://id.example.test"))
	require.NoError(t, err)
	assert.True(t, cfg.Google.Enabled())
	assert.Equal(t, "client.example.test", cfg.Google.ID.String())
	assert.NotContains(t, fmt.Sprintf("%v %#v %s", cfg, cfg.Google, cfg.Google.Secret), secret)
	var logs strings.Builder
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("config", "value", cfg, "google", cfg.Google)
	assert.NotContains(t, logs.String(), secret)

	for _, bad := range []func(string) string{
		env("client.example.test", "", "https://id.example.test"),
		env("", secret, "https://id.example.test"),
		env("client.example.test", secret, ""),
	} {
		_, err := Load(bad)
		require.ErrorIs(t, err, errGoogle)
		assert.NotContains(t, err.Error(), secret)
	}
}
