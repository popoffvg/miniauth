package config

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/api"
)

func TestLoad(t *testing.T) {
	const password = "db-password-must-stay-out-of-the-error"
	hash := adminHash(t, "bootstrap-token")
	cfg, err := Load(func(key string) string {
		switch key {
		case envListen:
			return "127.0.0.1:9090"
		case envDatabase:
			return "postgres://miniauth:" + password + "@127.0.0.1:5432/miniauth?sslmode=disable"
		case envAdmin:
			return hash
		case envCookie:
			return ".example.test"
		case envPublic:
			return "https://id.example.test"
		default:
			return ""
		}
	})
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:9090", cfg.Listen.String())
	assert.Equal(t, ".example.test", cfg.Cookie.String())
	assert.Equal(t, "id.example.test", cfg.PublicURL.Host())
	want, err := api.ParseAdminTokenHash(hash)
	require.NoError(t, err)
	assert.Equal(t, want, cfg.AdminToken)
	assert.Contains(t, cfg.Database.DSN(), password)

	printed := []string{
		fmt.Sprint(cfg.Database),
		fmt.Sprintf("%#v", cfg.Database),
		fmt.Sprintf("%s", cfg.AdminToken),
		fmt.Sprintf("%#v", cfg),
	}
	for _, text := range printed {
		assert.NotContains(t, text, password)
		assert.NotContains(t, text, hash)
	}
	var logs strings.Builder
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("config", "value", cfg)
	assert.NotContains(t, logs.String(), password)
	assert.NotContains(t, logs.String(), hash)
	assert.Contains(t, logs.String(), "redacted")
	assert.Contains(t, logs.String(), "127.0.0.1:9090")
}

func TestLoadUsesTheDefaultListenAddress(t *testing.T) {
	cfg, err := Load(validEnv(""))
	require.NoError(t, err)
	assert.Equal(t, defaultListen, cfg.Listen.String())
	assert.Empty(t, cfg.Cookie.String())
	assert.Empty(t, cfg.PublicURL.Host())
}

func TestLoadReportsEveryInvalidValueWithoutTheValue(t *testing.T) {
	const password = "db-password-must-stay-out-of-the-error"
	const listen = "not-a-socket"
	const cookie = "idp_not_a_domain"
	const token = "not-a-hash"
	const public = "https://user:idp_not_a_token@id.example.test/"
	_, err := Load(func(key string) string {
		switch key {
		case envListen:
			return listen
		case envDatabase:
			return "postgres://miniauth:" + password + "@127.0.0.1:bad/miniauth"
		case envAdmin:
			return token
		case envCookie:
			return cookie
		case envPublic:
			return public
		default:
			return ""
		}
	})
	require.Error(t, err)
	text := err.Error()
	assert.Contains(t, text, "MINIAUTH_LISTEN")
	assert.Contains(t, text, "MINIAUTH_DATABASE_URL")
	assert.Contains(t, text, "MINIAUTH_ADMIN_TOKEN_SHA256")
	assert.Contains(t, text, "MINIAUTH_COOKIE_DOMAIN")
	assert.Contains(t, text, "MINIAUTH_PUBLIC_URL")
	assert.NotContains(t, text, password)
	assert.NotContains(t, text, listen)
	assert.NotContains(t, text, cookie)
	assert.NotContains(t, text, token)
	assert.NotContains(t, text, "idp_not_a_token")
}

func TestLoadRequiresTheDatabaseURL(t *testing.T) {
	_, err := Load(func(key string) string {
		if key == envAdmin {
			return adminHash(t, "bootstrap-token")
		}
		return ""
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MINIAUTH_DATABASE_URL is not set")
	assert.NotContains(t, err.Error(), "MINIAUTH_LISTEN")
}

func TestLoadRejectsANilEnvironment(t *testing.T) {
	_, err := Load(nil)
	require.Error(t, err)
}

func adminHash(t *testing.T, token string) string {
	t.Helper()
	return adminHashHex(token)
}

func adminHashHex(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func validEnv(listen string) func(string) string {
	hash := adminHashHex("bootstrap-token")
	return func(key string) string {
		switch key {
		case envListen:
			return listen
		case envDatabase:
			return "postgres://miniauth:miniauth@127.0.0.1:5432/miniauth?sslmode=disable"
		case envAdmin:
			return hash
		default:
			return ""
		}
	}
}

func TestLoadTOTPKey(t *testing.T) {
	cfg, err := Load(validEnv(""))
	require.NoError(t, err)
	assert.False(t, cfg.TOTPKey.Set(), "no MINIAUTH_TOTP_KEY means TOTP enrollment is off")

	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	cfg, err = Load(withEnv(validEnv(""), envTOTPKey, key))
	require.NoError(t, err)
	assert.True(t, cfg.TOTPKey.Set())
	var logs strings.Builder
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("config", "value", cfg)
	assert.NotContains(t, logs.String(), key)
	assert.NotContains(t, fmt.Sprintf("%#v", cfg), "0123456789abcdef")

	short := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	_, err = Load(withEnv(validEnv(""), envTOTPKey, short))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MINIAUTH_TOTP_KEY")
	assert.NotContains(t, err.Error(), short)
}

func withEnv(base func(string) string, name, value string) func(string) string {
	return func(key string) string {
		if key == name {
			return value
		}
		return base(key)
	}
}
