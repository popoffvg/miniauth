package user

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordPrintsRedacted(t *testing.T) {
	t.Logf("gofakeit seed %d", uint64(7))
	raw := gofakeit.New(7).Password(true, true, true, false, false, 16)
	password, err := NewPassword(raw)
	require.NoError(t, err)
	printed := []string{
		fmt.Sprint(password),
		fmt.Sprintf("%v", password),
		fmt.Sprintf("%s", password),
		fmt.Sprintf("%#v", password),
		fmt.Sprintf("%x", password),
		password.String(),
		password.GoString(),
	}
	for _, text := range printed {
		assert.Equal(t, "redacted", text)
		assert.NotContains(t, text, raw)
	}
	var logs strings.Builder
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("password", "value", password)
	assert.NotContains(t, logs.String(), raw)
	assert.Contains(t, logs.String(), "redacted")
}

func TestHashPasswordMatchesAndHidesThePassword(t *testing.T) {
	t.Logf("gofakeit seed %d", uint64(11))
	raw := gofakeit.New(11).Password(true, true, true, true, false, 24)
	password, err := NewPassword(raw)
	require.NoError(t, err)
	first, err := HashPassword(password)
	require.NoError(t, err)
	second, err := HashPassword(password)
	require.NoError(t, err)
	assert.NotEqual(t, first.Encoded(), second.Encoded())
	assert.NotContains(t, first.Encoded(), raw)
	assert.Equal(t, "redacted", first.String())
	assert.Equal(t, "redacted", fmt.Sprintf("%#v", first))
	ok, err := first.Matches(password)
	require.NoError(t, err)
	assert.True(t, ok)
	other, err := NewPassword(raw + "x")
	require.NoError(t, err)
	ok, err = first.Matches(other)
	require.NoError(t, err)
	assert.False(t, ok)
	parsed, err := ParsePasswordHash(first.Encoded())
	require.NoError(t, err)
	ok, err = parsed.Matches(password)
	require.NoError(t, err)
	assert.True(t, ok)
	var logs strings.Builder
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("hash", "value", first)
	assert.NotContains(t, logs.String(), raw)
	assert.NotContains(t, logs.String(), first.Encoded())
	assert.Contains(t, logs.String(), "redacted")
}

func TestParseLogin(t *testing.T) {
	login, err := ParseLogin("  Ada ")
	require.NoError(t, err)
	assert.Equal(t, "ada", login.String())
	_, err = ParseLogin(".")
	assert.ErrorIs(t, err, ErrInvalidLogin)
	_, err = NewPassword("")
	assert.ErrorIs(t, err, ErrEmptyPassword)
}
