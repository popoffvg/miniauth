package oauth

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCodeRoundTrip(t *testing.T) {
	code, err := NewCode()
	require.NoError(t, err)
	text := code.Reveal()
	parsed, err := ParseCode(text)
	require.NoError(t, err)
	assert.Equal(t, code.Hash(), parsed.Hash())
	assert.NotContains(t, fmt.Sprintf("%v %+v %#v", code, code, code), text)
	for _, value := range []string{text[1:], text + "A", strings.Repeat("*", codeLength)} {
		_, err := ParseCode(value)
		assert.ErrorIs(t, err, ErrInvalidGrant, value)
	}
}

func TestRefreshSecretRoundTrip(t *testing.T) {
	secret, err := NewRefreshSecret()
	require.NoError(t, err)
	text := secret.Reveal()
	assert.True(t, strings.HasPrefix(text, RefreshMarker))
	parsed, err := ParseRefreshSecret(text)
	require.NoError(t, err)
	assert.Equal(t, secret.Hash(), parsed.Hash())
	assert.NotContains(t, fmt.Sprintf("%v %+v %#v", secret, secret, secret), text)
	for _, value := range []string{"idp_" + text[4:], text[:len(text)-1], RefreshMarker + strings.Repeat("*", refreshBodyLength)} {
		_, err := ParseRefreshSecret(value)
		assert.ErrorIs(t, err, ErrInvalidGrant, value)
	}
}

func TestParseStateRefusesControlAndLongValues(t *testing.T) {
	_, err := ParseState("")
	require.NoError(t, err)
	_, err = ParseState("abc-123_~")
	require.NoError(t, err)
	_, err = ParseState("a\nb")
	assert.ErrorIs(t, err, ErrState)
	_, err = ParseState(strings.Repeat("a", MaxStateBytes+1))
	assert.ErrorIs(t, err, ErrState)
}

func TestParseClientNameTrimsAndLimits(t *testing.T) {
	name, err := ParseClientName("  Claude  ")
	require.NoError(t, err)
	assert.Equal(t, "Claude", name.String())
	for _, raw := range []string{"", "   ", strings.Repeat("a", MaxClientNameRunes+1), "a\tb"} {
		_, err := ParseClientName(raw)
		assert.ErrorIs(t, err, ErrClientName, raw)
	}
}
