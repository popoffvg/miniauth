package invites

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenRoundTrip(t *testing.T) {
	token, err := NewToken()
	require.NoError(t, err)
	text := token.Reveal()
	require.Len(t, text, tokenLength)
	parsed, err := ParseToken(text)
	require.NoError(t, err)
	assert.Equal(t, token.Hash(), parsed.Hash())
	assert.Equal(t, "redacted", fmt.Sprint(token))
	assert.NotContains(t, fmt.Sprintf("%+v %#v", token, token), text)
}

func TestParseTokenRefusesOtherText(t *testing.T) {
	token, err := NewToken()
	require.NoError(t, err)
	text := token.Reveal()
	for _, value := range []string{"", text[1:], text + "A", strings.Repeat("*", tokenLength), strings.Repeat("A", tokenLength-1) + "B"} {
		_, err := ParseToken(value)
		assert.ErrorIs(t, err, ErrInviteGone, value)
	}
}
