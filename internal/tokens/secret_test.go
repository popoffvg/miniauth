package tokens

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSecretFormat(t *testing.T) {
	seen := map[string]struct{}{}
	for range 64 {
		secret, err := NewSecret()
		require.NoError(t, err)
		value := secret.Reveal()
		require.True(t, strings.HasPrefix(value, SecretMarker))
		require.Len(t, value, len(SecretMarker)+bodyLength)
		parsed, err := ParseSecret(value)
		require.NoError(t, err)
		assert.Equal(t, secret.Hash(), parsed.Hash())
		assert.Equal(t, value[:8], secret.Prefix().String())
		_, dup := seen[value]
		require.False(t, dup)
		seen[value] = struct{}{}
	}
}

func TestParseSecretRefusesAnotherFormat(t *testing.T) {
	body := strings.Repeat("a", bodyLength)
	for _, raw := range []string{"", "idp_", "idp_" + body[1:], "idp_" + body + "a", "xyz_" + body, "idp_" + body[1:] + "-"} {
		_, err := ParseSecret(raw)
		require.ErrorIs(t, err, ErrInvalid)
	}
}

func TestSecretIsRedacted(t *testing.T) {
	secret, err := NewSecret()
	require.NoError(t, err)
	for _, out := range []string{fmt.Sprint(secret), fmt.Sprintf("%v %+v %#v %s", secret, secret, secret, secret)} {
		assert.NotContains(t, out, secret.Reveal())
	}
}

func TestSecretMatches(t *testing.T) {
	a, err := NewSecret()
	require.NoError(t, err)
	b, err := NewSecret()
	require.NoError(t, err)
	assert.True(t, a.Matches(a.Hash()))
	assert.False(t, a.Matches(b.Hash()))
}

func TestParseName(t *testing.T) {
	name, err := ParseName("  laptop ci  ")
	require.NoError(t, err)
	assert.Equal(t, "laptop ci", name.String())
	for _, raw := range []string{"", "   ", strings.Repeat("a", MaxNameLengthRunes+1), "a\nb", "a\x00b", "\xff"} {
		_, err := ParseName(raw)
		require.ErrorIs(t, err, ErrName)
	}
}
