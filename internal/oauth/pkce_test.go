package oauth

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// openssl computed the challenge: printf %s verifier | openssl dgst -sha256 -binary | base64url.
const (
	knownVerifier  = "dBjftJeZ4CVP-mJ92K9CD8VPazHKtbP3rPN0vjLsYSs"
	knownChallenge = "7DeuWCVh4E1cL2MTRm5cteqyHOwsm5KmlKW7Mk-IdeI"
)

func TestChallengeVerifiesItsVerifier(t *testing.T) {
	verifier, err := ParseVerifier(knownVerifier)
	require.NoError(t, err)
	challenge, err := ParseChallenge(knownChallenge, ChallengeMethodS256)
	require.NoError(t, err)
	assert.True(t, challenge.Verifies(verifier))

	other, err := ParseVerifier(strings.Repeat("b", 43))
	require.NoError(t, err)
	assert.False(t, challenge.Verifies(other))
	assert.False(t, Challenge{}.Verifies(verifier))
	assert.Equal(t, "redacted", fmt.Sprint(verifier))
}

func TestParseChallengeRefusesPlainAndMalformed(t *testing.T) {
	for _, tc := range []struct{ raw, method string }{
		{knownChallenge, "plain"},
		{knownChallenge[1:], ChallengeMethodS256},
		{strings.Repeat("*", 43), ChallengeMethodS256},
	} {
		_, err := ParseChallenge(tc.raw, tc.method)
		assert.ErrorIs(t, err, ErrChallenge, tc)
	}
}

func TestParseVerifierChecksLengthAndAlphabet(t *testing.T) {
	for _, raw := range []string{strings.Repeat("a", 42), strings.Repeat("a", 129), strings.Repeat("a", 42) + "+"} {
		_, err := ParseVerifier(raw)
		assert.ErrorIs(t, err, ErrInvalidGrant, raw)
	}
	for _, raw := range []string{strings.Repeat("a", 43), strings.Repeat("Z", 128), strings.Repeat("-._~", 11)} {
		_, err := ParseVerifier(raw)
		assert.NoError(t, err, raw)
	}
}
