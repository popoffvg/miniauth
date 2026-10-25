package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionDomainDoesNotEchoTheValue(t *testing.T) {
	const secret = "idp_not_a_domain"
	t.Setenv("MINIAUTH_COOKIE_DOMAIN", secret)
	_, err := sessionDomain()
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secret)
	assert.Contains(t, err.Error(), "MINIAUTH_COOKIE_DOMAIN")

	t.Setenv("MINIAUTH_COOKIE_DOMAIN", "")
	domain, err := sessionDomain()
	require.NoError(t, err)
	assert.Empty(t, domain.String())
}

func TestPublicURLDoesNotEchoTheValue(t *testing.T) {
	const secret = "https://user:idp_not_a_token@id.example.test/"
	t.Setenv("MINIAUTH_PUBLIC_URL", secret)
	_, err := publicURL()
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secret)
	assert.NotContains(t, err.Error(), "idp_not_a_token")
	assert.Contains(t, err.Error(), "MINIAUTH_PUBLIC_URL")

	t.Setenv("MINIAUTH_PUBLIC_URL", "")
	parsed, err := publicURL()
	require.NoError(t, err)
	assert.Empty(t, parsed.Host())
}

func TestRejectArgsDoesNotEchoTheArguments(t *testing.T) {
	const secret = "not-a-real-admin-token"
	err := rejectArgs([]string{"user", "create", "--login", "ada", secret})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secret)
	assert.NotContains(t, err.Error(), "ada")
	assert.NotContains(t, err.Error(), "create")
	require.NoError(t, rejectArgs(nil))
}
