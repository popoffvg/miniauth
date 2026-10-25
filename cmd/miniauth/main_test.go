package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRejectArgsDoesNotEchoTheArguments(t *testing.T) {
	const secret = "not-a-real-admin-token"
	err := rejectArgs([]string{"user", "create", "--login", "ada", secret})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secret)
	assert.NotContains(t, err.Error(), "ada")
	assert.NotContains(t, err.Error(), "create")
	require.NoError(t, rejectArgs(nil))
}
