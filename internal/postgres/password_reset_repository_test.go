package postgres_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/recovery"
	"github.com/popoffvg/miniauth/internal/users"
)

// A reset that read its clock before the link expired MUST still fail once the database time is past the expiry.
func TestRedeemChecksTheExpiryWithTheDatabaseTime(t *testing.T) {
	ctx := t.Context()
	pool := migratedPool(t)
	ada := createAccount(t, users.NewService(postgres.NewUserRepository(pool)), "ada@example.test")
	repo := postgres.NewPasswordResetRepository(pool)
	token, err := recovery.NewToken()
	require.NoError(t, err)
	expiresAt := time.Now().Add(-time.Minute).UTC()
	require.NoError(t, repo.Create(ctx, recovery.Reset{Hash: token.Hash(), UserID: ada.ID, CreatedAt: expiresAt.Add(-recovery.LinkLifetime), ExpiresAt: expiresAt}))
	password, err := users.NewPassword("new-password-1")
	require.NoError(t, err)
	hash, err := users.HashPassword(password)
	require.NoError(t, err)

	_, err = repo.Redeem(ctx, token.Hash(), hash, expiresAt.Add(-time.Second))
	require.ErrorIs(t, err, recovery.ErrInvalidToken)
}
