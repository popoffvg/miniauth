package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/oauth"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

// A revoke or a client delete that starts while a token issue is open MUST end the token the issue writes.
func TestOAuthRevokeWaitsForAnOpenTokenIssue(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))
	accounts := users.NewService(postgres.NewUserRepository(pool))
	repo, err := postgres.NewOAuthRepository(pool)
	require.NoError(t, err)
	tokenRepo := postgres.NewTokenRepository(pool)

	for _, tc := range []struct {
		name  string
		login string
		end   func(ctx context.Context, consent oauth.Consent) error
	}{
		{
			name:  "the user disconnects the app",
			login: "revoker",
			end: func(ctx context.Context, consent oauth.Consent) error {
				return repo.RevokeConsent(ctx, consent.UserID, consent.ID, time.Now())
			},
		},
		{
			name:  "an admin deletes the client",
			login: "deleter",
			end: func(ctx context.Context, consent oauth.Consent) error {
				return repo.DeleteClient(ctx, consent.ClientID)
			},
		},
	} {
		user := createAccount(t, accounts, tc.login)
		t.Run(tc.name, func(t *testing.T) {
			consent, refresh := storeConsentWithRefresh(ctx, t, repo, user)
			access, err := tokens.NewSecret()
			require.NoError(t, err)

			claimed := make(chan struct{})
			release := make(chan struct{})
			issued := make(chan error, 1)
			go func() {
				issued <- repo.InTransaction(ctx, func(tx oauth.Transaction) error {
					if _, _, claimErr := tx.ClaimRefresh(ctx, refresh, time.Now()); claimErr != nil {
						close(claimed)
						return claimErr
					}
					close(claimed)
					<-release
					return tx.CreateAccessToken(ctx, accessToken(t, consent, access), access.Hash(), consent.ID)
				})
			}()
			<-claimed

			ended := make(chan error, 1)
			go func() { ended <- tc.end(ctx, consent) }()
			select {
			case endErr := <-ended:
				t.Fatalf("the end of the consent did not wait for the open issue: %v", endErr)
			case <-time.After(300 * time.Millisecond):
			}
			close(release)
			require.NoError(t, <-issued)
			require.NoError(t, <-ended)

			_, _, err = tokenRepo.Find(ctx, access.Hash())
			assert.ErrorIs(t, err, tokens.ErrInvalid, "the token issued during the end MUST be gone")
		})
	}
}

func storeConsentWithRefresh(ctx context.Context, t *testing.T, repo *postgres.OAuthRepository, user users.User) (oauth.Consent, oauth.RefreshHash) {
	t.Helper()
	name, err := oauth.ParseClientName("Claude")
	require.NoError(t, err)
	redirect, err := oauth.ParseRedirectURI("http://localhost/callback")
	require.NoError(t, err)
	client := oauth.Client{ID: oauth.NewClientID(), Name: name, RedirectURIs: []oauth.RedirectURI{redirect}, CreatedAt: time.Now()}
	require.NoError(t, repo.CreateClient(ctx, client))
	resource, err := tokens.ParseScope("https://mcp.example.test/mcp")
	require.NoError(t, err)
	consent, err := repo.SaveConsent(ctx, oauth.Consent{
		ID: oauth.NewConsentID(), UserID: user.ID, ClientID: client.ID, Resource: resource, CreatedAt: time.Now(),
	})
	require.NoError(t, err)
	secret, err := oauth.NewRefreshSecret()
	require.NoError(t, err)
	require.NoError(t, repo.InTransaction(ctx, func(tx oauth.Transaction) error {
		return tx.CreateRefresh(ctx, oauth.RefreshToken{
			Hash: secret.Hash(), ConsentID: consent.ID, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		})
	}))
	return consent, secret.Hash()
}

func accessToken(t *testing.T, consent oauth.Consent, secret tokens.Secret) tokens.Token {
	t.Helper()
	name, err := tokens.ParseName("Claude")
	require.NoError(t, err)
	return tokens.Token{
		ID:        tokens.NewID(),
		UserID:    consent.UserID,
		Prefix:    secret.Prefix(),
		Name:      name,
		Scopes:    tokens.Scopes{consent.Resource},
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
		ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond),
	}
}
