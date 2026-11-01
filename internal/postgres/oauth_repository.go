package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/popoffvg/miniauth/internal/oauth"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

// OAuthRepository is the PostgreSQL adapter for OAuth clients, consents, codes, and refresh tokens.
type OAuthRepository struct {
	db transactionalDB
	q  *sqlcgen.Queries
}

// NewOAuthRepository refuses a nil database before any query runs.
func NewOAuthRepository(db transactionalDB) (*OAuthRepository, error) {
	if db == nil {
		return nil, errors.New("postgres: oauth repository database is missing")
	}
	return &OAuthRepository{db: db, q: sqlcgen.New(db)}, nil
}

var _ oauth.Store = (*OAuthRepository)(nil)

// CreateClient stores the redirect URIs as the admin wrote them.
func (r *OAuthRepository) CreateClient(ctx context.Context, client oauth.Client) error {
	uris := make([]string, 0, len(client.RedirectURIs))
	for _, uri := range client.RedirectURIs {
		uris = append(uris, uri.String())
	}
	err := r.q.InsertOAuthClient(ctx, sqlcgen.InsertOAuthClientParams{
		ID:           pgUUIDBytes(client.ID.Bytes()),
		Name:         client.Name.String(),
		RedirectUris: uris,
		CreatedAt:    pgTime(client.CreatedAt),
	})
	if err != nil {
		return oauthError("create oauth client", err)
	}
	return nil
}

// FindClient returns oauth.ErrClientNotFound for an id that is not stored.
func (r *OAuthRepository) FindClient(ctx context.Context, id oauth.ClientID) (oauth.Client, error) {
	row, err := r.q.GetOAuthClient(ctx, pgUUIDBytes(id.Bytes()))
	if errors.Is(err, pgx.ErrNoRows) {
		return oauth.Client{}, oauth.ErrClientNotFound
	}
	if err != nil {
		return oauth.Client{}, oauthError("find oauth client", err)
	}
	return clientFromRow(row)
}

// ListClients returns every client, oldest first.
func (r *OAuthRepository) ListClients(ctx context.Context) ([]oauth.Client, error) {
	rows, err := r.q.ListOAuthClients(ctx)
	if err != nil {
		return nil, oauthError("list oauth clients", err)
	}
	out := make([]oauth.Client, 0, len(rows))
	for _, row := range rows {
		client, err := clientFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, client)
	}
	return out, nil
}

// DeleteClient locks the consents of the client first, so no token issue under them is in flight.
// It deletes their access tokens next: the cascade removes only the links.
func (r *OAuthRepository) DeleteClient(ctx context.Context, id oauth.ClientID) error {
	err := pgx.BeginFunc(ctx, r.db, func(tx pgx.Tx) error {
		q := sqlcgen.New(tx)
		if err := q.LockOAuthClient(ctx, pgUUIDBytes(id.Bytes())); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return oauth.ErrClientNotFound
			}
			return oauthError("lock oauth client", err)
		}
		if err := q.LockOAuthClientConsents(ctx, pgUUIDBytes(id.Bytes())); err != nil {
			return oauthError("lock oauth client consents", err)
		}
		if err := q.DeleteOAuthClientAccessTokens(ctx, pgUUIDBytes(id.Bytes())); err != nil {
			return oauthError("delete oauth client tokens", err)
		}
		n, err := q.DeleteOAuthClient(ctx, pgUUIDBytes(id.Bytes()))
		if err != nil {
			return oauthError("delete oauth client", err)
		}
		if n == 0 {
			return oauth.ErrClientNotFound
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("postgres: delete oauth client: %w", err)
	}
	return nil
}

// SaveConsent inserts the consent, or returns the active one for the same user, client, and resource.
func (r *OAuthRepository) SaveConsent(ctx context.Context, consent oauth.Consent) (oauth.Consent, error) {
	row, err := r.q.SaveOAuthConsent(ctx, sqlcgen.SaveOAuthConsentParams{
		ID:        pgUUIDBytes(consent.ID.Bytes()),
		UserID:    pgUUIDBytes(consent.UserID.Bytes()),
		ClientID:  pgUUIDBytes(consent.ClientID.Bytes()),
		Resource:  consent.Resource.String(),
		CreatedAt: pgTime(consent.CreatedAt),
	})
	if err != nil {
		return oauth.Consent{}, oauthError("save oauth consent", err)
	}
	return consentFromRow(row)
}

// ListConsents returns the active consents of the user, oldest first.
func (r *OAuthRepository) ListConsents(ctx context.Context, userID users.ID) ([]oauth.ConsentEntry, error) {
	rows, err := r.q.ListActiveOAuthConsents(ctx, pgUUIDBytes(userID.Bytes()))
	if err != nil {
		return nil, oauthError("list oauth consents", err)
	}
	out := make([]oauth.ConsentEntry, 0, len(rows))
	for _, row := range rows {
		consent, err := consentFromRow(sqlcgen.OauthConsent{
			ID:        row.ID,
			UserID:    row.UserID,
			ClientID:  row.ClientID,
			Resource:  row.Resource,
			CreatedAt: row.CreatedAt,
			RevokedAt: row.RevokedAt,
		})
		if err != nil {
			return nil, err
		}
		name, err := oauth.ParseClientName(row.ClientName)
		if err != nil {
			return nil, fmt.Errorf("postgres: oauth consent row: %w", err)
		}
		out = append(out, oauth.ConsentEntry{Consent: consent, ClientName: name})
	}
	return out, nil
}

// RevokeConsent returns oauth.ErrConsentNotFound when the user has no active consent with the id.
func (r *OAuthRepository) RevokeConsent(ctx context.Context, userID users.ID, id oauth.ConsentID, at time.Time) error {
	err := pgx.BeginFunc(ctx, r.db, func(tx pgx.Tx) error {
		q := sqlcgen.New(tx)
		n, err := q.RevokeUserOAuthConsent(ctx, sqlcgen.RevokeUserOAuthConsentParams{
			RevokedAt: pgTime(at),
			ID:        pgUUIDBytes(id.Bytes()),
			UserID:    pgUUIDBytes(userID.Bytes()),
		})
		if err != nil {
			return oauthError("revoke oauth consent", err)
		}
		if n == 0 {
			return oauth.ErrConsentNotFound
		}
		return deleteConsentTokens(ctx, q, id)
	})
	if err != nil {
		return fmt.Errorf("postgres: revoke oauth consent: %w", err)
	}
	return nil
}

// EndConsent keeps the first revoked_at of a consent revoked before.
func (r *OAuthRepository) EndConsent(ctx context.Context, id oauth.ConsentID, at time.Time) error {
	err := pgx.BeginFunc(ctx, r.db, func(tx pgx.Tx) error {
		q := sqlcgen.New(tx)
		err := q.EndOAuthConsent(ctx, sqlcgen.EndOAuthConsentParams{RevokedAt: pgTime(at), ID: pgUUIDBytes(id.Bytes())})
		if err != nil {
			return oauthError("end oauth consent", err)
		}
		return deleteConsentTokens(ctx, q, id)
	})
	if err != nil {
		return fmt.Errorf("postgres: end oauth consent: %w", err)
	}
	return nil
}

// CreateCode stores the hash, never the code.
func (r *OAuthRepository) CreateCode(ctx context.Context, code oauth.AuthorizationCode) error {
	err := r.q.InsertOAuthCode(ctx, sqlcgen.InsertOAuthCodeParams{
		CodeHash:    code.Hash[:],
		ConsentID:   pgUUIDBytes(code.ConsentID.Bytes()),
		RedirectUri: code.RedirectURI.String(),
		Challenge:   code.Challenge.String(),
		CreatedAt:   pgTime(code.CreatedAt),
		ExpiresAt:   pgTime(code.ExpiresAt),
	})
	if err != nil {
		return oauthError("create oauth code", err)
	}
	return nil
}

// InTransaction rolls back the claim on any error, so a refused exchange leaves the code or refresh token unspent.
func (r *OAuthRepository) InTransaction(ctx context.Context, fn func(oauth.Transaction) error) error {
	err := pgx.BeginFunc(ctx, r.db, func(tx pgx.Tx) error {
		return fn(&oauthTransaction{q: sqlcgen.New(tx), tokenRepo: NewTokenRepository(tx)})
	})
	if err != nil {
		return fmt.Errorf("postgres: oauth token request: %w", err)
	}
	return nil
}

type oauthTransaction struct {
	q         *sqlcgen.Queries
	tokenRepo *TokenRepository
}

// ClaimCode is one conditional UPDATE. A parallel claim waits for the row lock and then sees used_at set.
func (t *oauthTransaction) ClaimCode(ctx context.Context, hash oauth.CodeHash, at time.Time) (oauth.AuthorizationCode, oauth.Consent, error) {
	peek, err := t.q.GetOAuthCode(ctx, hash[:])
	if errors.Is(err, pgx.ErrNoRows) {
		return oauth.AuthorizationCode{}, oauth.Consent{}, oauth.ErrInvalidGrant
	}
	if err != nil {
		return oauth.AuthorizationCode{}, oauth.Consent{}, oauthError("get oauth code", err)
	}
	if !peek.ConsentID.Valid {
		return oauth.AuthorizationCode{}, oauth.Consent{}, errors.New("postgres: code consent_id is null")
	}
	consentID := oauth.ConsentIDFromBytes(peek.ConsentID.Bytes)
	consent, err := t.consent(ctx, consentID)
	if err != nil {
		return oauth.AuthorizationCode{}, oauth.Consent{}, err
	}
	row, err := t.q.ClaimOAuthCode(ctx, sqlcgen.ClaimOAuthCodeParams{UsedAt: pgTime(at), CodeHash: hash[:]})
	if errors.Is(err, pgx.ErrNoRows) {
		code, parseErr := codeFromRow(peek)
		if parseErr != nil {
			return oauth.AuthorizationCode{}, oauth.Consent{}, parseErr
		}
		return code, consent, oauth.ErrCodeReused
	}
	if err != nil {
		return oauth.AuthorizationCode{}, oauth.Consent{}, oauthError("claim oauth code", err)
	}
	code, err := codeFromRow(row)
	if err != nil {
		return oauth.AuthorizationCode{}, oauth.Consent{}, err
	}
	return code, consent, nil
}

// ClaimRefresh is one conditional UPDATE, like ClaimCode.
func (t *oauthTransaction) ClaimRefresh(ctx context.Context, hash oauth.RefreshHash, at time.Time) (oauth.RefreshToken, oauth.Consent, error) {
	peek, err := t.q.GetOAuthRefreshToken(ctx, hash[:])
	if errors.Is(err, pgx.ErrNoRows) {
		return oauth.RefreshToken{}, oauth.Consent{}, oauth.ErrInvalidGrant
	}
	if err != nil {
		return oauth.RefreshToken{}, oauth.Consent{}, oauthError("get oauth refresh token", err)
	}
	if !peek.ConsentID.Valid {
		return oauth.RefreshToken{}, oauth.Consent{}, errors.New("postgres: refresh token consent_id is null")
	}
	consentID := oauth.ConsentIDFromBytes(peek.ConsentID.Bytes)
	consent, err := t.consent(ctx, consentID)
	if err != nil {
		return oauth.RefreshToken{}, oauth.Consent{}, err
	}
	row, err := t.q.ClaimOAuthRefreshToken(ctx, sqlcgen.ClaimOAuthRefreshTokenParams{UsedAt: pgTime(at), SecretHash: hash[:]})
	if errors.Is(err, pgx.ErrNoRows) {
		refresh, parseErr := refreshFromRow(peek)
		if parseErr != nil {
			return oauth.RefreshToken{}, oauth.Consent{}, parseErr
		}
		return refresh, consent, oauth.ErrRefreshReused
	}
	if err != nil {
		return oauth.RefreshToken{}, oauth.Consent{}, oauthError("claim oauth refresh token", err)
	}
	refresh, err := refreshFromRow(row)
	if err != nil {
		return oauth.RefreshToken{}, oauth.Consent{}, err
	}
	return refresh, consent, nil
}

// CreateAccessToken stores the token in access_tokens and links it to the consent.
func (t *oauthTransaction) CreateAccessToken(ctx context.Context, token tokens.Token, hash tokens.Hash, consent oauth.ConsentID) error {
	if err := t.tokenRepo.Create(ctx, token, hash); err != nil {
		return err
	}
	err := t.q.InsertOAuthAccessToken(ctx, sqlcgen.InsertOAuthAccessTokenParams{
		TokenID:   pgUUIDBytes(token.ID.Bytes()),
		ConsentID: pgUUIDBytes(consent.Bytes()),
	})
	if err != nil {
		return oauthError("link oauth access token", err)
	}
	return nil
}

func (t *oauthTransaction) CreateRefresh(ctx context.Context, refresh oauth.RefreshToken) error {
	err := t.q.InsertOAuthRefreshToken(ctx, sqlcgen.InsertOAuthRefreshTokenParams{
		SecretHash: refresh.Hash[:],
		ConsentID:  pgUUIDBytes(refresh.ConsentID.Bytes()),
		CreatedAt:  pgTime(refresh.CreatedAt),
		ExpiresAt:  pgTime(refresh.ExpiresAt),
	})
	if err != nil {
		return oauthError("create oauth refresh token", err)
	}
	return nil
}

// FindUser loads the account through the open transaction queries.
func (t *oauthTransaction) FindUser(ctx context.Context, id users.ID) (users.User, error) {
	return userFromRow(t.q.GetUserByID(ctx, pgUUIDBytes(id.Bytes())))
}

func (t *oauthTransaction) consent(ctx context.Context, id oauth.ConsentID) (oauth.Consent, error) {
	row, err := t.q.LockOAuthConsentForIssue(ctx, pgUUIDBytes(id.Bytes()))
	if errors.Is(err, pgx.ErrNoRows) {
		return oauth.Consent{}, oauth.ErrInvalidGrant
	}
	if err != nil {
		return oauth.Consent{}, oauthError("load oauth consent", err)
	}
	return consentFromRow(row)
}

func deleteConsentTokens(ctx context.Context, q *sqlcgen.Queries, id oauth.ConsentID) error {
	if err := q.DeleteOAuthConsentAccessTokens(ctx, pgUUIDBytes(id.Bytes())); err != nil {
		return oauthError("delete oauth consent access tokens", err)
	}
	if err := q.DeleteOAuthConsentRefreshTokens(ctx, pgUUIDBytes(id.Bytes())); err != nil {
		return oauthError("delete oauth consent refresh tokens", err)
	}
	return nil
}

func clientFromRow(row sqlcgen.OauthClient) (oauth.Client, error) {
	if !row.ID.Valid || !row.CreatedAt.Valid {
		return oauth.Client{}, errors.New("postgres: oauth client row is incomplete")
	}
	name, err := oauth.ParseClientName(row.Name)
	if err != nil {
		return oauth.Client{}, fmt.Errorf("postgres: oauth client row: %w", err)
	}
	uris := make([]oauth.RedirectURI, 0, len(row.RedirectUris))
	for _, raw := range row.RedirectUris {
		uri, err := oauth.ParseRedirectURI(raw)
		if err != nil {
			return oauth.Client{}, fmt.Errorf("postgres: oauth client row: %w", err)
		}
		uris = append(uris, uri)
	}
	return oauth.Client{
		ID:           oauth.ClientIDFromBytes(row.ID.Bytes),
		Name:         name,
		RedirectURIs: uris,
		CreatedAt:    row.CreatedAt.Time.UTC(),
	}, nil
}

func consentFromRow(row sqlcgen.OauthConsent) (oauth.Consent, error) {
	if !row.ID.Valid || !row.UserID.Valid || !row.ClientID.Valid || !row.CreatedAt.Valid {
		return oauth.Consent{}, errors.New("postgres: oauth consent row is incomplete")
	}
	resource, err := tokens.ParseScope(row.Resource)
	if err != nil {
		return oauth.Consent{}, fmt.Errorf("postgres: oauth consent row: %w", err)
	}
	return oauth.Consent{
		ID:        oauth.ConsentIDFromBytes(row.ID.Bytes),
		UserID:    users.IDFromBytes(row.UserID.Bytes),
		ClientID:  oauth.ClientIDFromBytes(row.ClientID.Bytes),
		Resource:  resource,
		CreatedAt: row.CreatedAt.Time.UTC(),
		RevokedAt: optionalTime(row.RevokedAt),
	}, nil
}

func codeFromRow(row sqlcgen.OauthCode) (oauth.AuthorizationCode, error) {
	if len(row.CodeHash) != len(oauth.CodeHash{}) || !row.ConsentID.Valid || !row.CreatedAt.Valid || !row.ExpiresAt.Valid {
		return oauth.AuthorizationCode{}, errors.New("postgres: oauth code row is incomplete")
	}
	uri, err := oauth.ParseRedirectURI(row.RedirectUri)
	if err != nil {
		return oauth.AuthorizationCode{}, fmt.Errorf("postgres: oauth code row: %w", err)
	}
	challenge, err := oauth.ParseChallenge(row.Challenge, oauth.ChallengeMethodS256)
	if err != nil {
		return oauth.AuthorizationCode{}, fmt.Errorf("postgres: oauth code row: %w", err)
	}
	return oauth.AuthorizationCode{
		Hash:        oauth.CodeHash(row.CodeHash),
		ConsentID:   oauth.ConsentIDFromBytes(row.ConsentID.Bytes),
		RedirectURI: uri,
		Challenge:   challenge,
		CreatedAt:   row.CreatedAt.Time.UTC(),
		ExpiresAt:   row.ExpiresAt.Time.UTC(),
		UsedAt:      optionalTime(row.UsedAt),
	}, nil
}

func refreshFromRow(row sqlcgen.OauthRefreshToken) (oauth.RefreshToken, error) {
	if len(row.SecretHash) != len(oauth.RefreshHash{}) || !row.ConsentID.Valid || !row.CreatedAt.Valid || !row.ExpiresAt.Valid {
		return oauth.RefreshToken{}, errors.New("postgres: oauth refresh token row is incomplete")
	}
	return oauth.RefreshToken{
		Hash:      oauth.RefreshHash(row.SecretHash),
		ConsentID: oauth.ConsentIDFromBytes(row.ConsentID.Bytes),
		CreatedAt: row.CreatedAt.Time.UTC(),
		ExpiresAt: row.ExpiresAt.Time.UTC(),
		UsedAt:    optionalTime(row.UsedAt),
	}, nil
}

// oauthError keeps a value out of the message: a constraint name and a code say enough.
func oauthError(action string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return fmt.Errorf("postgres: %s: %s (SQLSTATE %s)", action, pgErr.ConstraintName, pgErr.Code)
	}
	return fmt.Errorf("postgres: %s: %w", action, err)
}
