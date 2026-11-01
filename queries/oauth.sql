-- name: InsertOAuthClient :exec
INSERT INTO oauth_clients (id, name, redirect_uris, created_at)
VALUES ($1, $2, $3, $4);

-- name: GetOAuthClient :one
SELECT id, name, redirect_uris, created_at
FROM oauth_clients
WHERE id = $1;

-- name: ListOAuthClients :many
SELECT id, name, redirect_uris, created_at
FROM oauth_clients
ORDER BY created_at, id;

-- name: DeleteOAuthClientAccessTokens :exec
DELETE FROM access_tokens
WHERE id IN (
    SELECT t.token_id
    FROM oauth_access_tokens t
    JOIN oauth_consents c ON c.id = t.consent_id
    WHERE c.client_id = $1
);

-- name: DeleteOAuthClient :execrows
DELETE FROM oauth_clients
WHERE id = $1;

-- name: SaveOAuthConsent :one
-- The no-op update returns the active consent that is already stored.
INSERT INTO oauth_consents (id, user_id, client_id, resource, created_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (user_id, client_id, resource) WHERE revoked_at IS NULL
DO UPDATE SET created_at = oauth_consents.created_at
RETURNING id, user_id, client_id, resource, created_at, revoked_at;

-- name: ListActiveOAuthConsents :many
SELECT
    c.id,
    c.user_id,
    c.client_id,
    c.resource,
    c.created_at,
    c.revoked_at,
    k.name AS client_name
FROM oauth_consents c
JOIN oauth_clients k ON k.id = c.client_id
WHERE c.user_id = $1
  AND c.revoked_at IS NULL
ORDER BY c.created_at, c.id;

-- name: RevokeUserOAuthConsent :execrows
UPDATE oauth_consents
SET revoked_at = sqlc.arg(revoked_at)
WHERE id = sqlc.arg(id)
  AND user_id = sqlc.arg(user_id)
  AND revoked_at IS NULL;

-- name: EndOAuthConsent :exec
UPDATE oauth_consents
SET revoked_at = COALESCE(revoked_at, sqlc.arg(revoked_at))
WHERE id = sqlc.arg(id);

-- name: DeleteOAuthConsentAccessTokens :exec
DELETE FROM access_tokens
WHERE id IN (
    SELECT token_id
    FROM oauth_access_tokens
    WHERE consent_id = $1
);

-- name: DeleteOAuthConsentRefreshTokens :exec
DELETE FROM oauth_refresh_tokens
WHERE consent_id = $1;

-- name: InsertOAuthCode :exec
INSERT INTO oauth_codes (code_hash, consent_id, redirect_uri, challenge, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ClaimOAuthCode :one
UPDATE oauth_codes
SET used_at = sqlc.arg(used_at)
WHERE code_hash = sqlc.arg(code_hash)
  AND used_at IS NULL
RETURNING code_hash, consent_id, redirect_uri, challenge, created_at, expires_at, used_at;

-- name: GetOAuthCode :one
SELECT code_hash, consent_id, redirect_uri, challenge, created_at, expires_at, used_at
FROM oauth_codes
WHERE code_hash = $1;

-- name: InsertOAuthRefreshToken :exec
INSERT INTO oauth_refresh_tokens (secret_hash, consent_id, created_at, expires_at)
VALUES ($1, $2, $3, $4);

-- name: ClaimOAuthRefreshToken :one
UPDATE oauth_refresh_tokens
SET used_at = sqlc.arg(used_at)
WHERE secret_hash = sqlc.arg(secret_hash)
  AND used_at IS NULL
RETURNING secret_hash, consent_id, created_at, expires_at, used_at;

-- name: GetOAuthRefreshToken :one
SELECT secret_hash, consent_id, created_at, expires_at, used_at
FROM oauth_refresh_tokens
WHERE secret_hash = $1;

-- name: InsertOAuthAccessToken :exec
INSERT INTO oauth_access_tokens (token_id, consent_id)
VALUES ($1, $2);

-- name: LockOAuthConsentForIssue :one
-- FOR SHARE makes a revoke of the consent wait until the token issue commits.
-- An issue that starts after the revoke reads the revoked row.
SELECT id, user_id, client_id, resource, created_at, revoked_at
FROM oauth_consents
WHERE id = $1
FOR SHARE;

-- name: LockOAuthClientConsents :exec
-- FOR UPDATE waits for every token issue under the client's consents,
-- so the access token delete that follows sees their tokens.
SELECT id
FROM oauth_consents
WHERE client_id = $1
FOR UPDATE;
