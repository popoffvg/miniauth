-- name: InsertAccessToken :exec
INSERT INTO access_tokens (
    id,
    user_id,
    secret_hash,
    display_prefix,
    name,
    scopes,
    created_at,
    expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8
);

-- name: GetAccessTokenByHash :one
SELECT
    id,
    user_id,
    secret_hash,
    display_prefix,
    name,
    scopes,
    created_at,
    expires_at,
    revoked_at,
    last_used_at
FROM access_tokens
WHERE secret_hash = $1;

-- name: ListUserAccessTokens :many
SELECT
    id,
    user_id,
    secret_hash,
    display_prefix,
    name,
    scopes,
    created_at,
    expires_at,
    revoked_at,
    last_used_at
FROM access_tokens
WHERE user_id = $1
ORDER BY created_at, id;

-- name: RevokeAccessToken :execrows
UPDATE access_tokens
SET revoked_at = COALESCE(revoked_at, sqlc.arg(revoked_at))
WHERE id = sqlc.arg(id)
  AND user_id = sqlc.arg(user_id);

-- name: TouchAccessToken :exec
UPDATE access_tokens
SET last_used_at = sqlc.arg(last_used_at)
WHERE id = sqlc.arg(id)
  AND (last_used_at IS NULL OR last_used_at <= sqlc.arg(touch_before));
