-- name: InsertSession :exec
INSERT INTO sessions (
    secret_hash,
    user_id,
    factors,
    auth_at,
    expires_at
) VALUES (
    $1, $2, $3, $4, $5
);

-- name: GetSession :one
SELECT
    user_id,
    factors,
    auth_at,
    expires_at,
    secret_hash
FROM sessions
WHERE secret_hash = $1;

-- name: ExtendSession :execrows
UPDATE sessions
SET expires_at = sqlc.arg(expires_at)
WHERE secret_hash = sqlc.arg(secret_hash)
  AND expires_at <= sqlc.arg(extend_before);

-- name: DeleteSession :exec
DELETE FROM sessions
WHERE secret_hash = $1;

-- name: DeleteUserSessions :exec
DELETE FROM sessions
WHERE user_id = $1;

-- name: CountSessions :one
SELECT count(*)::bigint AS n FROM sessions;
