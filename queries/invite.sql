-- name: InsertInvite :exec
INSERT INTO invites (token_hash, group_name, created_at, expires_at)
VALUES ($1, $2, $3, $4);

-- name: GetInvite :one
SELECT token_hash, created_at, expires_at, used_at, user_id, group_name
FROM invites
WHERE token_hash = $1;

-- name: ClaimInvite :one
UPDATE invites
SET used_at = sqlc.arg(now)
WHERE token_hash = sqlc.arg(token_hash)
    AND used_at IS NULL
    AND expires_at > sqlc.arg(now)
RETURNING token_hash, created_at, expires_at, used_at, user_id, group_name;

-- name: SetInviteUser :execrows
UPDATE invites
SET user_id = $2
WHERE token_hash = $1;
