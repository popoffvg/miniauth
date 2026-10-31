-- name: InsertPasswordReset :exec
INSERT INTO password_resets (token_hash, user_id, created_at, expires_at)
VALUES ($1, $2, $3, $4);

-- name: GetOpenPasswordReset :one
SELECT password_resets.token_hash, password_resets.user_id, password_resets.created_at, password_resets.expires_at
FROM password_resets
JOIN users ON users.id = password_resets.user_id
WHERE password_resets.token_hash = sqlc.arg(token_hash)
    AND password_resets.used_at IS NULL
    AND password_resets.expires_at > sqlc.arg(now)::timestamptz
    AND users.disabled_at IS NULL;

-- name: LockOpenPasswordReset :one
SELECT password_resets.user_id
FROM password_resets
JOIN users ON users.id = password_resets.user_id
WHERE password_resets.token_hash = sqlc.arg(token_hash)
    AND password_resets.used_at IS NULL
    AND password_resets.expires_at > sqlc.arg(now)::timestamptz
    AND users.disabled_at IS NULL
FOR UPDATE OF password_resets;

-- name: SetPasswordHash :execrows
UPDATE identities
SET password_hash = sqlc.arg(password_hash)::text
WHERE user_id = sqlc.arg(user_id) AND kind = 'password';

-- name: MarkPasswordResetUsed :exec
UPDATE password_resets
SET used_at = sqlc.arg(used_at)
WHERE token_hash = sqlc.arg(token_hash);

-- name: DeleteOpenPasswordResets :exec
DELETE FROM password_resets
WHERE user_id = $1 AND used_at IS NULL;

-- name: DeletePasswordResetsBefore :exec
DELETE FROM password_resets
WHERE expires_at < $1;
