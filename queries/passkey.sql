-- name: InsertPasskey :exec
INSERT INTO passkeys (
    id,
    user_id,
    credential_id,
    public_key,
    sign_count,
    transports,
    aaguid,
    backup_eligible,
    name,
    created_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
);

-- name: GetActivePasskeyByCredential :one
SELECT passkeys.*
FROM passkeys
JOIN users ON users.id = passkeys.user_id
WHERE passkeys.credential_id = $1 AND users.disabled_at IS NULL;

-- name: ListUserPasskeys :many
SELECT *
FROM passkeys
WHERE user_id = $1
ORDER BY created_at, id;

-- name: RecordPasskeyUse :execrows
UPDATE passkeys
SET
    sign_count = sqlc.arg(next_count),
    last_used_at = sqlc.arg(used_at)
WHERE id = sqlc.arg(id) AND sign_count = sqlc.arg(prev_count);

-- name: DeleteUserPasskey :execrows
DELETE FROM passkeys
WHERE id = $1 AND user_id = $2;
