-- name: InsertUserIdentity :exec
WITH new_user AS (
    INSERT INTO users (id, login, created_at)
    VALUES (
        sqlc.arg(user_id),
        sqlc.arg(login),
        sqlc.arg(created_at)
    )
    RETURNING id
)
INSERT INTO identities (id, user_id, kind, password_hash, created_at)
SELECT
    sqlc.arg(identity_id),
    new_user.id,
    sqlc.arg(kind),
    sqlc.arg(password_hash),
    sqlc.arg(created_at)
FROM new_user;

-- name: GetIdentityByLogin :one
SELECT
    users.id AS user_id,
    users.login,
    users.created_at AS user_created_at,
    identities.id AS identity_id,
    identities.kind,
    identities.password_hash,
    identities.created_at AS identity_created_at
FROM users
JOIN identities ON identities.user_id = users.id
WHERE users.login = $1 AND identities.kind = 'password';

-- name: GetUserByID :one
SELECT id, login, created_at
FROM users
WHERE id = $1;

-- name: CountUsers :one
SELECT count(*)::bigint AS n FROM users;
