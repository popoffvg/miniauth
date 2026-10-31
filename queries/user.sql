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
WHERE users.login = $1 AND identities.kind = 'password' AND users.disabled_at IS NULL;

-- name: GetUserByID :one
SELECT id, login, created_at, disabled_at
FROM users
WHERE id = $1;

-- name: GetUserByLogin :one
SELECT id, login, created_at, disabled_at
FROM users
WHERE login = $1;

-- name: CountUsers :one
SELECT count(*)::bigint AS n FROM users;

-- name: DisableUser :execrows
UPDATE users
SET disabled_at = COALESCE(disabled_at, sqlc.arg(disabled_at))
WHERE id = sqlc.arg(id);

-- name: ListUserAccounts :many
SELECT
    users.id,
    users.login,
    users.created_at,
    users.disabled_at,
    COALESCE(
        (SELECT array_agg(gm.name ORDER BY gm.name) FROM group_memberships gm WHERE gm.user_id = users.id),
        '{}'
    )::text[] AS group_names,
    (SELECT count(*) FROM devices d WHERE d.user_id = users.id)::bigint AS device_count,
    (SELECT max(d.last_seen) FROM devices d WHERE d.user_id = users.id)::timestamptz AS last_seen
FROM users
ORDER BY users.login;

-- name: EnableUser :execrows
UPDATE users
SET disabled_at = NULL
WHERE id = $1;
