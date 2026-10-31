-- name: InsertResource :exec
INSERT INTO resources (name, host, path_prefix)
VALUES ($1, $2, $3);

-- name: DeleteResource :execrows
DELETE FROM resources
WHERE name = $1;

-- name: GetResource :one
SELECT name, host, path_prefix
FROM resources
WHERE name = $1;

-- name: ListResourcesByHost :many
SELECT name, host, path_prefix
FROM resources
WHERE host = $1
ORDER BY name;

-- name: InsertAccessGrant :exec
INSERT INTO access_grants (
    id,
    resource_name,
    user_id,
    group_name,
    expires_at,
    created_at
) VALUES (
    $1, $2, $3, $4, $5, $6
);

-- name: DeleteAccessGrant :execrows
DELETE FROM access_grants
WHERE id = $1;

-- name: ListAccessGrants :many
SELECT id, resource_name, user_id, group_name, expires_at, created_at
FROM access_grants
WHERE resource_name = $1
ORDER BY created_at, id;

-- name: ListAllResources :many
SELECT name, host, path_prefix
FROM resources
ORDER BY name;

-- name: ListAccessGrantEntries :many
SELECT
    access_grants.id,
    access_grants.resource_name,
    access_grants.user_id,
    access_grants.group_name,
    access_grants.expires_at,
    access_grants.created_at,
    resources.host,
    resources.path_prefix,
    users.login AS user_login
FROM access_grants
JOIN resources ON resources.name = access_grants.resource_name
LEFT JOIN users ON users.id = access_grants.user_id
WHERE
    (sqlc.narg(login)::text IS NULL OR users.login = sqlc.narg(login))
    AND (sqlc.narg(resource_name)::text IS NULL OR access_grants.resource_name = sqlc.narg(resource_name))
ORDER BY access_grants.resource_name, access_grants.created_at, access_grants.id;
