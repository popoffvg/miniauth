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
