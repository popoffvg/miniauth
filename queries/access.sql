-- name: InsertResource :exec
INSERT INTO resources (name, host, path_prefix)
VALUES ($1, $2, $3);

-- name: DeleteResource :execrows
DELETE FROM resources
WHERE name = $1;

-- name: GetResource :one
SELECT name, host, path_prefix, managed
FROM resources
WHERE name = $1;

-- name: ListResourcesByHost :many
SELECT name, host, path_prefix, managed
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
SELECT id, resource_name, user_id, group_name, expires_at, created_at, managed
FROM access_grants
WHERE resource_name = $1
ORDER BY created_at, id;

-- name: ListAllResources :many
SELECT name, host, path_prefix, managed
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
    access_grants.managed,
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

-- name: GetAccessGrant :one
SELECT id, resource_name, user_id, group_name, expires_at, created_at, managed
FROM access_grants
WHERE id = $1;

-- name: UpsertManagedResource :exec
INSERT INTO resources (name, host, path_prefix, managed)
VALUES ($1, $2, $3, true)
ON CONFLICT (name) DO UPDATE
SET host = excluded.host, path_prefix = excluded.path_prefix, managed = true;

-- name: UpsertManagedGroupGrant :exec
INSERT INTO access_grants (id, resource_name, group_name, created_at, managed)
VALUES ($1, $2, $3, $4, true)
ON CONFLICT (resource_name, group_name) WHERE group_name IS NOT NULL DO UPDATE
SET managed = true, expires_at = NULL;

-- name: DeleteStaleManagedGrants :execrows
DELETE FROM access_grants
WHERE managed
    AND (resource_name, group_name) NOT IN (
        SELECT unnest(sqlc.arg(keep_resources)::text[]), unnest(sqlc.arg(keep_groups)::text[])
    );

-- name: DeleteStaleManagedResources :execrows
DELETE FROM resources
WHERE managed AND NOT (name = ANY(sqlc.arg(keep)::text[]));

-- name: DeferConstraints :exec
-- resources_url_unique is the one deferrable constraint.
SET CONSTRAINTS ALL DEFERRED;

-- name: UnmanagedResourceHasURL :one
SELECT EXISTS (
    SELECT 1 FROM resources
    WHERE host = sqlc.arg(host) AND path_prefix = sqlc.arg(path_prefix) AND name <> sqlc.arg(name) AND NOT managed
) AS taken;
