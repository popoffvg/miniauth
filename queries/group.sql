-- name: ListGroupMemberships :many
SELECT name
FROM group_memberships
WHERE user_id = $1
ORDER BY name;

-- name: InsertGroupMembership :exec
INSERT INTO group_memberships (user_id, name)
VALUES ($1, $2);

-- name: EnsureGroupMembership :exec
INSERT INTO group_memberships (user_id, name)
VALUES ($1, $2)
ON CONFLICT (user_id, name) DO NOTHING;

-- name: DeleteGroupMembership :execrows
DELETE FROM group_memberships
WHERE user_id = $1 AND name = $2;

-- name: InsertGroup :exec
INSERT INTO groups (name, created_at)
VALUES ($1, $2);

-- name: EnsureGroup :exec
INSERT INTO groups (name, created_at)
VALUES ($1, $2)
ON CONFLICT (name) DO NOTHING;

-- name: DeleteGroup :execrows
DELETE FROM groups
WHERE name = $1 AND NOT built_in;

-- name: ListGroupSummaries :many
SELECT
    groups.name,
    groups.built_in,
    groups.created_at,
    (SELECT count(*) FROM group_memberships gm WHERE gm.name = groups.name)::bigint AS member_count,
    COALESCE(
        (SELECT array_agg(ag.resource_name ORDER BY ag.resource_name) FROM access_grants ag WHERE ag.group_name = groups.name),
        '{}'
    )::text[] AS resource_names,
    COALESCE(
        (SELECT array_agg(ag.managed ORDER BY ag.resource_name) FROM access_grants ag WHERE ag.group_name = groups.name),
        '{}'
    )::boolean[] AS resource_managed
FROM groups
WHERE sqlc.narg(name)::text IS NULL OR groups.name = sqlc.narg(name)
ORDER BY groups.name;

-- name: ListGroupNames :many
SELECT name FROM groups
ORDER BY name;
