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
