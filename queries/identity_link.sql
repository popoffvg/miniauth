-- name: GetExternalIdentity :one
SELECT
    identities.id AS identity_id,
    identities.user_id,
    identities.kind,
    identities.subject,
    identities.created_at
FROM identities
JOIN users ON users.id = identities.user_id
WHERE identities.kind = sqlc.arg(kind)
    AND identities.subject = sqlc.arg(subject)
    AND users.disabled_at IS NULL;

-- name: InsertPendingIdentityLink :exec
INSERT INTO pending_identity_links (secret_hash, provider, subject, created_at, expires_at)
VALUES (
    sqlc.arg(secret_hash),
    sqlc.arg(provider),
    sqlc.arg(subject),
    sqlc.arg(created_at),
    sqlc.arg(expires_at)
);

-- name: LinkPendingIdentity :one
WITH taken AS (
    DELETE FROM pending_identity_links
    WHERE secret_hash = sqlc.arg(secret_hash) AND expires_at > sqlc.arg(now)
    RETURNING provider, subject
)
INSERT INTO identities (id, user_id, kind, subject, created_at)
SELECT sqlc.arg(identity_id), sqlc.arg(user_id), taken.provider, taken.subject, sqlc.arg(now)
FROM taken
RETURNING kind, subject::text AS subject;

-- name: GetPendingIdentityLink :one
SELECT provider, subject, created_at, expires_at
FROM pending_identity_links
WHERE secret_hash = sqlc.arg(secret_hash) AND expires_at > sqlc.arg(now);

-- name: DeletePendingIdentityLink :exec
DELETE FROM pending_identity_links
WHERE secret_hash = $1;

-- name: DeleteExpiredPendingIdentityLinks :exec
DELETE FROM pending_identity_links
WHERE expires_at <= sqlc.arg(now);

-- name: CountPendingIdentityLinks :one
SELECT count(*)::bigint AS n FROM pending_identity_links;
