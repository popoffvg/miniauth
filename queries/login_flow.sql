-- name: CreateLoginFlow :exec
INSERT INTO login_flows (
    id,
    secret_hash,
    secret_salt,
    state,
    factors,
    version,
    return_url,
    needs_second,
    pending_factor,
    expires_at,
    kind,
    user_id
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
);

-- name: GetLoginFlow :one
SELECT
    id,
    secret_hash,
    secret_salt,
    state,
    factors,
    version,
    return_url,
    needs_second,
    pending_factor,
    expires_at,
    kind,
    user_id,
    (expires_at <= now())::boolean AS expired
FROM login_flows
WHERE id = $1;

-- name: UpdateLoginFlow :execrows
UPDATE login_flows
SET
    state = sqlc.arg(state),
    factors = sqlc.arg(factors),
    version = sqlc.arg(next_version),
    return_url = sqlc.arg(return_url),
    needs_second = sqlc.arg(needs_second),
    pending_factor = sqlc.arg(pending_factor),
    expires_at = sqlc.arg(expires_at),
    user_id = sqlc.arg(user_id)
WHERE id = sqlc.arg(id) AND version = sqlc.arg(prev_version);

-- name: DeleteLoginFlowVersion :execrows
DELETE FROM login_flows
WHERE id = $1 AND version = $2;

-- name: DeleteLoginFlow :exec
DELETE FROM login_flows
WHERE id = $1;

-- name: DeleteExpiredLoginFlows :exec
DELETE FROM login_flows
WHERE expires_at <= now();

-- name: CountLoginFlows :one
SELECT count(*)::bigint AS n FROM login_flows;
