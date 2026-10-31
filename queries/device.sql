-- name: UpsertDevice :one
INSERT INTO devices (
    id,
    user_id,
    secret_hash,
    name,
    first_seen,
    last_seen
) VALUES (
    sqlc.arg(id),
    sqlc.arg(user_id),
    sqlc.arg(secret_hash),
    sqlc.arg(name),
    sqlc.arg(seen_at),
    sqlc.arg(seen_at)
)
ON CONFLICT (user_id, secret_hash) DO UPDATE
SET name = EXCLUDED.name,
    last_seen = EXCLUDED.last_seen
RETURNING id;

-- name: UpsertDeviceSession :exec
INSERT INTO sessions (
    secret_hash,
    user_id,
    device_id,
    factors,
    auth_at,
    expires_at
) VALUES (
    $1, $2, $3, $4, $5, $6
)
ON CONFLICT (user_id, device_id) DO UPDATE
SET secret_hash = EXCLUDED.secret_hash,
    factors = EXCLUDED.factors,
    auth_at = EXCLUDED.auth_at,
    expires_at = EXCLUDED.expires_at;

-- name: ListDevices :many
SELECT
    id,
    user_id,
    name,
    first_seen,
    last_seen
FROM devices
WHERE user_id = $1
ORDER BY last_seen DESC, id;

-- name: DeviceOwned :one
SELECT EXISTS (
    SELECT 1 FROM devices
    WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id)
) AS owned;

-- name: DeleteDeviceSession :exec
DELETE FROM sessions
WHERE user_id = $1
  AND device_id = $2;

-- name: DeleteDevice :execrows
DELETE FROM devices
WHERE id = sqlc.arg(id)
  AND user_id = sqlc.arg(user_id);

-- name: TouchSessionDevice :exec
UPDATE devices
SET last_seen = sqlc.arg(seen_at)
FROM sessions
WHERE sessions.secret_hash = sqlc.arg(secret_hash)
  AND devices.id = sessions.device_id
  AND devices.last_seen < sqlc.arg(seen_at);

-- name: CountDevices :one
SELECT count(*)::bigint AS n FROM devices;

-- name: GetStoredDeviceHash :one
SELECT secret_hash FROM devices WHERE id = $1;
