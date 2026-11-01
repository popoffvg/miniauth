-- name: InsertPendingTOTP :execrows
-- Zero rows means another request stored a row first.
INSERT INTO totp_credentials (user_id, sealed_secret, created_at, version)
VALUES (sqlc.arg(user_id), sqlc.arg(sealed_secret), sqlc.arg(created_at), sqlc.arg(version))
ON CONFLICT (user_id) DO NOTHING;

-- name: ReplacePendingTOTP :execrows
-- A confirmed row is not replaced.
UPDATE totp_credentials
SET sealed_secret = sqlc.arg(sealed_secret), created_at = sqlc.arg(created_at), last_step = 0, version = sqlc.arg(next_version)
WHERE user_id = sqlc.arg(user_id)
    AND confirmed_at IS NULL
    AND version = sqlc.arg(prev_version);

-- name: GetTOTPCredential :one
SELECT user_id, sealed_secret, last_step, created_at, confirmed_at, version
FROM totp_credentials
WHERE user_id = $1;

-- name: ConfirmTOTP :execrows
-- created_at names the enrollment. A deleted and new row starts at version 1 again,
-- so the version alone does not keep an older page from confirming a newer enrollment.
UPDATE totp_credentials
SET confirmed_at = sqlc.arg(confirmed_at), last_step = sqlc.arg(last_step), version = sqlc.arg(next_version)
WHERE user_id = sqlc.arg(user_id)
    AND confirmed_at IS NULL
    AND created_at = sqlc.arg(created_at)
    AND version = sqlc.arg(prev_version);

-- name: UseTOTPStep :execrows
-- Zero rows means a code of this step or a later step was already accepted.
UPDATE totp_credentials
SET last_step = sqlc.arg(step)
WHERE user_id = sqlc.arg(user_id)
    AND confirmed_at IS NOT NULL
    AND last_step < sqlc.arg(step);

-- name: DeleteTOTP :execrows
DELETE FROM totp_credentials
WHERE user_id = sqlc.arg(user_id)
    AND version = sqlc.arg(version);

-- name: InsertRecoveryCodes :exec
INSERT INTO recovery_codes (user_id, code_hash)
SELECT sqlc.arg(user_id), unnest(sqlc.arg(code_hashes)::bytea[]);

-- name: DeleteRecoveryCodes :exec
DELETE FROM recovery_codes
WHERE user_id = $1;

-- name: UseRecoveryCode :execrows
-- Zero rows means the code is unknown or spent.
UPDATE recovery_codes
SET used_at = sqlc.arg(used_at)
WHERE user_id = sqlc.arg(user_id)
    AND code_hash = sqlc.arg(code_hash)
    AND used_at IS NULL;
