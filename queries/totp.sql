-- name: UpsertPendingTOTP :execrows
-- A confirmed row is not replaced: zero rows means the user is already enrolled.
INSERT INTO totp_credentials (user_id, sealed_secret, created_at)
VALUES ($1, $2, $3)
ON CONFLICT (user_id) DO UPDATE
SET sealed_secret = excluded.sealed_secret, created_at = excluded.created_at, last_step = 0
WHERE totp_credentials.confirmed_at IS NULL;

-- name: GetTOTPCredential :one
SELECT user_id, sealed_secret, last_step, created_at, confirmed_at
FROM totp_credentials
WHERE user_id = $1;

-- name: ConfirmTOTP :execrows
-- created_at names the enrollment, so a newer enrollment of the same user is not confirmed by an older page.
UPDATE totp_credentials
SET confirmed_at = sqlc.arg(confirmed_at), last_step = sqlc.arg(last_step)
WHERE user_id = sqlc.arg(user_id)
    AND confirmed_at IS NULL
    AND created_at = sqlc.arg(created_at);

-- name: UseTOTPStep :execrows
-- Zero rows means a code of this step or a later step was already accepted.
UPDATE totp_credentials
SET last_step = sqlc.arg(step)
WHERE user_id = sqlc.arg(user_id)
    AND confirmed_at IS NOT NULL
    AND last_step < sqlc.arg(step);

-- name: DeleteTOTP :exec
DELETE FROM totp_credentials
WHERE user_id = $1;

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
