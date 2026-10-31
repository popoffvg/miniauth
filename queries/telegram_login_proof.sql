-- name: InsertTelegramLoginProof :execrows
INSERT INTO telegram_login_proofs (proof_hash, expires_at)
VALUES (sqlc.arg(proof_hash), sqlc.arg(expires_at))
ON CONFLICT (proof_hash) DO NOTHING;

-- name: DeleteExpiredTelegramLoginProofs :exec
DELETE FROM telegram_login_proofs
WHERE expires_at <= sqlc.arg(now);

-- name: CountTelegramLoginProofs :one
SELECT count(*)::bigint AS n FROM telegram_login_proofs;

-- name: DeleteTelegramLoginProof :exec
DELETE FROM telegram_login_proofs
WHERE proof_hash = sqlc.arg(proof_hash);
