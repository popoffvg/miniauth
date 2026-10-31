-- +goose Up
-- A Telegram identity has the decimal Telegram user id as its subject.
ALTER TABLE identities
    DROP CONSTRAINT identities_kind_secret,
    ADD CONSTRAINT identities_kind_secret CHECK (
        (kind = 'password' AND password_hash LIKE '$argon2id$%' AND subject IS NULL)
        OR (kind IN ('google', 'telegram') AND password_hash IS NULL AND subject <> '' AND char_length(subject) <= 255)
    );

-- One row per accepted Telegram widget login, so the same callback data signs in once.
-- proof_hash is the SHA-256 of the Telegram id, auth_date, and hash. A row expires when its data is too old to accept.
CREATE TABLE telegram_login_proofs (
    proof_hash bytea PRIMARY KEY,
    expires_at timestamptz NOT NULL,
    CONSTRAINT telegram_login_proofs_proof_hash_len CHECK (octet_length(proof_hash) = 32)
);

CREATE INDEX telegram_login_proofs_expires_at_idx ON telegram_login_proofs (expires_at);

-- +goose Down
DROP TABLE telegram_login_proofs;

DELETE FROM identities WHERE kind = 'telegram';
DELETE FROM pending_identity_links WHERE provider = 'telegram';

ALTER TABLE identities
    DROP CONSTRAINT identities_kind_secret,
    ADD CONSTRAINT identities_kind_secret CHECK (
        (kind = 'password' AND password_hash LIKE '$argon2id$%' AND subject IS NULL)
        OR (kind = 'google' AND password_hash IS NULL AND subject <> '' AND char_length(subject) <= 255)
    );
