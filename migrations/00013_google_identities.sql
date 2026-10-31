-- +goose Up
-- challenge is what one login step keeps between its redirect and its callback.
-- It holds hashes only, so a copy of the database cannot finish a login.
ALTER TABLE login_flows
    ADD COLUMN IF NOT EXISTS challenge bytea;

-- subject is the account id at an outside provider. kind names the provider.
-- A password identity has a password_hash and no subject. An outside identity has a subject and no password_hash.
ALTER TABLE identities
    ALTER COLUMN password_hash DROP NOT NULL,
    ADD COLUMN subject text,
    DROP CONSTRAINT identities_kind_password,
    DROP CONSTRAINT identities_password_hash_phc,
    ADD CONSTRAINT identities_kind_secret CHECK (
        (kind = 'password' AND password_hash LIKE '$argon2id$%' AND subject IS NULL)
        OR (kind = 'google' AND password_hash IS NULL AND subject <> '' AND char_length(subject) <= 255)
    ),
    ADD CONSTRAINT identities_kind_subject_unique UNIQUE (kind, subject);

-- An outside account that is not linked to a user yet.
-- secret_hash is the SHA-256 of the browser cookie. The cookie value is never stored.
-- A password login in the same browser links the account. Expired rows are ignored and then deleted.
CREATE TABLE pending_identity_links (
    secret_hash bytea PRIMARY KEY,
    provider text NOT NULL,
    subject text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT pending_identity_links_secret_hash_len CHECK (octet_length(secret_hash) = 32),
    CONSTRAINT pending_identity_links_provider CHECK (provider <> '' AND provider <> 'password'),
    CONSTRAINT pending_identity_links_subject CHECK (subject <> '' AND char_length(subject) <= 255)
);

CREATE INDEX pending_identity_links_expires_at_idx ON pending_identity_links (expires_at);

-- +goose Down
DROP TABLE pending_identity_links;

DELETE FROM identities WHERE kind <> 'password';

ALTER TABLE identities
    DROP CONSTRAINT identities_kind_subject_unique,
    DROP CONSTRAINT identities_kind_secret,
    DROP COLUMN subject,
    ALTER COLUMN password_hash SET NOT NULL,
    ADD CONSTRAINT identities_kind_password CHECK (kind = 'password'),
    ADD CONSTRAINT identities_password_hash_phc CHECK (password_hash LIKE '$argon2id$%');

ALTER TABLE login_flows
    DROP COLUMN IF EXISTS challenge;
