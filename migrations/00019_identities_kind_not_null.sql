-- +goose Up
-- A CHECK that is NULL passes. Each branch tests IS NOT NULL first, so a row with a missing secret or subject makes the check false.
ALTER TABLE identities
    DROP CONSTRAINT identities_kind_secret,
    ADD CONSTRAINT identities_kind_secret CHECK (
        (kind = 'password' AND password_hash IS NOT NULL AND password_hash LIKE '$argon2id$%' AND subject IS NULL)
        OR (kind IN ('google', 'telegram') AND password_hash IS NULL AND subject IS NOT NULL
            AND subject <> '' AND char_length(subject) <= 255)
    );

-- +goose Down
ALTER TABLE identities
    DROP CONSTRAINT identities_kind_secret,
    ADD CONSTRAINT identities_kind_secret CHECK (
        (kind = 'password' AND password_hash LIKE '$argon2id$%' AND subject IS NULL)
        OR (kind IN ('google', 'telegram') AND password_hash IS NULL AND subject <> '' AND char_length(subject) <= 255)
    );
