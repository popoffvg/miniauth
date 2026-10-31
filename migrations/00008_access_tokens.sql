-- +goose Up
-- disabled_at is set when the account may no longer authenticate.
ALTER TABLE users
    ADD COLUMN disabled_at timestamptz;

-- A personal access token. secret_hash is the SHA-256 of the clear token.
-- The clear token is never stored. display_prefix is its first 8 characters.
-- A scope is a URL prefix. An empty scopes array reaches every URL.
-- expires_at NULL means the token does not expire.
-- last_used_at moves forward at most once a minute.
CREATE TABLE access_tokens (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id),
    secret_hash bytea NOT NULL,
    display_prefix text NOT NULL,
    name text NOT NULL,
    scopes text[] NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz,
    revoked_at timestamptz,
    last_used_at timestamptz,
    CONSTRAINT access_tokens_secret_hash_unique UNIQUE (secret_hash),
    CONSTRAINT access_tokens_secret_hash_len CHECK (octet_length(secret_hash) = 32),
    CONSTRAINT access_tokens_display_prefix CHECK (display_prefix LIKE 'idp\_%' AND char_length(display_prefix) = 8),
    CONSTRAINT access_tokens_name CHECK (name <> '' AND char_length(name) <= 64)
);

CREATE INDEX access_tokens_user_id_idx ON access_tokens (user_id);

-- +goose Down
DROP TABLE access_tokens;

ALTER TABLE users
    DROP COLUMN disabled_at;
