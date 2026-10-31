-- +goose Up
-- An invite lets one new person create an account with a grant on one resource.
-- token_hash is the SHA-256 of the 32-byte token. The token is never stored.
-- used_at is set once, by the acceptance. user_id is the account that acceptance created.
CREATE TABLE invites (
    token_hash bytea PRIMARY KEY,
    resource_name text NOT NULL REFERENCES resources (name) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    user_id uuid REFERENCES users (id),
    CONSTRAINT invites_token_hash_len CHECK (octet_length(token_hash) = 32),
    CONSTRAINT invites_expiry CHECK (expires_at > created_at)
);

-- +goose Down
DROP TABLE invites;
