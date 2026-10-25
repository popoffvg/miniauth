-- +goose Up
-- A browser session. secret_hash is the SHA-256 of the cookie value.
-- The cookie value is never stored.
-- auth_at is the time of the login. expires_at moves forward at most once an hour.
CREATE TABLE sessions (
    secret_hash bytea PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id),
    factors integer NOT NULL,
    auth_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT sessions_secret_hash_len CHECK (octet_length(secret_hash) = 32),
    CONSTRAINT sessions_factors_range CHECK (factors >= 0 AND factors <= 65535)
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

-- +goose Down
DROP TABLE sessions;
