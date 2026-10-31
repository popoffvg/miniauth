-- +goose Up
-- One password recovery link. token_hash is the SHA-256 of the random token in the link.
-- The token is never stored. A row is open while used_at is NULL and expires_at is in the future.
CREATE TABLE password_resets (
    token_hash bytea PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    CONSTRAINT password_resets_token_hash_len CHECK (octet_length(token_hash) = 32)
);

CREATE INDEX password_resets_user_id_idx ON password_resets (user_id);
CREATE INDEX password_resets_expires_at_idx ON password_resets (expires_at);

-- One recovery request. It has the shape of login_attempts, so the password step backoff applies.
-- login is the normalised address the person typed. It need not belong to a user.
CREATE TABLE recovery_attempts (
    login text NOT NULL,
    ip inet NOT NULL,
    succeeded boolean NOT NULL,
    attempted_at timestamptz NOT NULL,
    CONSTRAINT recovery_attempts_login_len CHECK (login <> '' AND char_length(login) <= 64)
);

CREATE INDEX recovery_attempts_login_idx ON recovery_attempts (login, attempted_at);
CREATE INDEX recovery_attempts_ip_idx ON recovery_attempts (ip, attempted_at);
CREATE INDEX recovery_attempts_attempted_at_idx ON recovery_attempts (attempted_at);

-- +goose Down
DROP TABLE recovery_attempts;
DROP TABLE password_resets;
