-- +goose Up
-- One password try. The password is never stored.
-- login is the normalised login the person typed. It need not belong to a user.
-- ip is the client address. An IPv6 address is stored as its /64 network address.
-- Rows older than the backoff window are deleted by the cleanup query.
CREATE TABLE login_attempts (
    login text NOT NULL,
    ip inet NOT NULL,
    succeeded boolean NOT NULL,
    attempted_at timestamptz NOT NULL,
    CONSTRAINT login_attempts_login_len CHECK (login <> '' AND char_length(login) <= 64)
);

CREATE INDEX login_attempts_login_idx ON login_attempts (login, attempted_at);
CREATE INDEX login_attempts_ip_idx ON login_attempts (ip, attempted_at);
CREATE INDEX login_attempts_attempted_at_idx ON login_attempts (attempted_at);

-- +goose Down
DROP TABLE login_attempts;
