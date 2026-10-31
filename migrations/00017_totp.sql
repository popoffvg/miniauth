-- +goose Up
-- A login flow keeps the user of its first factor, so a second step checks the same user.
ALTER TABLE login_flows
    DROP CONSTRAINT login_flows_kind_user,
    ADD CONSTRAINT login_flows_kind_user CHECK (kind = 'login' OR user_id IS NOT NULL);

-- kind groups the steps that share one failure count per login.
-- A password success does not reset the count of a second_factor step.
ALTER TABLE login_attempts
    ADD COLUMN kind text NOT NULL DEFAULT 'password',
    ADD CONSTRAINT login_attempts_kind CHECK (kind IN ('password', 'second_factor'));

DROP INDEX login_attempts_login_idx;
CREATE INDEX login_attempts_login_idx ON login_attempts (login, kind, attempted_at);

-- sealed_secret is the AES-GCM nonce and ciphertext of the TOTP secret.
-- The user id is the additional data, so a sealed secret does not open for another user.
-- A row with a NULL confirmed_at waits for the first code of an enrollment.
-- last_step is the time step of the last accepted code. A code of that step or older is refused.
CREATE TABLE totp_credentials (
    user_id uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    sealed_secret bytea NOT NULL,
    last_step bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL,
    confirmed_at timestamptz
);

-- code_hash is the SHA-256 of a recovery code. The code is never stored.
-- A row with a used_at is spent.
CREATE TABLE recovery_codes (
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash bytea NOT NULL,
    used_at timestamptz,
    PRIMARY KEY (user_id, code_hash),
    CONSTRAINT recovery_codes_hash_len CHECK (octet_length(code_hash) = 32)
);

-- +goose Down
DROP TABLE recovery_codes;
DROP TABLE totp_credentials;

DROP INDEX login_attempts_login_idx;
CREATE INDEX login_attempts_login_idx ON login_attempts (login, attempted_at);

ALTER TABLE login_attempts
    DROP CONSTRAINT login_attempts_kind,
    DROP COLUMN kind;

UPDATE login_flows SET user_id = NULL WHERE kind = 'login';
ALTER TABLE login_flows
    DROP CONSTRAINT login_flows_kind_user,
    ADD CONSTRAINT login_flows_kind_user CHECK (
        (kind = 'login' AND user_id IS NULL) OR (kind = 'step_up' AND user_id IS NOT NULL)
    );
