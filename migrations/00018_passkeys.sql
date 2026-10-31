-- +goose Up
-- A WebAuthn credential of one user. credential_id is the id the authenticator chose.
-- public_key is the COSE key. sign_count is the last counter the authenticator sent.
-- backup_eligible is the BE flag of the registration: a later login MUST send the same flag.
CREATE TABLE passkeys (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id),
    credential_id bytea NOT NULL,
    public_key bytea NOT NULL,
    sign_count bigint NOT NULL,
    transports text[] NOT NULL,
    aaguid uuid NOT NULL,
    backup_eligible boolean NOT NULL,
    name text NOT NULL,
    created_at timestamptz NOT NULL,
    last_used_at timestamptz,
    CONSTRAINT passkeys_credential_id_unique UNIQUE (credential_id),
    CONSTRAINT passkeys_credential_id_len CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
    CONSTRAINT passkeys_public_key_len CHECK (octet_length(public_key) > 0),
    CONSTRAINT passkeys_sign_count_range CHECK (sign_count BETWEEN 0 AND 4294967295),
    CONSTRAINT passkeys_name CHECK (name <> '' AND char_length(name) <= 64)
);

CREATE INDEX passkeys_user_id_idx ON passkeys (user_id);

-- +goose Down
DROP TABLE passkeys;
