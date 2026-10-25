-- +goose Up
-- A user is an account. login is the name the person types.
-- An identity is one way that user proves who they are.
-- kind "password": password_hash is the PHC argon2id string, never the password.
CREATE TABLE users (
    id uuid PRIMARY KEY,
    login text NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT users_login_unique UNIQUE (login),
    CONSTRAINT users_login_nonempty CHECK (login <> '' AND char_length(login) <= 64)
);

CREATE TABLE identities (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id),
    kind text NOT NULL,
    password_hash text NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT identities_kind_password CHECK (kind = 'password'),
    CONSTRAINT identities_password_hash_phc CHECK (password_hash LIKE '$argon2id$%'),
    CONSTRAINT identities_user_kind_unique UNIQUE (user_id, kind)
);

-- +goose Down
DROP TABLE identities;
DROP TABLE users;
