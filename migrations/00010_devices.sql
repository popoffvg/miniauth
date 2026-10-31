-- +goose Up
-- A browser of one user. secret_hash is the SHA-256 of the device cookie.
-- The cookie value is never stored. name is a short label, not the User-Agent.
CREATE TABLE devices (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id),
    secret_hash bytea NOT NULL,
    name text NOT NULL,
    first_seen timestamptz NOT NULL,
    last_seen timestamptz NOT NULL,
    CONSTRAINT devices_user_secret_unique UNIQUE (user_id, secret_hash),
    CONSTRAINT devices_id_user_unique UNIQUE (id, user_id),
    CONSTRAINT devices_secret_hash_len CHECK (octet_length(secret_hash) = 32),
    CONSTRAINT devices_name_len CHECK (name <> '' AND octet_length(name) <= 64)
);

-- A device has at most one session. A session with a NULL device_id has no device.
-- The foreign key includes user_id, so a session cannot point at a device of another user.
ALTER TABLE sessions
    ADD COLUMN device_id uuid,
    ADD CONSTRAINT sessions_user_device_unique UNIQUE (user_id, device_id),
    ADD CONSTRAINT sessions_device_fkey FOREIGN KEY (device_id, user_id)
        REFERENCES devices (id, user_id) ON DELETE CASCADE;

-- +goose Down
ALTER TABLE sessions
    DROP CONSTRAINT sessions_device_fkey,
    DROP CONSTRAINT sessions_user_device_unique,
    DROP COLUMN device_id;

DROP TABLE devices;
