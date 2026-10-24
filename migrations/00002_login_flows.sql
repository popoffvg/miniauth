-- +goose Up
-- A login in progress. secret_hash is the SHA-256 of the flow secret.
-- version is the optimistic lock: a write matches the version it read.
-- A final state deletes the row. Expired rows are deleted by the cleanup query.
CREATE TABLE login_flows (
    id uuid PRIMARY KEY,
    secret_hash bytea NOT NULL,
    state text NOT NULL,
    factors integer NOT NULL,
    version bigint NOT NULL,
    return_url text NOT NULL,
    needs_second boolean NOT NULL,
    pending_factor integer NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT login_flows_secret_hash_len CHECK (octet_length(secret_hash) = 32)
);

CREATE INDEX login_flows_expires_at_idx ON login_flows (expires_at);

-- +goose Down
DROP TABLE login_flows;
