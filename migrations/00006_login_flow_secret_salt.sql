-- +goose Up
-- secret_hash is now the SHA-256 of secret_salt followed by the flow secret.
-- A row from before this migration has no salt and cannot be verified, so it is deleted.
-- A flow expires within minutes, so a user loses at most one login in progress.
DELETE FROM login_flows;

ALTER TABLE login_flows
    ADD COLUMN secret_salt bytea NOT NULL,
    ADD CONSTRAINT login_flows_secret_salt_len CHECK (octet_length(secret_salt) = 16);

-- +goose Down
-- A salted hash cannot be verified without the salt, so every row is deleted.
DELETE FROM login_flows;

ALTER TABLE login_flows
    DROP COLUMN secret_salt;
