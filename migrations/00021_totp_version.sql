-- +goose Up
-- version counts the enrollment transitions of the row. A write names the version it read,
-- so a confirm and a disable that read the same row cannot both succeed.
ALTER TABLE totp_credentials
    ADD COLUMN version bigint NOT NULL DEFAULT 1;

-- +goose Down
ALTER TABLE totp_credentials
    DROP COLUMN version;
