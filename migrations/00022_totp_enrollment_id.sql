-- +goose Up
-- enrollment_id names one enrollment. A deleted and new row starts at version 1 again but gets a new id,
-- so a write and a code check that read the old enrollment change zero rows.
ALTER TABLE totp_credentials
    ADD COLUMN enrollment_id uuid NOT NULL DEFAULT gen_random_uuid();

-- +goose Down
ALTER TABLE totp_credentials
    DROP COLUMN enrollment_id;
