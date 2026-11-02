-- +goose Up
-- pending_link is no longer a state: pending_factor alone marks an unknown external account.
-- Such a row has no factor and no user yet, so it waits for a first factor.
UPDATE login_flows SET state = 'awaiting' WHERE state = 'pending_link';

-- +goose Down
UPDATE login_flows SET state = 'pending_link' WHERE state = 'awaiting' AND pending_factor <> 0;
