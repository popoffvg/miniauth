-- +goose Up
-- step_state is the state of the child machine of the pass in progress: Google, passkey, or Telegram.
-- The request that begins a pass writes the start state. The callback moves it to a final state once.
ALTER TABLE login_flows
    ADD COLUMN step_state text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE login_flows
    DROP COLUMN step_state;
