-- +goose Up
-- kind is "login" for a sign-in, or "step_up" for a password check of a user who is signed in.
-- user_id is the user a step_up flow MUST verify. A login flow has no user_id.
ALTER TABLE login_flows
    ADD COLUMN kind text NOT NULL DEFAULT 'login',
    ADD COLUMN user_id uuid REFERENCES users (id) ON DELETE CASCADE,
    ADD CONSTRAINT login_flows_kind_user CHECK (
        (kind = 'login' AND user_id IS NULL) OR (kind = 'step_up' AND user_id IS NOT NULL)
    );

-- +goose Down
ALTER TABLE login_flows
    DROP CONSTRAINT login_flows_kind_user,
    DROP COLUMN user_id,
    DROP COLUMN kind;
