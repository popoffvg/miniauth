-- +goose Up
-- A group the forward-auth check reads.
-- name is stored in lower case. This table holds no secret.
CREATE TABLE group_memberships (
    user_id uuid NOT NULL REFERENCES users (id),
    name text NOT NULL,
    PRIMARY KEY (user_id, name),
    CONSTRAINT group_memberships_name CHECK (
        name <> ''
        AND char_length(name) <= 64
        AND name = lower(name)
    )
);

-- +goose Down
DROP TABLE group_memberships;
