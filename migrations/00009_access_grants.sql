-- +goose Up
-- A resource is a host and a path prefix that /auth/check protects.
-- host is lower case and keeps a port when the request names one.
-- path_prefix starts with '/' and has no trailing '/' unless it is '/'.
CREATE TABLE resources (
    name text PRIMARY KEY,
    host text NOT NULL,
    path_prefix text NOT NULL,
    CONSTRAINT resources_url_unique UNIQUE (host, path_prefix),
    CONSTRAINT resources_name CHECK (
        name <> ''
        AND char_length(name) <= 64
        AND name = lower(name)
    ),
    CONSTRAINT resources_host CHECK (host <> '' AND host = lower(host)),
    CONSTRAINT resources_path_prefix CHECK (left(path_prefix, 1) = '/')
);

-- A grant gives one user or one group access to one resource.
-- A grant with expires_at at or before now does not count.
CREATE TABLE access_grants (
    id uuid PRIMARY KEY,
    resource_name text NOT NULL REFERENCES resources (name) ON DELETE CASCADE,
    user_id uuid REFERENCES users (id),
    group_name text,
    expires_at timestamptz,
    created_at timestamptz NOT NULL,
    CONSTRAINT access_grants_subject CHECK ((user_id IS NULL) <> (group_name IS NULL))
);

CREATE UNIQUE INDEX access_grants_user_unique ON access_grants (resource_name, user_id)
WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX access_grants_group_unique ON access_grants (resource_name, group_name)
WHERE group_name IS NOT NULL;

-- +goose Down
DROP TABLE access_grants;
DROP TABLE resources;
