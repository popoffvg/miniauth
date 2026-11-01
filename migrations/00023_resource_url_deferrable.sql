-- +goose Up
-- A reconcile defers the URL check to its commit, so two managed resources can swap their URLs.
ALTER TABLE resources
    DROP CONSTRAINT resources_url_unique,
    ADD CONSTRAINT resources_url_unique UNIQUE (host, path_prefix) DEFERRABLE INITIALLY IMMEDIATE;

-- +goose Down
ALTER TABLE resources
    DROP CONSTRAINT resources_url_unique,
    ADD CONSTRAINT resources_url_unique UNIQUE (host, path_prefix);
