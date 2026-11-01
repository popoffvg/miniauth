-- +goose Up
-- A group is stored before a membership or a grant names it.
-- A built-in group always exists: the service refuses to delete it.
CREATE TABLE groups (
    name text PRIMARY KEY,
    built_in boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT groups_name CHECK (
        name <> ''
        AND char_length(name) <= 64
        AND name = lower(name)
    )
);

INSERT INTO groups (name, built_in) VALUES ('admins', true), ('users', true);

-- The group admin is now admins. A user or a resource in both keeps one row.
INSERT INTO group_memberships (user_id, name)
SELECT user_id, 'admins' FROM group_memberships WHERE name = 'admin'
ON CONFLICT (user_id, name) DO NOTHING;
DELETE FROM group_memberships WHERE name = 'admin';
DELETE FROM access_grants AS old
WHERE old.group_name = 'admin'
    AND EXISTS (
        SELECT 1 FROM access_grants AS kept
        WHERE kept.group_name = 'admins' AND kept.resource_name = old.resource_name
    );
UPDATE access_grants SET group_name = 'admins' WHERE group_name = 'admin';

INSERT INTO groups (name)
SELECT name FROM group_memberships
UNION
SELECT group_name FROM access_grants WHERE group_name IS NOT NULL
ON CONFLICT (name) DO NOTHING;

INSERT INTO group_memberships (user_id, name)
SELECT id, 'users' FROM users
ON CONFLICT (user_id, name) DO NOTHING;

ALTER TABLE group_memberships
ADD CONSTRAINT group_memberships_name_fkey
FOREIGN KEY (name) REFERENCES groups (name) ON DELETE CASCADE;

ALTER TABLE access_grants
ADD CONSTRAINT access_grants_group_name_fkey
FOREIGN KEY (group_name) REFERENCES groups (name) ON DELETE CASCADE;

-- managed marks a row that the resources file owns. The start of the process
-- writes and deletes these rows; the panel and the API refuse to change them.
ALTER TABLE resources ADD COLUMN managed boolean NOT NULL DEFAULT false;
ALTER TABLE access_grants ADD COLUMN managed boolean NOT NULL DEFAULT false;
ALTER TABLE access_grants
ADD CONSTRAINT access_grants_managed_group CHECK (NOT managed OR group_name IS NOT NULL);

-- An invite now names a group. An open invite named a resource, so it is deleted.
-- A used invite keeps its row: its account joined users above.
DELETE FROM invites WHERE used_at IS NULL;
ALTER TABLE invites ADD COLUMN group_name text REFERENCES groups (name) ON DELETE CASCADE;
UPDATE invites SET group_name = 'users';
ALTER TABLE invites ALTER COLUMN group_name SET NOT NULL;
ALTER TABLE invites DROP COLUMN resource_name;

-- +goose Down
DELETE FROM invites;
ALTER TABLE invites ADD COLUMN resource_name text NOT NULL REFERENCES resources (name) ON DELETE CASCADE;
ALTER TABLE invites DROP COLUMN group_name;
ALTER TABLE access_grants DROP CONSTRAINT access_grants_managed_group;
ALTER TABLE access_grants DROP COLUMN managed;
ALTER TABLE resources DROP COLUMN managed;
ALTER TABLE access_grants DROP CONSTRAINT access_grants_group_name_fkey;
ALTER TABLE group_memberships DROP CONSTRAINT group_memberships_name_fkey;
DELETE FROM group_memberships WHERE name = 'users';
UPDATE group_memberships SET name = 'admin' WHERE name = 'admins';
UPDATE access_grants SET group_name = 'admin' WHERE group_name = 'admins';
DROP TABLE groups;
