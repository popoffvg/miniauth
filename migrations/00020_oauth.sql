-- +goose Up
-- An OAuth client is an MCP client that an admin registered. It is a public client:
-- it has no secret and proves each code exchange with PKCE.
-- An http redirect URI is on a loopback host and matches on any port.
CREATE TABLE oauth_clients (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    redirect_uris text[] NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT oauth_clients_name CHECK (name <> '' AND char_length(name) <= 64),
    CONSTRAINT oauth_clients_redirect_uris CHECK (cardinality(redirect_uris) > 0)
);

-- A consent is the approval of one user for one client to reach one resource.
-- resource is a URL prefix in the token scope form. One active consent exists per user, client, and resource.
CREATE TABLE oauth_consents (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id),
    client_id uuid NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    resource text NOT NULL,
    created_at timestamptz NOT NULL,
    revoked_at timestamptz
);

CREATE UNIQUE INDEX oauth_consents_active_idx ON oauth_consents (user_id, client_id, resource)
    WHERE revoked_at IS NULL;
CREATE INDEX oauth_consents_client_id_idx ON oauth_consents (client_id);

-- code_hash is the SHA-256 of the authorization code. The code is never stored.
-- challenge is the S256 PKCE challenge. used_at is set once, by the exchange.
CREATE TABLE oauth_codes (
    code_hash bytea PRIMARY KEY,
    consent_id uuid NOT NULL REFERENCES oauth_consents (id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    challenge text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    CONSTRAINT oauth_codes_code_hash_len CHECK (octet_length(code_hash) = 32),
    CONSTRAINT oauth_codes_expiry CHECK (expires_at > created_at)
);

CREATE INDEX oauth_codes_consent_id_idx ON oauth_codes (consent_id);

-- secret_hash is the SHA-256 of the refresh token. used_at is set once, by the rotation.
-- A refresh token that comes back after used_at ends its consent.
CREATE TABLE oauth_refresh_tokens (
    secret_hash bytea PRIMARY KEY,
    consent_id uuid NOT NULL REFERENCES oauth_consents (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    CONSTRAINT oauth_refresh_tokens_secret_hash_len CHECK (octet_length(secret_hash) = 32),
    CONSTRAINT oauth_refresh_tokens_expiry CHECK (expires_at > created_at)
);

CREATE INDEX oauth_refresh_tokens_consent_id_idx ON oauth_refresh_tokens (consent_id);

-- An access token that the token endpoint issued. Its row is in access_tokens,
-- so /auth/check checks it like a personal access token. The token page does not list it.
CREATE TABLE oauth_access_tokens (
    token_id uuid PRIMARY KEY REFERENCES access_tokens (id) ON DELETE CASCADE,
    consent_id uuid NOT NULL REFERENCES oauth_consents (id) ON DELETE CASCADE
);

CREATE INDEX oauth_access_tokens_consent_id_idx ON oauth_access_tokens (consent_id);

-- +goose Down
DROP TABLE oauth_access_tokens;
DROP TABLE oauth_refresh_tokens;
DROP TABLE oauth_codes;
DROP TABLE oauth_consents;
DROP TABLE oauth_clients;
