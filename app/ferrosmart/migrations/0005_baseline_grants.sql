-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- What a person or a client was granted (docs/architecture.md section 13.9):
-- each grant, the access tokens issued on it or on a client's own grant, and
-- the rotating refresh tokens, kept as SHA-256 with their predecessor for
-- reuse detection (RFC 9700 section 4.14.2). grant is an SQL keyword, so
-- the table takes RFC 6749 section 1.3's full name.

CREATE TABLE authorization_grant (
    id text PRIMARY KEY,
    client_id text NOT NULL,
    subject text NOT NULL,
    fhir_user text,
    audience text NOT NULL,
    scope text NOT NULL,
    context jsonb NOT NULL DEFAULT '{}' CONSTRAINT authorization_grant_context_check
        CHECK (jsonb_typeof(context) = 'object'),
    auth_time bigint,
    access text CONSTRAINT authorization_grant_access_check
        CHECK (access IN ('offline', 'online')),
    upstream_session text REFERENCES upstream_session (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    roles text[] NOT NULL DEFAULT '{}',
    basis text CONSTRAINT authorization_grant_basis_check
        CHECK (basis IN ('page', 'remembered', 'administrative', 'first-party')),
    acr text CONSTRAINT authorization_grant_acr_check
        CHECK (acr IN ('low', 'substantial', 'high')),
    -- The DPoP key a public client's refresh tokens are bound to (RFC 9449 §5).
    dpop_jkt text
);
CREATE INDEX authorization_grant_first_party ON authorization_grant (client_id)
    WHERE basis = 'first-party';
CREATE INDEX authorization_grant_client ON authorization_grant (client_id) WHERE revoked_at IS NULL;
CREATE INDEX authorization_grant_session ON authorization_grant (upstream_session);
CREATE INDEX authorization_grant_subject ON authorization_grant (subject, client_id);

CREATE TABLE access_token (
    jti text PRIMARY KEY,
    client_id text NOT NULL,
    subject text NOT NULL,
    audience text NOT NULL,
    scope text NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    code_hash text,
    grant_id text REFERENCES authorization_grant (id) ON DELETE CASCADE
);
CREATE INDEX access_token_client ON access_token (client_id) WHERE revoked_at IS NULL;
CREATE INDEX access_token_code_hash ON access_token (code_hash);
CREATE INDEX access_token_expires_at ON access_token (expires_at);
CREATE INDEX access_token_grant ON access_token (grant_id);

CREATE TABLE refresh_token (
    token_hash text PRIMARY KEY,
    grant_id text NOT NULL REFERENCES authorization_grant (id) ON DELETE CASCADE,
    predecessor text,
    issued_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    revoked_at timestamptz,
    successor_salt text
);
CREATE INDEX refresh_token_expires_at ON refresh_token (expires_at);
CREATE INDEX refresh_token_grant ON refresh_token (grant_id);
