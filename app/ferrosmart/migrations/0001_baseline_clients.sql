-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- The client registry (docs/architecture.md section 13.9): each client as
-- an administrator (13.27) or its own registration (RFC 7591, 13.6 item 14)
-- wrote it. A secret is kept only as its Argon2id hash.

CREATE TABLE client (
    client_id text PRIMARY KEY,
    name text NOT NULL,
    kind text NOT NULL CONSTRAINT client_kind_check
        CHECK (kind IN ('public', 'confidential_asymmetric', 'confidential_symmetric')),
    jwks_uri text,
    jwks jsonb,
    redirect_uris text[] NOT NULL DEFAULT '{}',
    scopes text[] NOT NULL DEFAULT '{}',
    grant_types text[] NOT NULL DEFAULT '{}',
    registered_by text NOT NULL CONSTRAINT client_registered_by_check
        CHECK (registered_by IN ('admin', 'self')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    secret_hash text,
    approved_scope text[],
    approved_by text,
    approved_at timestamptz,
    launch_uri text CONSTRAINT client_launch_uri_key UNIQUE,
    first_party boolean NOT NULL DEFAULT false,
    client_uri text,
    logo_uri text,
    policy_uri text,
    tos_uri text,
    post_logout_redirect_uris text[] NOT NULL DEFAULT '{}',
    upstreams text[] NOT NULL DEFAULT '{}',
    disabled_at timestamptz,
    resources text[] NOT NULL DEFAULT '{}',
    assurance_minimum text CONSTRAINT client_assurance_minimum_check
        CHECK (assurance_minimum IN ('low', 'substantial', 'high')),
    -- An asymmetric client has a JWK Set by URL or by value; a public one has none.
    CONSTRAINT client_check
        CHECK (kind <> 'confidential_asymmetric' OR ((jwks_uri IS NULL) <> (jwks IS NULL))),
    CONSTRAINT client_check1
        CHECK (kind <> 'public' OR (jwks_uri IS NULL AND jwks IS NULL)),
    CONSTRAINT client_symmetric_keys_check
        CHECK (kind <> 'confidential_symmetric' OR (jwks_uri IS NULL AND jwks IS NULL)),
    CONSTRAINT client_secret_check
        CHECK ((kind = 'confidential_symmetric') = (secret_hash IS NOT NULL)),
    -- The organisation approval is whole or absent, and the first-party mark needs it.
    CONSTRAINT client_approval_check
        CHECK ((approved_scope IS NULL) = (approved_by IS NULL)
            AND (approved_by IS NULL) = (approved_at IS NULL)),
    CONSTRAINT client_first_party_check CHECK (NOT first_party OR approved_at IS NOT NULL),
    -- RFC 7591 section 5: an app's own registration is self-asserted.
    CONSTRAINT client_self_unapproved
        CHECK (registered_by <> 'self' OR (approved_scope IS NULL AND NOT first_party))
);
