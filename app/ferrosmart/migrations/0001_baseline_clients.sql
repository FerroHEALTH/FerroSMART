-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- The client registry (docs/architecture.md section 13.9): each client as
-- an administrator (13.27) or its own registration (RFC 7591, 13.6 item 14)
-- wrote it. A secret is kept only as its Argon2id hash.

CREATE TABLE client (
    client_id text PRIMARY KEY,
    client_name text NOT NULL,
    token_endpoint_auth_method text NOT NULL CONSTRAINT client_token_endpoint_auth_method_check
        CHECK (token_endpoint_auth_method IN
            ('none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt',
             'tls_client_auth', 'self_signed_tls_client_auth')),
    jwks_uri text,
    jwks jsonb,
    redirect_uris text[] NOT NULL DEFAULT '{}',
    scope text[] NOT NULL DEFAULT '{}',
    grant_types text[] NOT NULL DEFAULT '{}',
    registered_by text NOT NULL CONSTRAINT client_registered_by_check
        CHECK (registered_by IN ('admin', 'self')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    secret_hash text,
    -- RFC 7592 section 3, the registration access token, as its SHA-256.
    registration_token_hash text,
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
    default_acr_values text[] NOT NULL DEFAULT '{}',
    require_pushed_authorization_requests boolean NOT NULL DEFAULT false,
    dpop_bound_access_tokens boolean NOT NULL DEFAULT false,
    tls_client_certificate_bound_access_tokens boolean NOT NULL DEFAULT false,
    -- OpenID Connect Dynamic Client Registration 1.0 section 2; it signs the
    -- client's access tokens too.
    id_token_signed_response_alg text NOT NULL DEFAULT 'RS256'
        CONSTRAINT client_id_token_signed_response_alg_check
        CHECK (id_token_signed_response_alg IN ('RS256', 'PS256', 'ES256', 'EdDSA', 'ML-DSA-65')),
    -- RFC 8705 section 2.1.2, the one member that names the subject of a
    -- tls_client_auth client's certificate, and its value.
    tls_client_auth_member text CONSTRAINT client_tls_client_auth_member_check
        CHECK (tls_client_auth_member IN ('tls_client_auth_subject_dn', 'tls_client_auth_san_dns',
            'tls_client_auth_san_uri', 'tls_client_auth_san_ip', 'tls_client_auth_san_email')),
    tls_client_auth_value text,
    -- A private_key_jwt or self_signed_tls_client_auth client has a JWK Set by
    -- URL or by value; no other has one.
    CONSTRAINT client_keys_check
        CHECK ((token_endpoint_auth_method IN ('private_key_jwt', 'self_signed_tls_client_auth'))
            = ((jwks_uri IS NULL) <> (jwks IS NULL))),
    CONSTRAINT client_tls_subject_check
        CHECK ((token_endpoint_auth_method = 'tls_client_auth')
            = (tls_client_auth_member IS NOT NULL AND tls_client_auth_value IS NOT NULL)),
    CONSTRAINT client_tls_subject_pair_check
        CHECK ((tls_client_auth_member IS NULL) = (tls_client_auth_value IS NULL)),
    CONSTRAINT client_one_key_set_check CHECK (jwks_uri IS NULL OR jwks IS NULL),
    CONSTRAINT client_secret_check
        CHECK ((token_endpoint_auth_method IN ('client_secret_basic', 'client_secret_post'))
            = (secret_hash IS NOT NULL)),
    -- RFC 7591 section 5: an app's own registration is self-asserted.
    CONSTRAINT client_self_not_first_party CHECK (registered_by <> 'self' OR NOT first_party)
);
