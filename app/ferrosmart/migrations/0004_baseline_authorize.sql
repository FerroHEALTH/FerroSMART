-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- An authorization in flight (docs/architecture.md sections 13.6 and 13.9):
-- the validated request through its login, the code it ends in, the EHR
-- launches an app redeems, and the jti of every client assertion and launch
-- JWT until it expires. Codes and launch values are kept only as SHA-256.

CREATE TABLE pending_authorization (
    id text PRIMARY KEY,
    client_id text,
    redirect_uri text NOT NULL,
    scope text NOT NULL,
    state text NOT NULL,
    nonce text,
    code_challenge text NOT NULL,
    audience text NOT NULL,
    upstream_state text NOT NULL CONSTRAINT pending_authorization_upstream_state_key UNIQUE,
    upstream_nonce text NOT NULL,
    upstream_verifier text NOT NULL,
    form_token text NOT NULL,
    subject text,
    fhir_user text,
    display_name text,
    offered_scope text,
    auth_time bigint,
    expires_at timestamptz NOT NULL,
    purpose text NOT NULL DEFAULT 'authorize' CONSTRAINT pending_authorization_purpose_check
        CHECK (purpose IN ('authorize', 'manage')),
    upstream_session text,
    launch_context jsonb,
    roles text[] NOT NULL DEFAULT '{}',
    prompt text NOT NULL DEFAULT '',
    max_age bigint CONSTRAINT pending_authorization_max_age_check CHECK (max_age >= 0),
    ui_locales text,
    reauthenticated boolean NOT NULL DEFAULT false,
    person_claims jsonb,
    upstream_provider text,
    purpose_of_use text,
    asked_acr text CONSTRAINT pending_authorization_asked_acr_check
        CHECK (asked_acr IN ('low', 'substantial', 'high')),
    acr text CONSTRAINT pending_authorization_acr_check
        CHECK (acr IN ('low', 'substantial', 'high'))
);
CREATE INDEX pending_authorization_expires_at ON pending_authorization (expires_at);

CREATE TABLE authorization_code (
    code_hash text PRIMARY KEY,
    client_id text NOT NULL,
    redirect_uri text NOT NULL,
    code_challenge text NOT NULL,
    audience text NOT NULL,
    subject text NOT NULL,
    fhir_user text,
    scope text NOT NULL,
    nonce text,
    auth_time bigint NOT NULL,
    expires_at timestamptz NOT NULL,
    redeemed_at timestamptz,
    upstream_session text,
    launch_context jsonb,
    roles text[] NOT NULL DEFAULT '{}',
    approved_at timestamptz,
    person_claims jsonb,
    acr text CONSTRAINT authorization_code_acr_check
        CHECK (acr IN ('low', 'substantial', 'high'))
);
CREATE INDEX authorization_code_expires_at ON authorization_code (expires_at);

CREATE TABLE launch (
    launch_hash text PRIMARY KEY,
    ehr_client_id text NOT NULL,
    client_id text NOT NULL,
    audience text NOT NULL,
    context jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);
CREATE INDEX launch_expires_at ON launch (expires_at);

-- A jti is accepted once per issuer, until it expires.
CREATE TABLE seen_jti (
    issuer text NOT NULL,
    jti text NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (issuer, jti)
);
CREATE INDEX seen_jti_expires_at ON seen_jti (expires_at);
