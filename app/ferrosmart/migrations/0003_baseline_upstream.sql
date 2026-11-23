-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- The logins at the upstream providers (docs/architecture.md sections 13.9,
-- 13.25, 13.26 and 13.32): each upstream session a grant may live in, a logout
-- waiting for the person's answer, the SAML assertions already admitted,
-- and the EUDI Wallet's answers.

CREATE TABLE upstream_session (
    id text PRIMARY KEY,
    issuer text NOT NULL,
    subject text NOT NULL,
    sid text,
    last_seen timestamptz NOT NULL DEFAULT now(),
    ended_at timestamptz
);
CREATE INDEX upstream_session_sid ON upstream_session (issuer, sid);
CREATE INDEX upstream_session_subject ON upstream_session (issuer, subject);

CREATE TABLE pending_logout (
    id text PRIMARY KEY,
    client_id text,
    subject text,
    redirect_uri text,
    state text,
    form_token text NOT NULL,
    upstream_state text NOT NULL,
    expires_at timestamptz NOT NULL,
    upstream_provider text
);
CREATE INDEX pending_logout_upstream_state ON pending_logout (upstream_state);

-- saml-profiles section 4.1.4.5: an assertion is admitted once, until its
-- bearer confirmation's NotOnOrAfter.
CREATE TABLE seen_saml_assertion (
    identity_provider text NOT NULL,
    assertion_id text NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (identity_provider, assertion_id)
);
CREATE INDEX seen_saml_assertion_expires_at ON seen_saml_assertion (expires_at);

-- An EUDI Wallet's accepted presentation (section 13.32), kept under its
-- request's nonce so the nonce is answered once (OpenID4VP 1.0 section
-- 14.1.2), and taken once by the browser that brings the response code back
-- (section 14.2).
CREATE TABLE wallet_answer (
    nonce text PRIMARY KEY,
    pending_id text NOT NULL,
    response_code_hash text NOT NULL CONSTRAINT wallet_answer_response_code_hash_key UNIQUE,
    identity jsonb NOT NULL,
    taken_at timestamptz,
    expires_at timestamptz NOT NULL
);
CREATE INDEX wallet_answer_expires_at ON wallet_answer (expires_at);
