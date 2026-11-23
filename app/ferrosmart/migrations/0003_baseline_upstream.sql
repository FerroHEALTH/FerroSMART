-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- The logins at the upstream providers (docs/architecture.md sections 13.9,
-- 13.25 and 13.26): each upstream session a grant may live in, a logout
-- waiting for the person's answer, and the SAML assertions already admitted.

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
