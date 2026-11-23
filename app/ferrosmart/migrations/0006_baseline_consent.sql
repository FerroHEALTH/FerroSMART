-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- The consents a person chose to remember, per client and resource server
-- (docs/architecture.md section 13.6 item 6).

CREATE TABLE consent (
    subject text NOT NULL,
    client_id text NOT NULL,
    scope text NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    audience text NOT NULL,
    PRIMARY KEY (subject, client_id, audience)
);
