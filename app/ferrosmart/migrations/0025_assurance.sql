-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- The eIDAS level of assurance of a person's login (docs/architecture.md
-- section 13.28): the level a request asks for, the level the login
-- reached, carried from the login to the code and the grant so every token
-- issued on it says it as acr (RFC 9068 section 2.2.1), and the minimum a
-- client holds its people's logins to.

ALTER TABLE pending_authorization
    ADD COLUMN asked_acr text CHECK (asked_acr IN ('low', 'substantial', 'high')),
    ADD COLUMN acr text CHECK (acr IN ('low', 'substantial', 'high'));
ALTER TABLE authorization_code
    ADD COLUMN acr text CHECK (acr IN ('low', 'substantial', 'high'));
ALTER TABLE authorization_grant
    ADD COLUMN acr text CHECK (acr IN ('low', 'substantial', 'high'));
ALTER TABLE client
    ADD COLUMN assurance_minimum text CHECK (assurance_minimum IN ('low', 'substantial', 'high'));
