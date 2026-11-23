-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- The state of each token signing key (docs/architecture.md section 13.11),
-- which every replica reads so they agree on the key that signs. The
-- private key stays in the files the configuration names.

CREATE TABLE signing_key (
    kid text PRIMARY KEY,
    state text NOT NULL CHECK (state IN ('next', 'active', 'retiring', 'retired')),
    published_at timestamptz NOT NULL,
    active_at timestamptz,
    retiring_at timestamptz,
    retired_at timestamptz
);
CREATE UNIQUE INDEX signing_key_one_active ON signing_key ((true)) WHERE state = 'active';
CREATE UNIQUE INDEX signing_key_one_next ON signing_key ((true)) WHERE state = 'next';
