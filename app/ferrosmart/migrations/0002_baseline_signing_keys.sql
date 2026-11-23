-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- Where each token signing key stands in its rotation (docs/architecture.md
-- section 13.11), which every replica reads so they sign with the same key.
-- The private key stays in the files the configuration names.

CREATE TABLE signing_key (
    kid text PRIMARY KEY,
    state text NOT NULL CONSTRAINT signing_key_state_check
        CHECK (state IN ('next', 'active', 'retiring', 'retired')),
    published_at timestamptz NOT NULL,
    active_at timestamptz,
    retiring_at timestamptz,
    retired_at timestamptz
);
CREATE UNIQUE INDEX signing_key_one_active ON signing_key ((true)) WHERE state = 'active';
CREATE UNIQUE INDEX signing_key_one_next ON signing_key ((true)) WHERE state = 'next';
