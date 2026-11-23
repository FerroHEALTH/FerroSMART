-- SPDX-FileCopyrightText: Cadasto B.V.
-- SPDX-License-Identifier: BUSL-1.1
--
-- The User Access Brands Bundle a replica last started with (docs/
-- architecture.md section 13.9): one row for its contents and one per
-- resource, with when each last changed.

CREATE TABLE brand_bundle (
    resource text PRIMARY KEY,
    digest text NOT NULL,
    changed_at timestamptz NOT NULL
);
