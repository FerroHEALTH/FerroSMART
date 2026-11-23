---
name: migrations-in-place
description: FerroSMART's schema is a set of per-area baseline migrations changed in place; a schema change edits the baseline file, never adds a numbered file (owner, 2026-11-23)
metadata:
  type: project
---

<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

FerroSMART's schema lives in `app/ferrosmart/migrations/` as a small set of
baseline files, one per area of the schema (clients, signing keys,
upstream logins, authorization in flight, grants and tokens, consent,
audit, brands). Each table is written in its final shape, with its indexes
and constraints beside it. A schema change edits the file of its area in
place. Never add a numbered migration and never layer an ALTER on a CREATE.
Owner, 2026-11-23: "fully rewrite everything because it's a greenfield app,
so in-place changes reduce the amount of migration files ... do not put
everything in one sql file but redesign all these migration files".

**Why:** FerroSMART runs in no production deployment
([[ferrohealth-not-in-production]]), so a chain of incremental files only
records history that no database needs.

**How to apply:** edit the baseline file of the area. sqlx records each
applied file's checksum and refuses to start against a database whose files
changed, so a development or test database is dropped and created fresh
after a schema change. Before the first production deployment the owner
decides whether the baselines freeze.
