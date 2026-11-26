<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Upgrade FerroSMART

**For:** operators moving a running deployment to a newer release.

FerroSMART ships its database schema inside the binary and applies it at
start, under a PostgreSQL advisory lock, so replicas that start together
migrate once. An upgrade is a new image and a rolling restart, with one
exception below.

## Before you start

1. **Read the release notes** of every release between yours and the new
   one ([release notes](../changelog.md)). An entry marked "Breaking" says
   what a deployment changes: a configuration key, a client document
   member, a schema change.
2. **Check the configuration** with the new binary:
   `ferrosmart --config ferrosmart.toml config check`. Every table refuses a
   key it does not know, so a removed key fails here and not in
   production.
3. **Back up the database.**

## Roll the replicas

Pin the new version, or better its digest, and restart the replicas one
at a time. The first one to start applies the schema; the others find it
applied. Each replica withdraws readiness on `SIGTERM` and lets the
requests in flight finish, so a load balancer that reads
`/health/readiness` sends no request to a replica that is stopping
([operate and monitor](operations.md#stopping-and-restarting)).

## When the schema changed

The schema is a set of baseline files, one per area, and a release changes
those files in place. FerroSMART refuses to start against a database whose
applied migrations changed since they were applied: the migration step
fails at start and the replica exits. The release notes say when a
release does this, as an entry marked "Breaking".

For such a release, create the database fresh:

1. Stop every replica.
2. Drop and create the database.
3. Start one replica of the new release, which creates the schema.
4. Apply the client documents again with `ferrosmart client apply`.
5. Start the other replicas.

Every grant, consent and audit record of the old database is gone, so
every person signs in again and every app gets new tokens. Forward the
audit records to an Audit Record Repository
(`[ferrosmart.audit.feed]`) before the upgrade if you must keep them.

## Rolling back

Run the previous image against the database the previous release created.
A database the new release created fresh is not readable by the previous
one, which is why the backup comes first.
