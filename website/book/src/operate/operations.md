<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Operations and health

FerroSMART is one binary with a few commands, health routes for an
orchestrator, and all of its state in PostgreSQL, so running it is mostly
running a database well.

## The commands

| Command | What it does |
|---|---|
| `ferrosmart serve` | Runs the server; the image's default command |
| `ferrosmart config check` | Reads the configuration, prints it with every secret masked, and exits non-zero naming the first key FerroSMART cannot run with |
| `ferrosmart healthcheck` | Asks the server on loopback for `GET /health/readiness` and exits 0 only on `200`; the image's `HEALTHCHECK` |
| `ferrosmart client apply <file>...` | Writes each file's client document to the registry, creating the client or replacing the one with its `client_id`, each change with its audit record ([the client registry](../configure/clients.md#the-client-registry)) |
| `ferrosmart client secret <client_id>` | Issues a confidential client that authenticates with a secret a new one, stores its Argon2id hash, records the change and prints the secret once (RFC 7591 §3.2.1) |
| `ferrosmart subject --upstream <name> --sub <sub>` | Prints the FerroSMART `sub` of the person whose subject at the provider `<name>` is `<sub>`: the identifier a resource server binds the person by |
| `ferrosmart upstream registration <name>` | Prints what the provider `<name>` must be configured with: the redirect and logout URIs, the client authentication with its JWK Set URL, the scopes, the claims and the roles |

Each takes `--config <file>` and `--set key=value`
([configuration](../configure/configuration.md)). `subject` and `upstream
registration` read the configuration alone, with no key file, secret or
database, so they run on any host that has it.

FerroSMART derives a person's `sub` from the provider's issuer exactly as
configured and the person's `sub` there (a SHA-256, base64url), so the
same person at two providers, or at an issuer written with and without a
trailing slash, has two subjects. Take the value `ferrosmart subject`
prints; a person sees their own on the management page at
`{issuer}/manage`.

## Health

| Path | Answers |
|---|---|
| `/health/liveness` | `200` while the process serves |
| `/health/readiness` | `200` while FerroSMART takes requests and its database answers; withdrawn while it drains |
| `/health` | The summary of every indicator |
| `/health/info` | The build information |

The health routes sit under `[server] base_path`, as every route does, so
with an issuer at the host's root they are `/health/...`.

## Replicas and the database

Every piece of state is in PostgreSQL: clients, codes, grants, refresh and
access token records, launches, consents, upstream sessions, the
assertion and launch ids already used, and the audit records. Any replica
answers any request, so run as many as the load needs behind one issuer
URL, each with the same configuration and the same key files.

Codes, refresh tokens and launch values are stored as their SHA-256,
never as themselves. Migrations ship in the binary and run at start under a
PostgreSQL advisory lock, so replicas starting together migrate once. Every
minute each replica deletes the expired assertion ids, token records and
launches, and the grants an hour old with no token left.

Back up the database as you back up any PostgreSQL. Losing it ends every
grant: people log in again and apps receive new tokens.

## Stopping and restarting

On `SIGTERM` FerroSMART withdraws readiness, waits `[server] drain_delay`
so a load balancer stops sending requests, closes the listener, and lets
the requests in flight finish within `shutdown_timeout`. Restart replicas
one at a time, for a configuration change or a [key rotation](keys.md).

## Logs

FerroSMART logs to standard output, readable on a terminal and JSON
otherwise (`[telemetry] format`), at the level `[telemetry] filter` or
`RUST_LOG` sets. A log line names a client by `client_id` and a person by
`sub`, and carries no token, code, secret, assertion or claim beyond
those.

## The limits

`[server]` bounds every request: its time, the size of its body, the
requests served at once and, with `caller_rate`, the rate one caller may
send. A request past a limit is refused with `408`, `413`, `429` or `503`
and never queued without bound.
