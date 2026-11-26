<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Deploy for production

**For:** operators who take FerroSMART past the quickstart, onto a network
other machines reach.

The quickstart binds loopback and speaks plain `http`. A deployment serves
`https` on a name of its own, runs as many replicas as the load needs, and
keeps its state in a PostgreSQL you operate.

## The issuer

`[ferrosmart] issuer` is the URL every app, resource server and identity
provider reaches FerroSMART by, and every document repeats it exactly
(RFC 8414 §2). Choose it once: every token names it as `iss`, and resource
servers trust FerroSMART by it.

- It is `https`; `http` is accepted only on a loopback host.
- Its path is `[server] base_path`. With an issuer of
  `https://smart.example.org/auth`, set `base_path = "/auth"`, and every
  route, the health routes included, is served under `/auth`.

## TLS

Terminate TLS in one of two places:

- **At a reverse proxy.** The listener speaks plain HTTP on the private
  network, and the proxy forwards to it. Name the proxy's addresses in
  `[server] trusted_proxies` (an address or a CIDR block each), so the
  client address of a request, which the audit records and `caller_rate`
  read, is the one the proxy forwarded and not the proxy's own.
  `forwarded_header` picks the header the proxy writes: `forwarded`
  (RFC 7239) or `x-forwarded-for`.
- **At FerroSMART.** `[server.tls]` names `certificate_file` and
  `key_file`. For tokens bound to a client's certificate (RFC 8705), set
  `client_auth` to `optional` or `required` and name the CA in
  `client_ca_file`; the discovery documents then advertise
  `tls_client_certificate_bound_access_tokens`.

## The database

FerroSMART needs PostgreSQL 19 or newer and refuses an older server at
start. Give it its own database and a role that owns it, and pass the
connection URL as a file (`[ferrosmart.database] url_file`).
`max_connections` (16 by default) is per replica, so size PostgreSQL's
`max_connections` for every replica together.

Back the database up as any PostgreSQL. It holds every client, grant and
consent: losing it signs every person out and leaves every app to
register again.

## Replicas

Every piece of state is in PostgreSQL, so any replica answers any request
and no session affinity is needed. Run each replica with:

- the same configuration file and environment;
- the same key files, listed in the same order (`[ferrosmart.keys]`); a
  replica without the next key never makes it sign
  ([rotate keys](keys.md));
- the same issuer behind one load balancer.

The load balancer reads `GET {base_path}/health/readiness`, which answers
`200` while the replica takes requests and its database answers. On
`SIGTERM` a replica withdraws readiness first, waits `[server]
drain_delay`, then closes; set `drain_delay` to at least the balancer's
check interval so no request reaches a closing replica.

## Before you go live

- `ferrosmart config check` passes on the production configuration.
- Each identity provider is registered with what
  `ferrosmart upstream registration <name>` prints.
- The administrator's client exists (`ferrosmart client apply`), and each
  app is registered with the `resources` it may reach.
- `[ferrosmart] assurance_minimum` and each provider's
  `[ferrosmart.upstream.assurance]` say what a login must be worth.
- The audit records reach your Audit Record Repository, or someone reads
  `GET {issuer}/audit` ([audit records](audit.md)).
