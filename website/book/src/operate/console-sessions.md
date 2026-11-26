<!-- SPDX-FileCopyrightText: Cadasto B.V. -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Run a console's sessions

**For:** operators of a FerroHEALTH product's operator console, the web
interface whose sign-in comes from the `ferrohealth-session` crate this
repository publishes. FerroSMART itself keeps no console session; this
page is about the consoles of the products that use the crate.

An operator signs in to a console at the deployment's OpenID Provider with
the authorization code flow and PKCE. The console then keeps a session:
the operator's tokens, their refresh token and their stated justifications
stay in the console's process, and the browser holds only an opaque id in
a cookie.

## The store is memory

`[session] store = "memory"` is the only store, and the default. It has
three consequences for how you run a console:

- **One instance** is the deployment the store is made for: every session
  is in that process.
- **A restart signs every operator out.** Each signs in again at the
  provider; nothing else is lost, since a console keeps no other state in
  its sessions.
- **Several replicas need sticky sessions.** Route each session to the
  replica that holds it, by session affinity at the load balancer or
  ingress: on a cookie the balancer sets, or on the console's session
  cookie, `__Host-<console>_session` (or `<console>_session` with
  `secure_cookie = false`). A request that reaches another replica finds no
  session and is sent to sign in, and a replica that stops signs out the
  operators routed to it.

No shared store is offered.

## The keys

| Key | Default | What it is |
|---|---|---|
| `store` | `memory` | Where sessions are kept; `memory` is the only value |
| `secure_cookie` | `true` | Whether the cookies carry `Secure` and with it the `__Host-` prefix; `false` drops both, for a console served over plain `http` |
| `sign_in_timeout` | `5min` | How long a pending sign-in waits for the provider's redirect back |
| `max_sign_ins` | 1000 | How many pending sign-ins are held; past it the oldest is dropped |
| `idle_timeout` | `30min` | How long a session lives with no activity |
| `absolute_timeout` | `12h` | How long a session lives from its sign-in, whatever the activity; at least `idle_timeout` |
| `max_sessions` | 10000 | How many sessions are held; past it a new sign-in is refused |

A configuration that still names `store = "sealed"`, `key` or `key_file`
is refused when it loads, with a message that names `memory`. Delete those
keys.

The crate's own documentation, with the `[oidc]` section, is on
[docs.rs](https://docs.rs/ferrohealth-session).
