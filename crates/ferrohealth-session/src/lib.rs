// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The sign-in and the session of a FerroHEALTH operator console.
//!
//! An operator signs in at the deployment's OpenID Provider with the
//! authorization code flow and PKCE, through the relying party of
//! `ferrohealth-smart` (`ferrohealth_smart::oidc::RelyingParty`), which keeps
//! no state of its own. This crate keeps the state between the redirect and
//! the callback, and the session once the sign-in completes:
//!
//! - [`config`]: the `[oidc]` and `[session]` sections every console embeds,
//!   read with `deny_unknown_fields`, each secret through
//!   `ferrohealth-secret`'s `<key>` / `<key>_file` rule;
//! - [`sessions::Sessions`]: the store, in the console's process, with an
//!   opaque id in the cookie; a restart signs every operator out, and a
//!   console that runs as several instances routes each session to one of
//!   them (sticky sessions);
//! - [`clock`]: the clock every lifetime is counted on, the wall clock by
//!   default, with `clock::ManualClock` (feature `test-clock`) for a
//!   console's tests;
//! - [`lifetime`]: the idle and the absolute lifetime, both counted from
//!   times the session carries, the absolute one from the sign-in time, and
//!   what is left as FerroUI's session watch reads it;
//! - [`sessions::Sessions::keep_fresh`]: the refresh of an access token before
//!   it expires;
//! - [`justification`]: a justification the operator stated for one object,
//!   kept with the session until it ends;
//! - `routes` (feature `axum`): `GET /login`, `GET /auth/callback`,
//!   `POST /logout` and `GET`/`POST /session`, and the middleware that hands
//!   every page what its request holds.
//!
//! No token, key, password, session id, `state`, `nonce` or verifier reaches a
//! log line, a `Debug` rendering or an error message. No specification
//! governs the session store, its lifetimes or the watch route: our own
//! design, held to the OWASP Session Management Cheat Sheet (idle and
//! absolute timeouts).

pub mod clock;
pub mod config;
pub mod cookies;
pub mod justification;
pub mod lifetime;
pub mod paths;
pub mod record;
pub mod refresh;
pub mod resource;
pub mod return_path;
#[cfg(feature = "axum")]
pub mod routes;
pub mod sessions;

mod store;
