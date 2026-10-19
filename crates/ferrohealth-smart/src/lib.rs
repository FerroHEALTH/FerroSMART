// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The shared SMART App Launch 2.x and OAuth 2.0 resource-server crate of the
//! FerroHEALTH products.
//!
//! FerroSMART is a library, never an authorization server: it issues no token
//! and holds no key that signs one. Each deployment points it at its own
//! standards-compliant authorization server, and the crate does four things
//! every product needs:
//!
//! - [`resource`]: the resource-server role. The issuer's metadata is read at
//!   the RFC 8414 §3 location, with `OpenID` Connect Discovery 1.0 §4 as the
//!   fallback ([`metadata`]), its key set is read and read again on a
//!   rotation, and every JWT access token is validated under RFC 9068 (the
//!   signature with an asymmetric algorithm only, `iss`, `aud`, `exp` and
//!   `nbf` within a clock skew). A refused token is one generic `401` that
//!   names no claim ([`refusal`]).
//! - [`scope`]: the SMART App Launch 2.x scopes, `patient/`, `user/` and
//!   `system/` with the `cruds` permissions, and the patient compartment the
//!   token's launch context names; a missing permission is a `403` that names
//!   no scope. Behind the `openehr` feature, [`openehr`] enforces the SMART
//!   on openEHR grammar beside it, parsed by `openehr-sdt`: the
//!   `template-`, `composition-` and `aql-` families with their patterns,
//!   and the `ehrId` of the launch context. The product's route table
//!   declares which grammar each route is checked against.
//! - [`basic`] and [`client`]: machine-to-machine authentication in exactly
//!   two modes, HTTP Basic (RFC 7617, verified against Argon2id hashes and
//!   sent outgoing) and the OAuth 2.0 client credentials grant (RFC 6749 §4.4,
//!   a token client with a cache and one renewal on a `401`, authenticating
//!   with a secret or a `private_key_jwt` assertion). A static bearer token
//!   or an API key is not a mode.
//! - [`audit`]: one audit line per request, which carries the principal, the
//!   client, the scheme, the issuer, the method, the route, the target, the
//!   interaction, the status and the duration, and never the token or any
//!   content.
//!
//! [`config`] holds the `[auth]` and `[<lane>.credentials]` sections every
//! product embeds. The `axum` feature adds [`guard`], the `tower::Layer` that
//! runs the credential check, the scope check and the audit line in front of
//! every route, and [`extract`], the extractor of the caller the layer
//! admitted. The core stays framework-neutral.

#![doc(test(attr(deny(warnings))))]

pub mod audit;
pub mod basic;
pub mod client;
pub mod config;
#[cfg(feature = "axum")]
pub mod extract;
#[cfg(feature = "axum")]
pub mod guard;
pub mod metadata;
#[cfg(feature = "openehr")]
pub mod openehr;
pub mod refusal;
pub mod resource;
pub mod scope;
