// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The shared SMART App Launch 2.x and OAuth 2.0 resource-server crate of the
//! FerroHEALTH products.
//!
//! This crate is a library, never an authorization server: it issues no token
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
//!   no scope. Behind the `openehr` feature, `openehr` enforces the SMART
//!   on openEHR grammar beside it, parsed by `openehr::smart_scopes`: the
//!   `template-`, `composition-` and `aql-` families with their patterns,
//!   and the `ehrId` of the launch context. The product's route table
//!   declares which grammar each route is checked against.
//! - [`basic`] and [`client`]: machine-to-machine authentication in exactly
//!   two modes, HTTP Basic (RFC 7617, verified against Argon2id hashes and
//!   sent outgoing) and the OAuth 2.0 client credentials grant (RFC 6749 §4.4,
//!   a token client with a cache and one renewal on a `401`, authenticating
//!   with a secret or a `private_key_jwt` assertion). A static bearer token
//!   or an API key is not a mode.
//! - [`kind`] and [`profile`]: who stands behind a token, read from its
//!   standard claims: a system, or a user named by the type of their
//!   `fhirUser`, with the patient context and the RFC 8693 actor beside
//!   them; a `federation` issuer's tokens name another party's professional
//!   or organisation. A token that reads as none is refused naming why.
//! - [`party`]: the party a person's login belongs to, looked up on every
//!   request through a source the product supplies, with one typed outcome.
//! - [`assurance`]: the assurance level of the authentication behind a
//!   token, with the RFC 9470 step-up refusal below a minimum.
//! - [`sender`]: sender-constrained tokens, bound by a `DPoP` proof (RFC 9449)
//!   or by the client certificate of a mutual-TLS connection (RFC 8705 §3),
//!   checked per issuer, with the proof replay store the product supplies.
//! - [`roles`]: the roles a caller holds, read from the claims RFC 9068
//!   §2.2.3.1 names or granted to a Basic user, which a route requirement
//!   checks beside its scopes.
//! - [`audit`]: one audit line per request, which carries the principal, the
//!   client, the scheme, the issuer, the method, the route, what was
//!   addressed, the interaction, the status and the duration, and never the
//!   token or any content.
//!
//! [`config`] holds the `[auth]` and `[<lane>.credentials]` sections every
//! product embeds. The `axum` feature adds `guard`, the `tower::Layer` that
//! runs the credential check, the scope check and the audit line in front of
//! every route, and `extract`, the extractor of the caller the layer
//! admitted. The core stays framework-neutral. The HTTP fetchers (the
//! issuer's metadata, the key set over its `jwks_uri`, and the client
//! credentials token client) sit behind the default `fetch` feature; without
//! it the crate links no HTTP client and reads a key set from a file. The
//! `oidc` feature adds `oidc`, the OpenID Connect relying-party client an
//! operator console signs its operator in with. The `xml` feature adds `xml`, the bounded
//! XML reader and Exclusive XML Canonicalization an XML signature check
//! reads its document through.
//!
//! The `openehr-scopes` feature builds `openehr::smart_scopes`, the SMART on
//! openEHR scope grammar, which depends on nothing. For the browser
//! (`wasm32-unknown-unknown`) the grammar is the whole crate: the resource
//! server is left out with its dependencies, so a browser client parses
//! scopes with the parser the resource server enforces them with.

#![doc(test(attr(deny(warnings))))]

#[cfg(resource_server)]
pub mod assurance;
#[cfg(resource_server)]
pub mod audit;
#[cfg(resource_server)]
pub mod basic;
#[cfg(resource_server)]
pub mod client;
#[cfg(resource_server)]
pub mod config;
#[cfg(all(feature = "axum", resource_server))]
pub mod extract;
#[cfg(resource_server)]
pub mod federation;
#[cfg(all(feature = "axum", resource_server))]
pub mod guard;
#[cfg(resource_server)]
#[cfg(resource_server)]
pub mod json;
#[cfg(resource_server)]
mod jws;
#[cfg(resource_server)]
pub mod kind;
#[cfg(resource_server)]
pub mod metadata;
#[cfg(all(feature = "oidc", resource_server))]
pub mod oidc;
#[cfg(feature = "openehr-scopes")]
pub mod openehr;
#[cfg(resource_server)]
pub mod party;
#[cfg(resource_server)]
pub mod profile;
#[cfg(resource_server)]
pub mod refusal;
#[cfg(resource_server)]
pub mod resource;
#[cfg(resource_server)]
pub mod roles;
#[cfg(resource_server)]
pub mod scope;
#[cfg(resource_server)]
pub mod sender;
#[cfg(resource_server)]
pub mod uri;
#[cfg(resource_server)]
pub mod usage;
#[cfg(all(feature = "xml", resource_server))]
pub mod xml;

// The Rust examples of this crate's README and the repository's README
// compile as doctests, with the features they guard a router with.
#[cfg(all(doctest, feature = "axum", feature = "fetch"))]
#[doc = include_str!("../README.md")]
struct CrateReadme;
#[cfg(all(doctest, feature = "axum", feature = "fetch"))]
#[doc = include_str!("../../../README.md")]
struct RootReadme;
