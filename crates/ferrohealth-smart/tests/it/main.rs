// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The integration suite: one binary, one module per subject, every upstream
//! a `wiremock` stub and every key generated when the case runs.

#![expect(
    clippy::panic_in_result_fn,
    reason = "a Result-returning test still asserts; a failed assertion is how it fails"
)]
#![expect(
    clippy::expect_used,
    reason = "a test support function fails the case the way a test body does"
)]
#![cfg_attr(
    feature = "fetch",
    expect(
        clippy::panic,
        reason = "a test support function fails the case the way a test body does"
    )
)]

#[cfg(feature = "fetch")]
mod assertion_key;
mod attributes;
mod audit;
#[cfg(feature = "fetch")]
mod auth_tls;
mod basic;
mod care_role;
mod classify;
#[cfg(feature = "fetch")]
mod client;
#[cfg(feature = "fetch")]
mod client_bound;
#[cfg(feature = "fetch")]
mod client_fapi2;
mod config;
mod consent;
mod contact_point;
mod correlation;
mod described;
#[cfg(feature = "ehdsi-assertion")]
mod ehdsi_assertion;
mod endpoint;
#[cfg(feature = "test-support")]
mod external;
mod federation;
#[cfg(all(feature = "axum", feature = "fetch"))]
mod guard;
#[cfg(feature = "fetch")]
mod introspection;
#[cfg(feature = "fetch")]
mod issuer_lists;
mod jws;
mod key_file;
#[cfg(feature = "fetch")]
mod metadata;
#[cfg(feature = "fetch")]
mod ml_dsa;
mod nl_profile;
#[cfg(feature = "oidc")]
mod oidc;
#[cfg(feature = "fetch")]
mod onward;
#[cfg(all(feature = "openehr", feature = "fetch"))]
mod openehr;
#[cfg(feature = "fetch")]
mod outbound;
#[cfg(feature = "fetch")]
mod outbound_builder;
#[cfg(feature = "fetch")]
mod outbound_shared_tls;
#[cfg(all(feature = "fetch", feature = "server-tls"))]
mod outbound_tls_key;
mod party;
#[cfg(feature = "fetch")]
mod person;
#[cfg(feature = "fetch")]
mod presented_tls;
#[cfg(feature = "fetch")]
mod reach;
mod redaction;
#[cfg(feature = "fetch")]
mod roles;
mod schema;
mod section_eq;
#[cfg(feature = "fetch")]
mod sender;
#[cfg(feature = "fetch")]
mod shape;
#[cfg_attr(
    not(feature = "fetch"),
    expect(
        dead_code,
        reason = "the stub issuer's metadata and key set serve the fetch cases alone"
    )
)]
mod support;
#[cfg(feature = "fetch")]
mod tls;
#[cfg(feature = "fetch")]
mod token;
#[cfg(feature = "fetch")]
mod token_answer;
#[cfg(feature = "fetch")]
mod token_endpoint_shape;
#[cfg(feature = "fetch")]
mod upstream_body;
#[cfg(feature = "fetch")]
mod verdict;
