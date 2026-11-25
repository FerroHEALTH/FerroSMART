// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The integration tests of FerroSMART, one binary: the configuration and
//! the discovery routes, every key generated when the case runs.

#![expect(
    clippy::expect_used,
    reason = "a test support function fails the case the way a test body does"
)]

mod admin;
mod admin_subjects;
mod audit;
mod audit_search;
mod authorize;
mod brands;
mod clients;
mod config;
mod discovery;
mod ehr_launch;
mod ig_examples;
mod introspection;
mod launch;
mod ml_dsa;
mod openapi;
mod post_quantum;
mod refresh;
mod registration;
mod replicas;
mod resources;
mod revocation;
mod saml;
mod screenshots;
mod sender;
mod signing;
mod store;
mod support;
mod symmetric;
mod token;
mod upstream_config;
mod upstream_vendors;
mod upstreams;
