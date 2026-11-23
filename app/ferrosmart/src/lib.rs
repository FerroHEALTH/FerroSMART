// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! FerroSMART, the SMART App Launch 2.x authorization server of the
//! FerroHEALTH products (`docs/architecture.md` §13).
//!
//! It is the one component of the family that issues tokens and holds the
//! keys that sign them; any OpenID Connect provider upstream serves the
//! login. This crate is the server: its command line, its configuration,
//! its signing keys and the documents that describe it.

pub mod admin;
pub mod approvals;
pub mod assurance;
pub mod audit;
pub mod audit_feed;
pub mod audit_log;
pub mod authorize;
pub mod brands;
pub mod cli;
pub mod client_keys;
pub mod clients;
pub mod command;
pub mod config;
pub mod discovery;
pub mod form;
pub mod introspect;
pub mod launch;
pub mod logout;
pub mod pages;
pub mod picker;
pub mod refresh;
pub mod revoke;
pub mod saml;
pub mod scopes;
pub mod server;
pub mod signing;
pub mod store;
pub mod token;
pub mod upstream;
