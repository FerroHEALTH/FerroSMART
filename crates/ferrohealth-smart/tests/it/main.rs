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
    clippy::panic,
    reason = "a test support function fails the case the way a test body does"
)]

mod basic;
mod client;
#[cfg(feature = "axum")]
mod guard;
#[cfg(feature = "openehr")]
mod openehr;
mod support;
mod token;
