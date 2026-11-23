// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The authorization endpoint, the upstream login and the consent page:
//! SMART App Launch 2.2.0's authorization code flow, standalone launch
//! (`docs/architecture.md` §13.6).
//!
//! `GET` or `POST {issuer}/authorize` checks the request and sends the
//! browser to the upstream provider; `GET {issuer}/callback` completes the
//! login there and offers the person the scopes policy allows them; the
//! consent page's post issues the code and sends the browser back to the
//! app. A cookie of FerroSMART's own binds the three to one browser.

pub mod callback;
pub mod choose;
pub mod consent;
pub mod manage;
mod oidc;
pub mod par;
pub mod request;
pub mod saml;

use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use url::Url;

use crate::clients::Client;
use crate::pages::{self, Fault};
use crate::server::AppState;
use crate::store::{Pending, Purpose, StoreError};

/// The cookie that binds an authorization request to the browser that
/// began it. No specification governs it: our own design.
pub const COOKIE: &str = "ferrosmart_authorization";

/// How long an authorization request may take, login and consent
/// included. No specification governs the value: our own design.
pub const REQUEST_SECONDS: i64 = 600;

/// How long an authorization code lives: "short-lived, usually expiring
/// within around one minute" (SMART App Launch 2.2.0, Obtain authorization
/// code, Response).
pub const CODE_SECONDS: i64 = 60;

/// The authorization endpoint's route under the issuer.
pub const AUTHORIZE_ROUTE: &str = "/authorize";
/// The upstream provider's redirection endpoint under the issuer.
pub const CALLBACK_ROUTE: &str = "/callback";
/// The consent page's route under the issuer.
pub const CONSENT_ROUTE: &str = "/consent";
/// The management page's route under the issuer, the `management_endpoint`
/// (SMART App Launch 2.2.0, Conformance, Metadata).
pub const MANAGE_ROUTE: &str = "/manage";

/// An error the authorization endpoint sends back to the app (RFC 6749
/// §4.1.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Denial {
    /// The `error` code.
    error: &'static str,
    /// The `error_description`.
    description: &'static str,
}

impl Denial {
    /// The `invalid_request` denial.
    const fn request(description: &'static str) -> Self {
        Self {
            error: "invalid_request",
            description,
        }
    }
}

/// Why the authorization request stopped before the upstream login.
#[derive(Debug)]
enum Stop {
    /// The request is refused, and the app is told why.
    Deny(Denial),
    /// The server failed.
    Fail(Box<dyn std::error::Error + Send + Sync>),
}

/// Returns `error` as the server's failure.
fn fail(error: impl std::error::Error + Send + Sync + 'static) -> Stop {
    Stop::Fail(Box::new(error))
}

/// Returns the client of `pending`, or the page that says it is gone.
async fn registered(state: &AppState, pending: &Pending) -> Result<Client, Box<Response>> {
    let found = match &pending.client_id {
        Some(client_id) => state.store().client(client_id).await,
        None => Ok(None),
    };
    match found {
        Ok(Some(client)) => Ok(client),
        Ok(None) => Err(Box::new(pages::fault(state, Fault::UnknownClient))),
        Err(error) => Err(Box::new(pages::server_error(state, &error))),
    }
}

/// Sends the browser back to `pending`'s app with `denial`, given before
/// the person's login was accepted; an app that registered itself gets the
/// page that refuses its request instead.
async fn deny_unsigned(state: &AppState, pending: &Pending, denial: Denial) -> Response {
    // NOTE: RFC 9700 §4.11.2, the server authenticates the person before it redirects;
    // no administrator vouched for the redirect URI of an app that registered itself.
    match registered(state, pending).await {
        Ok(client) if client.registered_itself() => pages::fault(state, Fault::Refused),
        Ok(_) => Back::of(state, pending).deny(denial),
        Err(response) => *response,
    }
}

/// Returns the request a store lookup `looked` found, or the page that says
/// it lapsed or that the store failed.
fn found(
    state: &AppState,
    looked: Result<Option<Pending>, StoreError>,
) -> Result<Pending, Box<Response>> {
    match looked {
        Ok(Some(pending)) => Ok(pending),
        Ok(None) => Err(Box::new(pages::fault(state, Fault::Lapsed))),
        Err(error) => Err(Box::new(pages::server_error(state, &error))),
    }
}

/// Returns the browser's request once its person logged in, or the page
/// that says why there is none.
pub(crate) async fn logged_in(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Pending, Box<Response>> {
    let Some(id) = cookie(headers, COOKIE) else {
        return Err(Box::new(pages::fault(state, Fault::Lapsed)));
    };
    let pending = found(state, state.store().pending(&id).await)?;
    if pending.subject.is_some() && pending.purpose == Purpose::Authorize {
        Ok(pending)
    } else {
        Err(Box::new(pages::fault(state, Fault::Lapsed)))
    }
}

/// Where and how the browser goes back to the app.
#[derive(Debug, Clone)]
pub(crate) struct Back {
    /// The app's redirect URI.
    redirect_uri: String,
    /// The app's `state`.
    state: Option<String>,
    /// FerroSMART's issuer, sent as `iss` (RFC 9207 §2).
    issuer: String,
}

impl Back {
    /// Returns the way back for `pending`.
    pub(crate) fn of(state: &AppState, pending: &Pending) -> Self {
        Self {
            redirect_uri: pending.redirect_uri.clone(),
            state: Some(pending.state.clone()),
            issuer: state.settings().issuer.clone(),
        }
    }

    /// Sends the browser back with `denial` (RFC 6749 §4.1.2.1).
    fn deny(&self, denial: Denial) -> Response {
        self.send(&[
            ("error", denial.error),
            ("error_description", denial.description),
        ])
    }

    /// Sends the browser back with `code` (RFC 6749 §4.1.2).
    fn grant(&self, code: &str) -> Response {
        self.send(&[("code", code)])
    }

    /// Returns the URL that sends the browser back with `denial`, for a
    /// page that names the reason first.
    fn denial_url(&self, denial: Denial) -> Option<Url> {
        self.url(&[
            ("error", denial.error),
            ("error_description", denial.description),
        ])
    }

    /// Sends the browser back with `pairs`, the `state` and the `iss`.
    fn send(&self, pairs: &[(&str, &str)]) -> Response {
        match self.url(pairs) {
            Some(url) => see_other(url.as_str()),
            None => StatusCode::BAD_REQUEST.into_response(),
        }
    }

    /// Returns the redirect URI with `pairs`, the `state` and the `iss`.
    fn url(&self, pairs: &[(&str, &str)]) -> Option<Url> {
        let mut url = Url::parse(&self.redirect_uri).ok()?;
        {
            let mut query = url.query_pairs_mut();
            query.extend_pairs(pairs);
            if let Some(state) = &self.state {
                query.append_pair("state", state);
            }
            query.append_pair("iss", &self.issuer);
        }
        Some(url)
    }
}

/// Ends `pending` before the browser is sent back, logging a failure: the
/// request lapses on its own then.
async fn forget(state: &AppState, pending: &Pending) {
    if let Err(error) = state.store().finish(&pending.id).await {
        tracing::warn!(error = %ferrohealth_server::run::chain(&error), "a pending authorization was not ended");
    }
}

/// Returns a `303 See Other` to `location`.
pub(crate) fn see_other(location: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    no_store(response)
}

/// Returns `response` uncacheable: an authorization response carries a code
/// (RFC 6749 §10.3; RFC 9700 §4.2).
fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

/// Sets the cookie `name` to `value` for `max_age` seconds, scoped to the
/// issuer's path: `HttpOnly`, `Secure` and `SameSite=Lax`, which the
/// provider's redirect back still carries.
pub(crate) fn set_cookie(
    state: &AppState,
    response: &mut Response,
    name: &str,
    value: &str,
    max_age: i64,
) {
    let path = state.settings().issuer_url.path();
    let cookie =
        format!("{name}={value}; Path={path}; Max-Age={max_age}; HttpOnly; Secure; SameSite=Lax");
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

/// Returns the value of the request's cookie `name`.
pub(crate) fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(found, _)| *found == name)
        .map(|(_, value)| value.to_owned())
        .filter(|value| !value.is_empty())
}

/// Returns whether `a` and `b` are equal, in time that depends only on
/// their lengths.
pub(crate) fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Returns 256 random bits, base64url: a code, a request id, a grant id or
/// a refresh token, each beyond guessing (RFC 6749 §10.10).
pub(crate) fn random() -> Result<String, aws_lc_rs::error::Unspecified> {
    let mut bytes = [0_u8; 32];
    aws_lc_rs::rand::fill(&mut bytes)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Returns the SHA-256 of `value`, base64url: how the store keeps a code.
#[must_use]
pub fn sha256(value: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA256,
        value.as_bytes(),
    ))
}

/// Returns the time now in seconds since the epoch.
pub(crate) fn now() -> i64 {
    jiff::Timestamp::now().as_second()
}
