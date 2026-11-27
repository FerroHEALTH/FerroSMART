// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The pushed authorization request endpoint (RFC 9126): an authenticated
//! client posts its authorization request and receives a `request_uri`
//! that the authorization endpoint takes once in its place.

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, StatusCode};
use serde_json::json;

use crate::clients::GrantType;
use crate::form::Params;
use crate::server::AppState;
use crate::token::{Refusal, no_store, read_form, server_error};

use super::{now, random, sha256};

/// The pushed authorization request endpoint's route under the issuer.
pub const PAR_ROUTE: &str = "/par";

/// The form of a `request_uri` (RFC 9126 §2.2).
pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// How long a `request_uri` lives: RFC 9126 §2.2 has it "relatively short
/// (e.g., between 5 and 600 seconds)"; the value is our own design.
pub const PUSHED_SECONDS: i64 = 60;

/// The parameters a pushed request carries for client authentication alone,
/// never kept with the request (RFC 9126 §2.1).
const AUTHENTICATION: [&str; 3] = ["client_secret", "client_assertion", "client_assertion_type"];

/// `POST {issuer}/par`.
pub async fn par(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    if state.providers().is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match push(&state, &headers, &body).await {
        Ok(response) => response,
        Err(refusal) => refusal.answer(&headers),
    }
}

/// Authenticates the client, checks its pushed request as the
/// authorization endpoint would, and keeps it under a new `request_uri`
/// (RFC 9126 §2.1, §2.2).
async fn push(state: &AppState, headers: &HeaderMap, body: &[u8]) -> Result<Response, Refusal> {
    let form = read_form(headers, body)?;
    let client = crate::token::grants::identify(
        state,
        headers,
        &form,
        crate::token::assertion::Endpoint::Par,
    )
    .await?;
    // NOTE: RFC 9126 §2.1, `client_id` is required, and the request is the
    // authenticated client's own.
    if form.get("client_id") != Some(client.client_id.as_str()) {
        return Err(Refusal::request(
            "the client_id is not the authenticated client",
        ));
    }
    if form.get("request_uri").is_some() {
        return Err(Refusal::request("a pushed request carries no request_uri"));
    }
    if !client.grant_types.contains(&GrantType::AuthorizationCode) {
        return Err(Refusal {
            error: "unauthorized_client",
            description: "the client may not use this grant",
        });
    }
    // NOTE: RFC 9700 §2.1, the redirect URI matches a registered one exactly;
    // RFC 9126 §2.3, invalid_request names a redirect URI that does not.
    let registered = form
        .get("redirect_uri")
        .is_some_and(|uri| client.redirect_uris.iter().any(|known| known == uri));
    if !registered {
        return Err(Refusal::request("the redirect_uri is not registered"));
    }
    super::request::check(state, &client, &form).map_err(|denial| Refusal {
        error: denial.error,
        description: denial.description,
    })?;
    let parameters = kept(&form);
    let reference =
        random().map_err(|error| server_error("no request_uri can be drawn", &error))?;
    let request_uri = format!("{REQUEST_URI_PREFIX}{reference}");
    state
        .store()
        .push_request(
            &sha256(&request_uri),
            &client.client_id,
            &parameters,
            now().saturating_add(PUSHED_SECONDS),
        )
        .await
        .map_err(|error| server_error("the pushed request cannot be kept", &error))?;
    let body = json!({ "request_uri": request_uri, "expires_in": PUSHED_SECONDS });
    Ok(no_store((StatusCode::CREATED, Json(body)).into_response()))
}

/// Returns the authorization request of `form` without its client
/// authentication, form-encoded.
fn kept(form: &Params) -> String {
    let mut encoded = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in form.pairs() {
        if !AUTHENTICATION.contains(&name) {
            encoded.append_pair(name, value);
        }
    }
    encoded.finish()
}
