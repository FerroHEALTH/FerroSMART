// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Client registration (RFC 7591) and its management (RFC 7592), the one
//! client endpoint SMART App Launch 2.2.0 recommends (Register App with EHR).
//!
//! An administrator's FerroSMART access token holding `system/admin` is the
//! initial access token (RFC 7591 §3), which sets every member. Without one,
//! the endpoint answers only when `[ferrosmart.registration] open` is set:
//! the app registers itself, its `scope` held to that section's, and a
//! member only an administrator sets is refused. A registered client manages
//! itself with the registration access token its registration answered.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, State};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde_json::{Value, json};

use super::document::ClientDocument;
use super::openapi::Operation;
use super::{AdminError, Applied, Change, DOCUMENT_LIMIT, OnClient, Record, no_store};
use crate::audit::{self, Connected};
use crate::server::AppState;
use crate::store::admin::Registered;

/// The registration endpoint (RFC 7591 §3).
pub const REGISTER_ROUTE: &str = "/register";
/// A client's configuration endpoint (RFC 7592 §2).
pub const CONFIGURATION_ROUTE: &str = "/register/{client_id}";

/// Returns the registration routes.
pub fn router() -> Router<Arc<AppState>> {
    super::openapi::routes(table()).layer(DefaultBodyLimit::max(DOCUMENT_LIMIT))
}

/// Returns the registration operations.
pub(super) fn table() -> Vec<Operation> {
    vec![
        Operation::post(REGISTER_ROUTE, register),
        Operation::get(CONFIGURATION_ROUTE, read),
        Operation::put(CONFIGURATION_ROUTE, update),
        Operation::delete(CONFIGURATION_ROUTE, remove),
    ]
}

/// The change a request on `on` by `by` makes: `None` when the client
/// manages itself with its registration access token.
fn change<'a>(on: &'a OnClient, by: Option<&'a str>) -> Change<'a> {
    Change {
        state: &on.state,
        by,
        from: on.from,
    }
}

/// Returns the bearer token `headers` carry (RFC 6750 §2.1).
fn token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Bearer"))
        .map(|(_, token)| token.trim())
}

/// Returns the `401` of a missing or refused token (RFC 6750 §3, RFC 7592
/// §2.1).
fn unauthorized() -> Response {
    let mut response = no_store(
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_token" })),
        )
            .into_response(),
    );
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer error=\"invalid_token\""),
    );
    response
}

/// Returns the RFC 7591 §3.2.2 `invalid_client_metadata` refusal naming
/// `description`.
fn invalid_metadata(description: &str) -> Response {
    no_store(
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_client_metadata", "error_description": description })),
        )
            .into_response(),
    )
}

/// Returns a fresh random value: 32 bytes, base64url without padding.
fn random() -> Result<String, AdminError> {
    use base64::Engine as _;
    let mut bytes = [0_u8; 32];
    aws_lc_rs::rand::fill(&mut bytes)
        .map_err(|_unspecified| AdminError::Secret(crate::clients::HashError::Salt))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Returns whether the bearer `token` is an administrator's, or `Err` with
/// the answer to give when it is no token FerroSMART takes.
async fn administrator(state: &AppState, token: &str) -> Result<String, Box<Response>> {
    match super::guard::administrator(state, token).await {
        Ok(Some(admin)) => Ok(admin),
        Ok(None) => Err(Box::new(unauthorized())),
        Err(error) => Err(Box::new(AdminError::Store(error).into_response())),
    }
}

/// Returns who the bearer token of a request on `client_id` is: `None` for
/// the client's registration access token, the admin client for an
/// administrator's (RFC 7592 §3).
async fn bearer(
    state: &AppState,
    headers: &HeaderMap,
    client_id: &str,
) -> Result<Option<String>, Box<Response>> {
    let token = token(headers).ok_or_else(|| Box::new(unauthorized()))?;
    let held = state
        .store()
        .holds_registration_token(client_id, &crate::authorize::sha256(token))
        .await
        .map_err(|error| Box::new(AdminError::Store(error).into_response()))?;
    if held {
        return Ok(None);
    }
    administrator(state, token).await.map(Some)
}

/// Returns the RFC 7591 §3.2.1 answer for `applied`: the client's metadata,
/// the issued secret once, and with the registration access token `token`,
/// when one was issued, the client's configuration URL and
/// `client_id_issued_at`.
fn answered(
    state: &AppState,
    status: StatusCode,
    applied: &Applied,
    token: Option<&str>,
) -> Response {
    let Some(token) = token else {
        return super::issued(status, applied, Value::Null);
    };
    let client_id = &applied.registered.client.client_id;
    let extra = json!({
        "registration_access_token": token,
        "registration_client_uri": state
            .settings()
            .endpoint(&CONFIGURATION_ROUTE.replace("{client_id}", client_id)),
        "client_id_issued_at": jiff::Timestamp::now().as_second(),
    });
    super::issued(status, applied, extra)
}

/// `POST /register`: registers the client the body describes (RFC 7591
/// §3.1).
async fn register(
    State(state): State<Arc<AppState>>,
    Connected(from): Connected,
    headers: HeaderMap,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let admin = match token(&headers) {
        Some(token) => match administrator(&state, token).await {
            Ok(admin) => Some(admin),
            Err(response) => return *response,
        },
        None => None,
    };
    let ceiling = state.settings().registration.clone();
    if admin.is_none() && ceiling.is_none() {
        return unauthorized();
    }
    let body = match body {
        Ok(Json(body)) => body,
        Err(rejection) => return AdminError::Unreadable(rejection).into_response(),
    };
    let Ok((document, _secret)) = ClientDocument::from_registration(body) else {
        return invalid_metadata("the body is no client metadata object");
    };
    let client_id = match random() {
        Ok(generated) => generated,
        Err(error) => return error.into_response(),
    };
    let document = match ceiling.filter(|_| admin.is_none()) {
        Some(ceiling) => match own(&state, document, client_id, &ceiling) {
            Ok(document) => document,
            Err(response) => return *response,
        },
        None if document.client_id().is_empty() => document.named(client_id),
        None => document,
    };
    // NOTE: RFC 7591 §3.2.1, the registration access token is optional: an app that
    // registered itself manages itself with one, an administrator with its own token.
    let registration_token = if admin.is_none() {
        match random() {
            Ok(token) => Some(token),
            Err(error) => return error.into_response(),
        }
    } else {
        None
    };
    let hash = registration_token.as_deref().map(crate::authorize::sha256);
    let change = Change {
        state: &state,
        by: admin.as_deref(),
        from,
    };
    let created = async {
        let tx = state.store().begin().await?;
        let client_id = document.client_id().to_owned();
        let (section, material) = document.registration(&client_id, None);
        change
            .create(tx, &section, material, admin.is_none(), hash.as_deref())
            .await
    }
    .await;
    match created {
        Ok(applied) => {
            let mut response = answered(
                &state,
                StatusCode::CREATED,
                &applied,
                registration_token.as_deref(),
            );
            let location = state.settings().endpoint(
                &CONFIGURATION_ROUTE.replace("{client_id}", &applied.registered.client.client_id),
            );
            // NOTE: RFC 9110 §10.2.2, the created client's configuration endpoint; one
            // that is no header value leaves the Location off, the client created all the same.
            if let Ok(location) = HeaderValue::from_str(&location) {
                response.headers_mut().insert(header::LOCATION, location);
            }
            response
        }
        Err(error) => error.into_response(),
    }
}

/// Returns the document of an app that registers itself, `client_id`
/// assigned, its `scope` held to `ceiling` (all of it when it asks none),
/// and every configured resource server as its audience; or the refusal of
/// a member only an administrator sets or a scope beyond the ceiling.
fn own(
    state: &AppState,
    document: ClientDocument,
    client_id: String,
    ceiling: &[String],
) -> Result<ClientDocument, Box<Response>> {
    if let Some(member) = document.administrators_only() {
        return Err(Box::new(invalid_metadata(&format!(
            "`{member}` is set by an administrator alone"
        ))));
    }
    let asked: Vec<&str> = document.scope().split_whitespace().collect();
    if !asked
        .iter()
        .all(|scope| crate::scopes::admits(ceiling, scope))
    {
        return Err(Box::new(invalid_metadata(
            "the scope is wider than an app registering itself may hold",
        )));
    }
    let scope = if asked.is_empty() {
        ceiling.join(" ")
    } else {
        asked.join(" ")
    };
    // NOTE: our own design, an open registration lets the app reach every resource
    // server the deployment configures, since RFC 8707 leaves the targets to it.
    let resources = state.settings().resources.clone();
    Ok(document.assigned(client_id, scope, resources))
}

/// `GET /register/{client_id}`: the client's metadata (RFC 7592 §2.1).
async fn read(on: OnClient, headers: HeaderMap) -> Response {
    if let Err(response) = bearer(&on.state, &headers, &on.client_id).await {
        return *response;
    }
    match on.state.store().registered_client(&on.client_id).await {
        Ok(Some(registered)) => super::answer(StatusCode::OK, &registered),
        Ok(None) => unauthorized(),
        Err(error) => AdminError::Store(error).into_response(),
    }
}

/// `PUT /register/{client_id}`: replaces the client's metadata with the
/// body's, which names the client and, when it carries `client_secret`, the
/// secret the client holds (RFC 7592 §2.2).
async fn update(
    on: OnClient,
    headers: HeaderMap,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    let by = match bearer(&on.state, &headers, &on.client_id).await {
        Ok(by) => by,
        Err(response) => return *response,
    };
    let body = match body {
        Ok(Json(body)) => body,
        Err(rejection) => return AdminError::Unreadable(rejection).into_response(),
    };
    let Ok((document, secret)) = ClientDocument::from_registration(body) else {
        return invalid_metadata("the body is no client metadata object");
    };
    if document.client_id() != on.client_id {
        return AdminError::OtherClient.into_response();
    }
    let change = change(&on, by.as_deref());
    let (tx, stored) = match change.lock(&on.client_id).await {
        Ok(locked) => locked,
        Err(error) => return error.into_response(),
    };
    if let Some(secret) = &secret
        && !holds_secret(&stored, secret).await
    {
        return invalid_metadata("the client_secret is not the client's");
    }
    let document = if stored.client.registered_itself() {
        let Some(ceiling) = on.state.settings().registration.clone() else {
            return unauthorized();
        };
        match own(&on.state, document, on.client_id.clone(), &ceiling) {
            Ok(document) => document,
            Err(response) => return *response,
        }
    } else if by.is_none() {
        return unauthorized();
    } else {
        document
    };
    let (section, material) = document.registration(&on.client_id, Some(&stored.client));
    match change.replace(tx, &stored, &section, material).await {
        Ok(applied) => answered(&on.state, StatusCode::OK, &applied, None),
        Err(error) => error.into_response(),
    }
}

/// Returns whether `stored`'s secret hash holds `secret`.
async fn holds_secret(stored: &Registered, secret: &secrecy::SecretString) -> bool {
    let Some(hash) = stored.client.secret_hash.clone() else {
        return false;
    };
    let secret = secret.clone();
    tokio::task::spawn_blocking(move || {
        use secrecy::ExposeSecret as _;
        ferrohealth_smart::basic::PasswordStore::new()
            .with_user("client", secrecy::SecretString::from(hash.phc().to_owned()))
            .is_ok_and(|store| {
                store
                    .verify_password("client", secret.expose_secret())
                    .is_ok()
            })
    })
    .await
    .unwrap_or(false)
}

/// `DELETE /register/{client_id}`: deprovisions the client, every grant
/// and token it held revoked (RFC 7592 §2.3).
async fn remove(on: OnClient, headers: HeaderMap) -> Response {
    let by = match bearer(&on.state, &headers, &on.client_id).await {
        Ok(by) => by,
        Err(response) => return *response,
    };
    let change = change(&on, by.as_deref());
    let client_id = on.client_id.as_str();
    let removed = async {
        let (mut tx, _stored) = change.lock(client_id).await?;
        let ended = tx.disable_client(client_id).await?;
        tx.delete_client(client_id).await?;
        let record = Record {
            event: audit::Event::ClientDeleted,
            client_id,
            details: vec![
                ("revoked", ended.grants.to_string()),
                ("access_tokens", ended.access_tokens.to_string()),
                ("consents", ended.consents.to_string()),
            ],
        };
        change.record(tx, record).await
    }
    .await;
    match removed {
        Ok(()) => no_store(StatusCode::NO_CONTENT.into_response()),
        Err(error) => error.into_response(),
    }
}
