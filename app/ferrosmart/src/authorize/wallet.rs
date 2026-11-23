// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The EUDI Wallet routes (`docs/architecture.md` §13.32): the request
//! object, the response URI and the browser's way back.
//!
//! The wallet fetches the request object by its `state` as often as it
//! needs (OpenID4VP 1.0 §5.10), and posts its encrypted answer to the
//! response URI, which checks the presentation and answers with a
//! `redirect_uri` carrying a fresh response code (§8.2). The browser that
//! began the request brings the code back and the login completes there
//! (§14.2; HAIP 1.0 §5.1). A presentation refused at the response URI is
//! recorded with its reason and answered with a `400`, and the request
//! stays open until it lapses or a valid answer completes it.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use serde_json::{Value, json};

use crate::audit::Connected;
use crate::form::Params;
use crate::pages::{self, Fault};
use crate::server::AppState;
use crate::store::wallet::Answer;
use crate::store::{Pending, Purpose};
use crate::upstream::wallet::{
    COMPLETE_ROUTE, DIGITAL_CREDENTIALS_ROUTE, MODULE_ROUTE, PAGE_ROUTE, REQUEST_ROUTE,
    RESPONSE_ROUTE, WalletLogin,
};
use crate::upstream::{Identity, LoginProvider};
use crate::wallet::Refusal;
use crate::wallet::jwe::{self, EphemeralKey};
use crate::wallet::request::{CREDENTIAL_ID, Lane, MEDIA_TYPE};

use super::{COOKIE, Denial, cookie, deny_unsigned, forget, found, now, random, sha256};

/// Returns the wallet routes.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route(REQUEST_ROUTE, get(request_object).post(request_object))
        .route(RESPONSE_ROUTE, post(response))
        .route(COMPLETE_ROUTE, get(complete))
        .route(PAGE_ROUTE, get(page))
        .route(MODULE_ROUTE, get(module))
        .route(DIGITAL_CREDENTIALS_ROUTE, post(digital_credentials))
}

/// The longest `wallet_nonce` taken (no specification sets one: our own
/// design).
const MAX_WALLET_NONCE: usize = 256;

/// `GET` or `POST {issuer}/wallet/request/{state}`: the signed request
/// object, with the `wallet_nonce` a posting wallet sends (OpenID4VP 1.0
/// §5.10).
pub async fn request_object(
    State(state): State<Arc<AppState>>,
    Path(request_state): Path<String>,
    method: Method,
    body: Bytes,
) -> Response {
    let wallet_nonce = if method == Method::POST {
        let Ok(params) = Params::parse(&body, &[]) else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        params.get("wallet_nonce").map(str::to_owned)
    } else {
        None
    };
    if wallet_nonce
        .as_deref()
        .is_some_and(|nonce| nonce.len() > MAX_WALLET_NONCE)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let pending = match state.store().pending_by_upstream(&request_state).await {
        Ok(Some(pending)) => pending,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return failed(&error),
    };
    let Some(login) = wallet_of(&state, &pending).and_then(LoginProvider::wallet) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match login.request_object(
        &pending.upstream_state,
        &pending.upstream_nonce,
        &pending.upstream_verifier,
        Lane::Redirect {
            wallet_nonce: wallet_nonce.as_deref(),
        },
        pending.expires_at,
    ) {
        Ok(object) => no_store(object, MEDIA_TYPE),
        Err(error) => failed(&error),
    }
}

/// `POST {issuer}/wallet/response`: the wallet's answer (OpenID4VP 1.0
/// §8.2, §8.3.1).
pub async fn response(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let Ok(params) = Params::parse(&body, &[]) else {
        return refusal_body(Refusal::MalformedResponse);
    };
    if let Some(sealed) = params.get("response") {
        let Some(kid) = jwe::kid(sealed) else {
            return refusal_body(Refusal::MalformedResponse);
        };
        let (pending, provider) = match request(&state, &kid).await {
            Ok(found) => found,
            Err(response) => return *response,
        };
        return match opened(&pending, sealed) {
            Ok(payload) => answered(&state, &pending, provider, &payload).await,
            Err(refusal) => refused(&state, provider, refusal).await,
        };
    }
    let Some(request_state) = params.get("state") else {
        return refusal_body(Refusal::MalformedResponse);
    };
    let (pending, provider) = match request(&state, request_state).await {
        Ok(found) => found,
        Err(response) => return *response,
    };
    // NOTE: OpenID4VP 1.0 §8.3.1, a wallet unable to encrypt may send an error in the clear.
    if params.get("error").is_some() && params.get("vp_token").is_none() {
        return declined(&state, &pending, provider).await;
    }
    // NOTE: HAIP 1.0 §5.1, the response is encrypted with direct_post.jwt.
    refused(&state, provider, Refusal::UnencryptedResponse).await
}

/// Returns the live request `request_state` names, with its wallet
/// provider, or the `400` that answers a response to no such request.
async fn request<'a>(
    state: &'a AppState,
    request_state: &str,
) -> Result<(Pending, &'a LoginProvider), Box<Response>> {
    let pending = match state.store().pending_by_upstream(request_state).await {
        Ok(Some(pending)) => pending,
        Ok(None) => return Err(Box::new(refusal_body(Refusal::MalformedResponse))),
        Err(error) => return Err(Box::new(failed(&error))),
    };
    match wallet_of(state, &pending) {
        Some(provider) if provider.wallet().is_some() => Ok((pending, provider)),
        _ => Err(Box::new(refusal_body(Refusal::MalformedResponse))),
    }
}

/// Returns the provider the request `pending` went to.
fn wallet_of<'a>(state: &'a AppState, pending: &Pending) -> Option<&'a LoginProvider> {
    pending
        .upstream_provider
        .as_deref()
        .and_then(|name| state.providers().named(name))
}

/// Returns the payload of the encrypted response `sealed` to the request
/// `pending`, once it names that request's `state`.
fn opened(pending: &Pending, sealed: &str) -> Result<Value, Refusal> {
    let key = EphemeralKey::from_stored(&pending.upstream_verifier)
        .map_err(|_unread| Refusal::MalformedResponse)?;
    let plain = key
        .decrypt(sealed, &pending.upstream_state)
        .map_err(|_unopened| Refusal::MalformedResponse)?;
    let payload: Value =
        serde_json::from_slice(&plain).map_err(|_unread| Refusal::MalformedResponse)?;
    // NOTE: RFC 6749 §4.1.2, the response carries back the request's state.
    if payload.get("state").and_then(Value::as_str) != Some(pending.upstream_state.as_str()) {
        return Err(Refusal::MalformedResponse);
    }
    Ok(payload)
}

/// Answers the opened response `payload` to `pending` at `provider`: a
/// declined request, a refusal, or the person's answer kept for the
/// browser.
async fn answered(
    state: &AppState,
    pending: &Pending,
    provider: &LoginProvider,
    payload: &Value,
) -> Response {
    if payload.get("error").is_some() {
        return declined(state, pending, provider).await;
    }
    let Some(login) = provider.wallet() else {
        return refusal_body(Refusal::MalformedResponse);
    };
    match presented(
        login,
        pending,
        payload,
        &Lane::Redirect { wallet_nonce: None },
    )
    .await
    {
        Ok(identity) => accept(state, pending, provider, &identity).await,
        Err(refusal) => refused(state, provider, refusal).await,
    }
}

/// Checks the one presentation of the VP Token in `payload` for `pending`
/// in `lane` and returns the person it names (OpenID4VP 1.0 §8.1, §8.6).
async fn presented(
    login: &WalletLogin,
    pending: &Pending,
    payload: &Value,
    lane: &Lane<'_>,
) -> Result<Identity, Refusal> {
    let Some([Value::String(presentation)]) = payload
        .get("vp_token")
        .and_then(|token| token.get(CREDENTIAL_ID))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
    else {
        return Err(Refusal::MalformedResponse);
    };
    let audience = login.upstream().audience(lane);
    login
        .verify(presentation, &pending.upstream_nonce, &audience, now())
        .await
}

/// Keeps the person `identity` for `pending` under a fresh response code
/// and answers the wallet with the `redirect_uri` that brings it back, or
/// refuses a nonce already answered.
async fn accept(
    state: &AppState,
    pending: &Pending,
    provider: &LoginProvider,
    identity: &Identity,
) -> Response {
    let Ok(code) = random() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let identity = match serde_json::to_value(identity) {
        Ok(identity) => identity,
        Err(error) => return failed(&error),
    };
    let answer = Answer {
        pending_id: pending.id.clone(),
        identity,
    };
    match state
        .store()
        .first_answer(
            &pending.upstream_nonce,
            &sha256(&code),
            &answer,
            pending.expires_at,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => return refused(state, provider, Refusal::ReplayedNonce).await,
        Err(error) => return failed(&error),
    }
    tracing::info!(
        target: "ferrosmart::audit",
        event = "wallet.answer",
        client_id = ?pending.client_id,
        "a wallet presentation was admitted"
    );
    back(state, &[("response_code", &code)])
}

/// Records that the wallet declined `pending` and sends the browser back
/// with the error and the request's `state`, which the cookie's request
/// must name (OpenID4VP 1.0 §8.5; RFC 6749 §4.1.2.1); the nonce stays
/// unanswered, so an error posted against the public `state` blocks no
/// presentation.
async fn declined(state: &AppState, pending: &Pending, provider: &LoginProvider) -> Response {
    if let Err(response) = super::callback::record_login(
        state,
        provider.upstream(),
        Err("the person declined at the wallet"),
    )
    .await
    {
        return *response;
    }
    back(
        state,
        &[
            ("error", "access_denied"),
            ("state", &pending.upstream_state),
        ],
    )
}

/// Answers the wallet with the `redirect_uri` of [`COMPLETE_ROUTE`]
/// carrying `pairs` (OpenID4VP 1.0 §8.2).
fn back(state: &AppState, pairs: &[(&str, &str)]) -> Response {
    let mut url = state.settings().endpoint_url(COMPLETE_ROUTE);
    url.query_pairs_mut().extend_pairs(pairs);
    no_store(
        Json(json!({"redirect_uri": url.as_str()})),
        "application/json",
    )
}

/// Records the refusal `refusal` of a presentation at `provider` and
/// answers the wallet with a `400` naming it.
async fn refused(state: &AppState, provider: &LoginProvider, refusal: Refusal) -> Response {
    tracing::warn!(reason = %refusal, "a wallet presentation was refused");
    let reason = format!("the wallet presentation is refused: {refusal}");
    if let Err(response) =
        super::callback::record_login(state, provider.upstream(), Err(&reason)).await
    {
        return *response;
    }
    refusal_body(refusal)
}

/// Returns the `400` that names `refusal` to the wallet.
fn refusal_body(refusal: Refusal) -> Response {
    let body = json!({"error": "invalid_request", "error_description": refusal.to_string()});
    let mut response = no_store(Json(body), "application/json");
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response
}

/// Returns `body` as a response of `content_type` no cache keeps.
fn no_store(body: impl IntoResponse, content_type: &'static str) -> Response {
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Returns the `500` of a failure the wallet cannot act on, logged.
fn failed(error: &(dyn std::error::Error + 'static)) -> Response {
    tracing::error!(error = %ferrohealth_server::run::chain(error), "a wallet request failed");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

/// `GET {issuer}/wallet/complete`: the browser that began the request comes back.
///
/// With a `response_code` it brings the wallet's answer and the login
/// completes (OpenID4VP 1.0 §14.2; HAIP 1.0 §5.1); with `error` and `state`
/// the wallet declined.
pub async fn complete(
    State(state): State<Arc<AppState>>,
    Connected(from): Connected,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let Ok(params) = Params::parse(query.unwrap_or_default().as_bytes(), &[]) else {
        return pages::fault(&state, Fault::BadRequest);
    };
    let Some(code) = params.get("response_code") else {
        return declined_back(&state, &headers, &params).await;
    };
    let answer = match found(&state, state.store().take_answer(&sha256(code)).await) {
        Ok(answer) => answer,
        Err(response) => return *response,
    };
    let pending = match found(&state, state.store().pending(&answer.pending_id).await) {
        Ok(pending) => pending,
        Err(response) => return *response,
    };
    // NOTE: HAIP 1.0 §5.1, an answer brought back in another session is refused.
    if cookie(&headers, COOKIE).as_deref() != Some(pending.id.as_str()) {
        return pages::fault(&state, Fault::OtherBrowser);
    }
    let Some(provider) = wallet_of(&state, &pending) else {
        return pages::fault(&state, Fault::Lapsed);
    };
    match serde_json::from_value::<Identity>(answer.identity) {
        Ok(identity) => {
            super::callback::complete(&state, &pending, provider, &identity, from).await
        }
        Err(error) => pages::server_error(&state, &error),
    }
}

/// Answers the way back of a declined request: the cookie's request, sent
/// to the wallet under the `state` the query names, ends with
/// `access_denied` for the app.
async fn declined_back(state: &AppState, headers: &HeaderMap, params: &Params) -> Response {
    let (Some(_), Some(named)) = (params.get("error"), params.get("state")) else {
        return pages::fault(state, Fault::BadRequest);
    };
    let Some(id) = cookie(headers, COOKIE) else {
        return pages::fault(state, Fault::OtherBrowser);
    };
    let pending = match found(state, state.store().pending(&id).await) {
        Ok(pending) => pending,
        Err(response) => return *response,
    };
    let at_wallet = wallet_of(state, &pending).is_some_and(|provider| provider.wallet().is_some());
    // NOTE: RFC 6749 §10.12, the state ties the answer to the browser's own request.
    if !at_wallet || !super::constant_eq(named.as_bytes(), pending.upstream_state.as_bytes()) {
        return pages::fault(state, Fault::OtherBrowser);
    }
    back_declined(state, &pending).await
}

/// Ends `pending`, which the wallet declined, and sends the browser back to
/// the app with `access_denied` (RFC 6749 §4.1.2.1).
async fn back_declined(state: &AppState, pending: &Pending) -> Response {
    forget(state, pending).await;
    if pending.purpose == Purpose::Manage {
        return pages::fault(state, Fault::Lapsed);
    }
    let denial = Denial {
        error: "access_denied",
        description: "the login was declined",
    };
    deny_unsigned(state, pending, denial).await
}

/// Returns the browser's live request at the wallet and its provider, or
/// the page that says why there is none.
async fn at_wallet<'a>(
    state: &'a AppState,
    headers: &HeaderMap,
) -> Result<(Pending, &'a LoginProvider), Box<Response>> {
    let Some(id) = cookie(headers, COOKIE) else {
        return Err(Box::new(pages::fault(state, Fault::Lapsed)));
    };
    let pending = found(state, state.store().pending(&id).await)?;
    match wallet_of(state, &pending) {
        Some(provider) if provider.wallet().is_some() => Ok((pending, provider)),
        _ => Err(Box::new(pages::fault(state, Fault::Lapsed))),
    }
}

/// `GET {issuer}/wallet`: the page that offers the wallet by redirect and,
/// where the browser has it, through the Digital Credentials API.
pub async fn page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (pending, provider) = match at_wallet(&state, &headers).await {
        Ok(found) => found,
        Err(page) => return *page,
    };
    let Some(login) = provider.wallet() else {
        return pages::fault(&state, Fault::Lapsed);
    };
    let origin = login.upstream().origin().to_owned();
    let invocation = login.invocation(&pending.upstream_state);
    let request = login.request_object(
        &pending.upstream_state,
        &pending.upstream_nonce,
        &pending.upstream_verifier,
        Lane::DigitalCredentials { origin: &origin },
        pending.expires_at,
    );
    match (invocation, request) {
        (Ok(invocation), Ok(request)) => {
            pages::wallet::page(&state, &headers, &pending, &invocation, &request)
        }
        (Err(error), _) | (_, Err(error)) => pages::server_error(&state, &error),
    }
}

/// `GET {issuer}/wallet/dc.js`: the page's module.
pub async fn module() -> Response {
    pages::wallet::module()
}

/// `POST {issuer}/wallet/dc`: the wallet's answer through the Digital
/// Credentials API, posted by the page's form in the browser that began
/// the request (OpenID4VP 1.0 Appendix A.4; HAIP 1.0 §5.2).
pub async fn digital_credentials(
    State(state): State<Arc<AppState>>,
    Connected(from): Connected,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(form) = Params::parse(&body, &[]) else {
        return pages::fault(&state, Fault::BadRequest);
    };
    let (pending, provider) = match at_wallet(&state, &headers).await {
        Ok(found) => found,
        Err(page) => return *page,
    };
    let sent = form.get("form_token").unwrap_or_default();
    if !super::constant_eq(sent.as_bytes(), pending.form_token.as_bytes()) {
        return pages::fault(&state, Fault::BadRequest);
    }
    let data: Value = match form.get("data").map(serde_json::from_str) {
        Some(Ok(data)) => data,
        _ => return pages::fault(&state, Fault::BadRequest),
    };
    // NOTE: OpenID4VP 1.0 Appendix A.4, a wallet's error is an object with one error member.
    if data.get("error").is_some() {
        if let Err(response) = super::callback::record_login(
            &state,
            provider.upstream(),
            Err("the person declined at the wallet"),
        )
        .await
        {
            return *response;
        }
        return back_declined(&state, &pending).await;
    }
    match api_answer(&state, &pending, provider, &data).await {
        Ok(identity) => {
            super::callback::complete(&state, &pending, provider, &identity, from).await
        }
        Err(refusal) => api_refused(&state, &pending, provider, refusal).await,
    }
}

/// Opens and checks the Digital Credentials API answer `data` to `pending`
/// and takes its nonce (OpenID4VP 1.0 §14.1.2), returning the person it
/// names.
async fn api_answer(
    state: &AppState,
    pending: &Pending,
    provider: &LoginProvider,
    data: &Value,
) -> Result<Identity, Refusal> {
    let login = provider.wallet().ok_or(Refusal::MalformedResponse)?;
    // NOTE: HAIP 1.0 §5.2, the answer comes as dc_api.jwt, encrypted.
    let sealed = data
        .get("response")
        .and_then(Value::as_str)
        .ok_or(Refusal::UnencryptedResponse)?;
    let key = EphemeralKey::from_stored(&pending.upstream_verifier)
        .map_err(|_unread| Refusal::MalformedResponse)?;
    let plain = key
        .decrypt(sealed, &pending.upstream_state)
        .map_err(|_unopened| Refusal::MalformedResponse)?;
    let payload: Value =
        serde_json::from_slice(&plain).map_err(|_unread| Refusal::MalformedResponse)?;
    let origin = login.upstream().origin().to_owned();
    let lane = Lane::DigitalCredentials { origin: &origin };
    let identity = presented(login, pending, &payload, &lane).await?;
    let answer = Answer {
        pending_id: pending.id.clone(),
        identity: serde_json::to_value(&identity)
            .map_err(|_unwritten| Refusal::MalformedResponse)?,
    };
    let code = random().map_err(|_failed| Refusal::MalformedResponse)?;
    let first = state
        .store()
        .first_answer(&pending.upstream_nonce, &sha256(&code), &answer, pending.expires_at)
        .await
        .map_err(|error| {
            tracing::error!(error = %ferrohealth_server::run::chain(&error), "a wallet answer could not be recorded");
            Refusal::MalformedResponse
        })?;
    if first {
        Ok(identity)
    } else {
        Err(Refusal::ReplayedNonce)
    }
}

/// Records the refusal `refusal` of a Digital Credentials API answer and
/// ends `pending`, sending the app `access_denied` (RFC 6749 §4.1.2.1).
async fn api_refused(
    state: &AppState,
    pending: &Pending,
    provider: &LoginProvider,
    refusal: Refusal,
) -> Response {
    tracing::warn!(reason = %refusal, "a wallet presentation was refused");
    let reason = format!("the wallet presentation is refused: {refusal}");
    if let Err(response) =
        super::callback::record_login(state, provider.upstream(), Err(&reason)).await
    {
        return *response;
    }
    back_declined(state, pending).await
}
