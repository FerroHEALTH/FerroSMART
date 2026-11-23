// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The admin API: `/admin/clients` over the registry every replica reads,
//! and `/admin/keys`, the signing key ring (`docs/architecture.md` §13.8).
//!
//! The configuration seeds the registry at start; once the API creates or
//! changes a client, the store is its source and its table is no longer
//! written. Every change commits with its audit record, and a change that
//! withdraws an organisation approval or disables a client revokes the
//! grants and tokens it covered in the same transaction, so the next
//! request at any replica sees it. No specification governs the admin API:
//! our own design, the registry SMART leaves to the server ("SMART does not
//! specify a standards-based registration process", SMART App Launch 2.2.0,
//! Register App with EHR).

pub mod document;
pub mod guard;

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequestParts, Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use ferrohealth_server::run::chain;
use ferrohealth_smart::resource::Access;
use http::{HeaderValue, StatusCode, header};
use serde_json::{Value, json};

use crate::audit::{self, Connected, Happening, RecordFailure};
use crate::clients::{Client, ClientError};
use crate::server::AppState;
use crate::store::admin::Registered;
use crate::store::{StoreError, Transaction};

use document::{ClientDocument, ClientView};

/// The registry.
pub const CLIENTS_ROUTE: &str = "/admin/clients";
/// One client.
pub const CLIENT_ROUTE: &str = "/admin/clients/{client_id}";
/// Disabling one client.
pub const DISABLE_ROUTE: &str = "/admin/clients/{client_id}/disable";
/// Enabling one disabled client.
pub const ENABLE_ROUTE: &str = "/admin/clients/{client_id}/enable";
/// One client's organisation approval, which `DELETE` withdraws.
pub const APPROVAL_ROUTE: &str = "/admin/clients/{client_id}/organisation_approval";
/// The signing key ring.
pub const KEYS_ROUTE: &str = "/admin/keys";

/// Returns the admin routes, each behind the guard.
pub fn router(state: &Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route(CLIENTS_ROUTE, get(list).post(create))
        .route(CLIENT_ROUTE, get(read).put(update))
        .route(DISABLE_ROUTE, post(disable))
        .route(ENABLE_ROUTE, post(enable))
        .route(APPROVAL_ROUTE, delete(withdraw))
        .route(KEYS_ROUTE, get(keys))
        .layer(DefaultBodyLimit::max(DOCUMENT_LIMIT))
        .route_layer(guard::layer(Arc::clone(state)))
}

/// Why an admin request is refused, each answered with its status and an
/// error code.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    /// The body is no client document: not `application/json`, over
    /// [`DOCUMENT_LIMIT`], not JSON, or a member the document does not have.
    #[error("the body is no client document")]
    Unreadable(#[source] JsonRejection),
    /// The document names another client than the path.
    #[error("the document's client_id is not the path's")]
    OtherClient,
    /// The registration breaks a rule of the registry.
    #[error(transparent)]
    Metadata(#[from] ClientError),
    /// The client names a provider the configuration does not.
    #[error("the client `{client_id}` names the provider `{name}`, which is not configured")]
    UnknownUpstream {
        /// The client.
        client_id: String,
        /// The name.
        name: String,
    },
    /// The client names a resource server the configuration does not.
    #[error("the client `{client_id}` names the resource `{base}`, which is not configured")]
    UnknownResource {
        /// The client.
        client_id: String,
        /// The base.
        base: String,
    },
    /// No client is registered under the id.
    #[error("no client is registered as `{0}`")]
    NotFound(String),
    /// A client is registered under the id already.
    #[error("a client is registered as `{0}` already")]
    Exists(String),
    /// Another client registers the launch URL.
    #[error("another client registers the launch URL")]
    LaunchUriTaken,
    /// The change asks for the state the client is in already.
    #[error("{0}")]
    Unchanged(&'static str),
    /// The store failed.
    #[error("the registry cannot be read or written")]
    Store(#[source] StoreError),
    /// The change could not be committed with its record.
    #[error("the change cannot be recorded")]
    Record(#[source] RecordFailure),
}

impl From<StoreError> for AdminError {
    fn from(error: StoreError) -> Self {
        let taken = matches!(&error, StoreError::Database(sqlx::Error::Database(database))
            if database.constraint() == Some("client_launch_uri_key"));
        if taken {
            Self::LaunchUriTaken
        } else {
            Self::Store(error)
        }
    }
}

impl AdminError {
    /// Returns the status and the error code of the refusal: the RFC 7591
    /// §3.2.2 codes for a registration a rule refuses, our own otherwise.
    fn code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::Unreadable(rejection) => (rejection.status(), "invalid_request"),
            Self::OtherClient => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::Metadata(ClientError::RedirectUri { .. }) => {
                (StatusCode::BAD_REQUEST, "invalid_redirect_uri")
            }
            Self::Metadata(_) | Self::UnknownUpstream { .. } | Self::UnknownResource { .. } => {
                (StatusCode::BAD_REQUEST, "invalid_client_metadata")
            }
            Self::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            Self::Exists(_) => (StatusCode::CONFLICT, "client_exists"),
            Self::LaunchUriTaken => (StatusCode::CONFLICT, "launch_uri_taken"),
            Self::Unchanged(_) => (StatusCode::CONFLICT, "unchanged"),
            Self::Store(_) | Self::Record(_) => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        }
    }
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        let (status, error) = self.code();
        let body = if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %chain(&self), "an admin request failed");
            json!({ "error": error })
        } else {
            json!({ "error": error, "error_description": self.to_string() })
        };
        no_store((status, Json(body)).into_response())
    }
}

/// A request on one client: the state, the client the path names, the
/// admin caller the guard admitted and the address it came from.
struct OnClient {
    /// The state.
    state: Arc<AppState>,
    /// The client the path names.
    client_id: String,
    /// The address the request came from.
    from: std::net::IpAddr,
    /// The admin caller.
    access: Access,
}

impl OnClient {
    /// Returns the change this request makes.
    fn change(&self) -> Change<'_> {
        Change::new(&self.state, &self.access, self.from)
    }
}

impl FromRequestParts<Arc<AppState>> for OnClient {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let Path(client_id) = Path::<String>::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;
        let Connected(from) = Connected::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;
        let access = Access::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;
        Ok(Self {
            state: Arc::clone(state),
            client_id,
            from,
            access,
        })
    }
}

/// Returns `response` marked never to be stored (RFC 9111 §5.2.2.5).
fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Returns the answer naming `registered`.
fn answer(status: StatusCode, registered: &Registered) -> Response {
    no_store((status, Json(ClientView::from(registered))).into_response())
}

/// The admin caller and where its request came from, as each change's
/// record names them.
struct Change<'a> {
    /// The state.
    state: &'a AppState,
    /// The admin client.
    by: Option<&'a str>,
    /// The address the request came from.
    from: std::net::IpAddr,
}

/// What a change's record says: the event, the client changed, the
/// details, and the approval it withdrew with the grants revoked on it.
struct Record<'a> {
    /// What happened.
    event: audit::Event,
    /// The client changed.
    client_id: &'a str,
    /// What the record holds of the change.
    details: Vec<(&'static str, String)>,
    /// The approval withdrawn, with the grants revoked on it.
    withdrawn: Option<(&'a crate::clients::Approval, u64)>,
}

impl<'a> Change<'a> {
    /// Returns the change `access` makes from `from`.
    fn new(state: &'a AppState, access: &'a Access, from: std::net::IpAddr) -> Self {
        Self {
            state,
            by: access.caller().and_then(|caller| caller.client_id()),
            from,
        }
    }

    /// Opens the change's transaction with the row of `client_id` locked.
    async fn lock(&self, client_id: &str) -> Result<(Transaction, Registered), AdminError> {
        let mut tx = self.state.store().begin().await?;
        let stored = tx
            .lock_client(client_id)
            .await?
            .ok_or_else(|| AdminError::NotFound(client_id.to_owned()))?;
        Ok((tx, stored))
    }

    /// Commits `tx` with `record`, the record of the approval it withdrew
    /// first, and answers with the client as the store then holds it.
    async fn finish(
        &self,
        mut tx: Transaction,
        record: Record<'_>,
        status: StatusCode,
    ) -> Result<Response, AdminError> {
        let client_id = record.client_id;
        let endpoint = self
            .state
            .settings()
            .endpoint_url(&format!("{CLIENTS_ROUTE}/{client_id}"));
        let happening = |event, mut details: Vec<(&'static str, String)>| {
            details.insert(0, ("client", client_id.to_owned()));
            Happening {
                event,
                issuer: self.state.settings().issuer.as_str(),
                client_id: self.by,
                subject: None,
                from: self.from,
                endpoint: &endpoint,
                details,
            }
        };
        if let Some((approval, revoked)) = record.withdrawn {
            let withdrawn = happening(
                audit::Event::ApprovalWithdrawn,
                crate::approvals::withdrawn_details(approval, revoked),
            );
            let row = self
                .state
                .audit()
                .row(
                    &audit::happened(&withdrawn),
                    withdrawn.event.code(),
                    None,
                    self.by,
                )
                .map_err(AdminError::Record)?;
            tx.record(&row).await?;
        }
        self.state
            .audit()
            .commit_happening(tx, &happening(record.event, record.details))
            .await
            .map_err(AdminError::Record)?;
        tracing::info!(
            target: "ferrosmart::audit",
            event = record.event.code(),
            client_id = %client_id,
            "the admin API changed a client"
        );
        let registered = self
            .state
            .store()
            .registered_client(client_id)
            .await?
            .ok_or_else(|| AdminError::NotFound(client_id.to_owned()))?;
        Ok(answer(status, &registered))
    }
}

/// What a change's record says of `client`: never a secret or a key.
fn described(client: &Client) -> Vec<(&'static str, String)> {
    let grants: Vec<&str> = client
        .grant_types
        .iter()
        .map(|grant| grant.as_str())
        .collect();
    vec![
        ("kind", client.kind.as_str().to_owned()),
        ("scope", client.scopes.join(" ")),
        ("grant_types", grants.join(" ")),
    ]
}

/// Checks that every provider and every resource server `client` names is
/// configured.
fn check_names(state: &AppState, client: &Client) -> Result<(), AdminError> {
    let settings = state.settings();
    if let Some(base) = client
        .resources
        .iter()
        .find(|base| !settings.resources.contains(base))
    {
        return Err(AdminError::UnknownResource {
            client_id: client.client_id.clone(),
            base: base.clone(),
        });
    }
    let upstreams = &settings.upstreams;
    match client
        .upstreams
        .iter()
        .find(|name| !upstreams.iter().any(|upstream| upstream.name == **name))
    {
        Some(name) => Err(AdminError::UnknownUpstream {
            client_id: client.client_id.clone(),
            name: name.clone(),
        }),
        None => Ok(()),
    }
}

/// The largest client document the admin API reads, in bytes: room for a
/// JWK Set by value with a few keys. No specification governs the value:
/// our own design.
pub const DOCUMENT_LIMIT: usize = 64 * 1024;

/// Returns the client document the request carried: an `application/json`
/// body of at most [`DOCUMENT_LIMIT`] bytes into the closed
/// [`ClientDocument`], whose unknown members refuse it, every value then
/// checked by the registry's rules before anything is stored.
fn document(
    body: Result<Json<ClientDocument>, JsonRejection>,
) -> Result<ClientDocument, AdminError> {
    body.map(|Json(document)| document)
        .map_err(AdminError::Unreadable)
}

/// `GET /admin/clients`: every registered client, disabled ones included.
async fn list(State(state): State<Arc<AppState>>) -> Result<Response, AdminError> {
    let registered = state.store().registered().await?;
    let clients: Vec<ClientView<'_>> = registered.iter().map(ClientView::from).collect();
    Ok(no_store(
        Json(json!({ "clients": clients })).into_response(),
    ))
}

/// `GET /admin/clients/{client_id}`.
async fn read(
    State(state): State<Arc<AppState>>,
    Path(client_id): Path<String>,
) -> Result<Response, AdminError> {
    let registered = state
        .store()
        .registered_client(&client_id)
        .await?
        .ok_or(AdminError::NotFound(client_id))?;
    Ok(answer(StatusCode::OK, &registered))
}

/// `POST /admin/clients`: registers the client the body describes.
async fn create(
    State(state): State<Arc<AppState>>,
    Connected(from): Connected,
    access: Access,
    body: Result<Json<ClientDocument>, JsonRejection>,
) -> Result<Response, AdminError> {
    let document = document(body)?;
    let client_id = document.client_id().to_owned();
    let (section, material) =
        document.registration(&client_id, None, jiff::Timestamp::now().as_second());
    let client = crate::clients::resolve_with(&section, material)?;
    check_names(&state, &client)?;
    let mut tx = state.store().begin().await?;
    if !tx.create_client(&client).await? {
        return Err(AdminError::Exists(client_id));
    }
    let record = Record {
        event: audit::Event::ClientCreated,
        client_id: &client_id,
        details: described(&client),
        withdrawn: None,
    };
    let mut response = Change::new(&state, &access, from)
        .finish(tx, record, StatusCode::CREATED)
        .await?;
    let location = state
        .settings()
        .endpoint(&format!("{CLIENTS_ROUTE}/{client_id}"));
    // NOTE: RFC 9110 §10.2.2, the issuer and the client id make a URI; one that
    // is no header value leaves the Location off, the client created all the same.
    if let Ok(location) = HeaderValue::from_str(&location) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    Ok(response)
}

/// `PUT /admin/clients/{client_id}`: replaces the client with the body's.
/// An organisation approval the body no longer gives in the same form is
/// withdrawn, every grant issued on it revoked with its tokens.
async fn update(
    on: OnClient,
    body: Result<Json<ClientDocument>, JsonRejection>,
) -> Result<Response, AdminError> {
    let (change, client_id) = (on.change(), on.client_id.as_str());
    let document = document(body)?;
    if !document.client_id().is_empty() && document.client_id() != client_id {
        return Err(AdminError::OtherClient);
    }
    let (mut tx, stored) = change.lock(client_id).await?;
    let (section, material) = document.registration(
        client_id,
        Some(&stored.client),
        jiff::Timestamp::now().as_second(),
    );
    let client = crate::clients::resolve_with(&section, material)?;
    check_names(&on.state, &client)?;
    let lapsed = stored
        .client
        .approval()
        .filter(|approval| client.approval() != Some(*approval));
    let withdrawn = match lapsed {
        Some(approval) => Some((
            approval,
            tx.withdraw_approval(client_id, approval.approved_at)
                .await?,
        )),
        None => None,
    };
    tx.update_client(&client).await?;
    let record = Record {
        event: audit::Event::ClientUpdated,
        client_id,
        details: described(&client),
        withdrawn,
    };
    change.finish(tx, record, StatusCode::OK).await
}

/// `POST /admin/clients/{client_id}/disable`: no request finds the client
/// again, and every grant and token it holds is revoked.
async fn disable(on: OnClient) -> Result<Response, AdminError> {
    let (change, client_id) = (on.change(), on.client_id.as_str());
    let (mut tx, stored) = change.lock(client_id).await?;
    if stored.disabled_at.is_some() {
        return Err(AdminError::Unchanged("the client is disabled already"));
    }
    let ended = tx.disable_client(client_id).await?;
    let details = vec![
        ("revoked", ended.grants.to_string()),
        ("access_tokens", ended.access_tokens.to_string()),
        ("consents", ended.consents.to_string()),
    ];
    let record = Record {
        event: audit::Event::ClientDisabled,
        client_id,
        details,
        withdrawn: None,
    };
    change.finish(tx, record, StatusCode::OK).await
}

/// `POST /admin/clients/{client_id}/enable`.
async fn enable(on: OnClient) -> Result<Response, AdminError> {
    let (change, client_id) = (on.change(), on.client_id.as_str());
    let (mut tx, _stored) = change.lock(client_id).await?;
    if !tx.enable_client(client_id).await? {
        return Err(AdminError::Unchanged("the client is not disabled"));
    }
    let record = Record {
        event: audit::Event::ClientEnabled,
        client_id,
        details: Vec::new(),
        withdrawn: None,
    };
    change.finish(tx, record, StatusCode::OK).await
}

/// `DELETE /admin/clients/{client_id}/organisation_approval`: withdraws the
/// approval, every grant issued on it revoked with its tokens.
async fn withdraw(on: OnClient) -> Result<Response, AdminError> {
    let (change, client_id) = (on.change(), on.client_id.as_str());
    let (mut tx, stored) = change.lock(client_id).await?;
    let approval = stored
        .client
        .approval()
        .cloned()
        .ok_or(AdminError::Unchanged(
            "the client holds no organisation approval",
        ))?;
    let revoked = tx
        .withdraw_approval(client_id, approval.approved_at)
        .await?;
    tx.clear_approval(client_id).await?;
    let record = Record {
        event: audit::Event::ClientUpdated,
        client_id,
        details: vec![("organisation_approval", String::from("withdrawn"))],
        withdrawn: Some((&approval, revoked)),
    };
    change.finish(tx, record, StatusCode::OK).await
}

/// `GET /admin/keys`: the signing key ring, each public key with its
/// state: `active` signs, `next` is published ahead of a rotation, and
/// `retiring` is the previous key, published while its overlap lasts
/// (`docs/architecture.md` §13.11). The private keys stay in the files
/// the configuration names; the API never carries one.
async fn keys(State(state): State<Arc<AppState>>) -> Response {
    let ring = &state.settings().keys;
    let now = std::time::Instant::now();
    let mut keys: Vec<Value> =
        vec![json!({ "state": "active", "jwk": ring.current().public_jwk() })];
    if let Some(retiring) = ring.retiring() {
        keys.push(json!({
            "state": "retiring",
            "published": ring.previous_at(now).is_some(),
            "jwk": retiring.public_jwk(),
        }));
    }
    if let Some(next) = ring.next() {
        keys.push(json!({ "state": "next", "jwk": next.public_jwk() }));
    }
    no_store(Json(json!({ "keys": keys })).into_response())
}
