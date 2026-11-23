// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The admin API: `/admin/clients` over the registry every replica reads,
//! and `/admin/keys`, the signing key ring (`docs/architecture.md` §13.8).
//!
//! [`apply`] writes a client document the way the API does, for `ferrosmart
//! client apply`. Every change commits with its audit record, and a change
//! that clears a first-party mark or disables a client revokes the grants
//! and tokens it covered in the same transaction, so the next
//! request at any replica sees it. No specification governs the admin API:
//! our own design, since RFC 6749 §2 leaves registration to the server.

pub mod document;
pub mod guard;
pub mod register;

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequestParts, Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use ferrohealth_server::run::chain;
use ferrohealth_smart::resource::Access;
use http::{HeaderValue, StatusCode, header};
use serde_json::{Value, json};

use crate::audit::{self, Connected, Happening, RecordFailure};
use crate::clients::{Client, ClientError, ClientMetadata, Material};
use crate::server::AppState;
use crate::store::admin::Registered;
use crate::store::{StoreError, Transaction};

use document::{ClientDocument, ClientView};

/// The registry.
pub const CLIENTS_ROUTE: &str = "/admin/clients";
/// Disabling one client.
pub const DISABLE_ROUTE: &str = "/admin/clients/{client_id}/disable";
/// Enabling one disabled client.
pub const ENABLE_ROUTE: &str = "/admin/clients/{client_id}/enable";
/// A confidential symmetric client's new secret.
pub const SECRET_ROUTE: &str = "/admin/clients/{client_id}/secret";
/// The signing key ring.
pub const KEYS_ROUTE: &str = "/admin/keys";

/// Returns the admin routes, each behind the guard.
pub fn router(state: &Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route(CLIENTS_ROUTE, get(list))
        .route(DISABLE_ROUTE, post(disable))
        .route(ENABLE_ROUTE, post(enable))
        .route(SECRET_ROUTE, post(secret))
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
    /// No client secret could be issued.
    #[error("no client secret can be issued")]
    Secret(#[source] crate::clients::HashError),
    /// The client authenticates with no secret.
    #[error("the client `{0}` authenticates with no client secret")]
    NoSecret(String),
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
            Self::OtherClient | Self::NoSecret(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
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
            Self::Store(_) | Self::Record(_) | Self::Secret(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "server_error")
            }
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

/// A request on one client: the state, the client the path names and the
/// address it came from.
pub(super) struct OnClient {
    /// The state.
    state: Arc<AppState>,
    /// The client the path names.
    client_id: String,
    /// The address the request came from.
    from: std::net::IpAddr,
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
        Ok(Self {
            state: Arc::clone(state),
            client_id,
            from,
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

/// Returns the answer naming the client `applied` wrote with the members
/// `extra` holds, and the secret it issued, if any, with
/// `client_secret_expires_at` 0 for a secret that does not expire (RFC 7591
/// §3.2.1).
fn issued(status: StatusCode, applied: &Applied, extra: Value) -> Response {
    let mut body = json!(ClientView::from(&applied.registered));
    if let Some(members) = body.as_object_mut() {
        if let Some(secret) = &applied.secret {
            members.insert(
                String::from("client_secret"),
                Value::from(secrecy::ExposeSecret::expose_secret(secret)),
            );
            members.insert(String::from("client_secret_expires_at"), Value::from(0));
        }
        if let Value::Object(extra) = extra {
            members.extend(extra);
        }
    }
    no_store((status, Json(body)).into_response())
}

/// Returns the answer naming `registered`.
fn answer(status: StatusCode, registered: &Registered) -> Response {
    no_store((status, Json(ClientView::from(registered))).into_response())
}

/// Who `ferrosmart client apply` is in the record of each change it makes.
pub const APPLY_REQUESTER: &str = "ferrosmart client apply";

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

/// What a change's record says: the event, the client changed and the
/// details.
struct Record<'a> {
    /// What happened.
    event: audit::Event,
    /// The client changed.
    client_id: &'a str,
    /// What the record holds of the change.
    details: Vec<(&'static str, String)>,
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

    /// Commits `tx` with `record` and returns the client as the store then
    /// holds it.
    async fn finish(&self, tx: Transaction, record: Record<'_>) -> Result<Registered, AdminError> {
        let client_id = record.client_id;
        self.record(tx, record).await?;
        self.state
            .store()
            .registered_client(client_id)
            .await?
            .ok_or_else(|| AdminError::NotFound(client_id.to_owned()))
    }

    /// Commits `tx` with `record`.
    async fn record(&self, tx: Transaction, record: Record<'_>) -> Result<(), AdminError> {
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
        self.state
            .audit()
            .commit_happening(tx, &happening(record.event, record.details))
            .await
            .map_err(AdminError::Record)?;
        tracing::info!(
            target: "ferrosmart::audit",
            event = record.event.code(),
            client_id = %client_id,
            "a client was changed"
        );
        Ok(())
    }

    /// Registers the client `section` and `material` describe in `tx`, as
    /// one that registered itself when `itself`.
    async fn create(
        &self,
        mut tx: Transaction,
        section: &ClientMetadata,
        mut material: Material,
        itself: bool,
        registration_token: Option<&str>,
    ) -> Result<Applied, AdminError> {
        let client_id = section.client_id.clone();
        let secret = issue(section, &mut material)?;
        let mut client = crate::clients::resolve(section, material)?;
        if itself {
            client.registration = crate::clients::Registration::Dynamic;
        }
        check_names(self.state, &client)?;
        if !tx.create_client(&client).await? {
            return Err(AdminError::Exists(client_id));
        }
        if let Some(hash) = registration_token {
            tx.set_registration_token(&client_id, hash).await?;
        }
        let record = Record {
            event: audit::Event::ClientCreated,
            client_id: &client_id,
            details: described(&client),
        };
        Ok(Applied {
            registered: self.finish(tx, record).await?,
            created: true,
            secret,
        })
    }

    /// Replaces the client `stored`, its row locked in `tx`, with the one
    /// `section` and `material` describe, registered by whoever registered
    /// `stored`. Clearing its first-party mark revokes every grant issued
    /// with no page on it, with its tokens.
    async fn replace(
        &self,
        mut tx: Transaction,
        stored: &Registered,
        section: &ClientMetadata,
        mut material: Material,
    ) -> Result<Applied, AdminError> {
        let client_id = stored.client.client_id.as_str();
        let secret = issue(section, &mut material)?;
        let mut client = crate::clients::resolve(section, material)?;
        if stored.client.registered_itself() {
            client.registration = crate::clients::Registration::Dynamic;
        }
        check_names(self.state, &client)?;
        let mut details = described(&client);
        if stored.client.first_party() && !client.first_party() {
            let revoked = tx.revoke_first_party(client_id).await?;
            details.push(("first_party", String::from("cleared")));
            details.push(("revoked", revoked.to_string()));
        }
        tx.update_client(&client).await?;
        let record = Record {
            event: audit::Event::ClientUpdated,
            client_id,
            details,
        };
        Ok(Applied {
            registered: self.finish(tx, record).await?,
            created: false,
            secret,
        })
    }
}

/// Issues a client secret into `material` when `section` authenticates
/// with one and holds none yet, and returns it (RFC 7591 §3.2.1).
fn issue(
    section: &ClientMetadata,
    material: &mut Material,
) -> Result<Option<secrecy::SecretString>, AdminError> {
    let symmetric = section.auth_method.kind() == crate::clients::ClientKind::ConfidentialSymmetric;
    if !symmetric || material.secret_hash.is_some() {
        return Ok(None);
    }
    let issued = crate::clients::issue_secret().map_err(AdminError::Secret)?;
    material.secret_hash = Some(issued.hash);
    Ok(Some(issued.secret))
}

/// What [`apply`] did with one document.
#[derive(Debug)]
pub struct Applied {
    /// The client as the store holds it.
    pub registered: Registered,
    /// Whether the client was new; otherwise it replaced the stored one.
    pub created: bool,
    /// The client secret issued with the change, which no answer repeats.
    pub secret: Option<secrecy::SecretString>,
}

/// Writes the client `document` describes as `PUT` would, or as `POST`
/// would when no client has its `client_id`, through the same checks and
/// with the same records, naming [`APPLY_REQUESTER`] from this host.
///
/// # Errors
/// Returns [`AdminError`] for a document the registry refuses and for a
/// store or record that fails; nothing is written then.
pub async fn apply(state: &AppState, document: ClientDocument) -> Result<Applied, AdminError> {
    let change = Change {
        state,
        by: Some(APPLY_REQUESTER),
        from: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
    };
    let mut tx = state.store().begin().await?;
    let client_id = document.client_id().to_owned();
    if let Some(stored) = tx.lock_client(&client_id).await? {
        let (section, material) = document.registration(&client_id, Some(&stored.client));
        return change.replace(tx, &stored, &section, material).await;
    }
    let (section, material) = document.registration(&client_id, None);
    change.create(tx, &section, material, false, None).await
}

/// Issues the confidential symmetric client `client_id` a new secret, its
/// hash replacing the stored one, recorded as [`apply`] records a change.
///
/// # Errors
/// Returns [`AdminError::NotFound`] for an unknown client,
/// [`AdminError::NoSecret`] for one that authenticates otherwise, and an
/// error of the store or the record.
pub async fn issue_secret(
    state: &AppState,
    client_id: &str,
) -> Result<secrecy::SecretString, AdminError> {
    let change = Change {
        state,
        by: Some(APPLY_REQUESTER),
        from: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
    };
    change.new_secret(client_id).await.map(|(_, secret)| secret)
}

impl Change<'_> {
    /// Issues the confidential symmetric client `client_id` a new secret,
    /// its hash replacing the stored one, with the change's record, and
    /// returns the client and the secret.
    async fn new_secret(
        &self,
        client_id: &str,
    ) -> Result<(Registered, secrecy::SecretString), AdminError> {
        let (mut tx, stored) = self.lock(client_id).await?;
        if stored.client.kind() != crate::clients::ClientKind::ConfidentialSymmetric {
            return Err(AdminError::NoSecret(client_id.to_owned()));
        }
        let issued = crate::clients::issue_secret().map_err(AdminError::Secret)?;
        tx.set_secret(client_id, &issued.hash).await?;
        let record = Record {
            event: audit::Event::ClientUpdated,
            client_id,
            details: vec![("client_secret", String::from("issued"))],
        };
        let registered = self.finish(tx, record).await?;
        Ok((registered, issued.secret))
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
        (
            "token_endpoint_auth_method",
            client.auth_method.as_str().to_owned(),
        ),
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

/// The largest client document the registration endpoint reads, in bytes: room for a
/// JWK Set by value with a few keys. No specification governs the value:
/// our own design.
pub const DOCUMENT_LIMIT: usize = 64 * 1024;

/// `GET /admin/clients`: every registered client, disabled ones included.
async fn list(State(state): State<Arc<AppState>>) -> Result<Response, AdminError> {
    let registered = state.store().registered().await?;
    let clients: Vec<ClientView<'_>> = registered.iter().map(ClientView::from).collect();
    Ok(no_store(
        Json(json!({ "clients": clients })).into_response(),
    ))
}

/// `POST /admin/clients/{client_id}/disable`: no request finds the client
/// again, and every grant and token it holds is revoked.
async fn disable(on: OnClient, access: Access) -> Result<Response, AdminError> {
    let change = Change::new(&on.state, &access, on.from);
    let client_id = on.client_id.as_str();
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
    };
    let registered = change.finish(tx, record).await?;
    Ok(answer(StatusCode::OK, &registered))
}

/// `POST /admin/clients/{client_id}/enable`.
async fn enable(on: OnClient, access: Access) -> Result<Response, AdminError> {
    let change = Change::new(&on.state, &access, on.from);
    let client_id = on.client_id.as_str();
    let (mut tx, _stored) = change.lock(client_id).await?;
    if !tx.enable_client(client_id).await? {
        return Err(AdminError::Unchanged("the client is not disabled"));
    }
    let record = Record {
        event: audit::Event::ClientEnabled,
        client_id,
        details: Vec::new(),
    };
    let registered = change.finish(tx, record).await?;
    Ok(answer(StatusCode::OK, &registered))
}

/// `POST /admin/clients/{client_id}/secret`: a new secret for a
/// confidential symmetric client, answered once with the client (RFC 7591
/// §3.2.1); the old secret no longer authenticates.
async fn secret(on: OnClient, access: Access) -> Result<Response, AdminError> {
    let change = Change::new(&on.state, &access, on.from);
    let (registered, secret) = change.new_secret(&on.client_id).await?;
    let applied = Applied {
        registered,
        created: false,
        secret: Some(secret),
    };
    Ok(issued(StatusCode::OK, &applied, Value::Null))
}

/// `GET /admin/keys`: the signing key ring this replica signs with, each
/// public key with its state: `active` signs, `next` is published ahead of
/// the rotation that makes it sign, and `retiring` stays published until
/// the tokens it signed have expired (`docs/architecture.md` §13.11). The
/// private keys stay in the files the configuration names; the API never
/// carries one.
async fn keys(State(state): State<Arc<AppState>>) -> Response {
    let ring = state.settings().keys.ring();
    let keys: Vec<Value> = std::iter::once(("active", ring.current()))
        .chain(ring.retiring().map(|key| ("retiring", key)))
        .chain(ring.next().map(|key| ("next", key)))
        .map(|(state, key)| json!({ "state": state, "jwk": key.public_jwk() }))
        .collect();
    no_store(Json(json!({ "keys": keys })).into_response())
}
