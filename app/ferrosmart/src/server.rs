// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The routes and the stack around them.
//!
//! The issuer's routes sit under `[server] base_path`, which is the
//! issuer's path; the RFC 8414 metadata sits beside it at the root, the
//! well-known suffix inserted between the host and the issuer's path
//! (RFC 8414 §3). The discovery documents and the JWK Set answer any
//! origin (SMART App Launch 2.2.0, Considerations for CORS support: "For
//! requests from any origin, CORS configuration permits access to the
//! public discovery endpoints").

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use ferrohealth_health::lifecycle::Lifecycle;
use ferrohealth_health::registry::{Check, HealthIndicator, Outcome, Registry};
use ferrohealth_server::health::Health;
use ferrohealth_server::stack::{Stack, StackPolicy};
use http::{HeaderValue, StatusCode, header};
use serde_json::Value;

use crate::audit::Audit;
use crate::authorize::{self, AUTHORIZE_ROUTE, CALLBACK_ROUTE, CONSENT_ROUTE, MANAGE_ROUTE};
use crate::client_keys::ClientKeySets;
use crate::config::settings::Settings;
use crate::discovery::{
    self, INTROSPECT_ROUTE, JWKS_ROUTE, OPENID_CONFIGURATION_ROUTE, REVOKE_ROUTE,
    SMART_CONFIGURATION_ROUTE, TOKEN_ROUTE, UPSTREAM_JWKS_ROUTE,
};
use crate::store::Store;
use crate::upstream::Providers;

/// The `Cache-Control` of the JWK Set: an hour, and a next key is published
/// at least that long before it signs (`docs/architecture.md` §13.11). No
/// specification governs the value: our own design.
pub const JWKS_CACHE_CONTROL: &str = "public, max-age=3600";

/// The `max-age` of [`JWKS_CACHE_CONTROL`].
pub const JWKS_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(3600);

/// The routes that answer a person's browser with a page.
///
/// They are the consent page, the patient picker, the management page, and
/// the error pages the authorization endpoint and the upstream callback
/// draw. The book shows each (`website/book/src/integrate/img/`).
pub const PAGES: [&str; 7] = [
    AUTHORIZE_ROUTE,
    CALLBACK_ROUTE,
    CONSENT_ROUTE,
    crate::picker::PICKER_ROUTE,
    MANAGE_ROUTE,
    crate::logout::end_session::END_SESSION_ROUTE,
    authorize::choose::LOGIN_ROUTE,
];

/// What every request reads.
#[derive(Debug)]
pub struct AppState {
    /// The settings the server runs on.
    settings: Settings,
    /// The RFC 8414 metadata document, built once.
    metadata: Value,
    /// The SMART configuration, built once.
    smart: Value,
    /// The OpenID Connect discovery document, once people log in.
    openid: Option<Value>,
    /// The process's phase, which the drain moves.
    lifecycle: Lifecycle,
    /// The store.
    store: Store,
    /// The clients' JWK Sets.
    client_keys: ClientKeySets,
    /// The upstream providers people log in at.
    providers: Providers,
    /// The audit lane every login and token is recorded in.
    audit: Audit,
    /// The HTTP client the patient picker searches the resource servers
    /// with.
    fhir: reqwest::Client,
    /// The User Access Brands Bundle as served, when the deployment
    /// publishes one.
    brands: Option<crate::brands::Published>,
}

impl AppState {
    /// Returns the state of the server `settings` describe over `store`,
    /// recording in `audit`.
    #[must_use]
    pub fn new(settings: Settings, store: Store, audit: Audit) -> Self {
        let metadata = discovery::metadata(&settings, false);
        let smart = discovery::smart_configuration(&settings, &metadata, false);
        Self {
            metadata: discovery::metadata_document(&metadata),
            settings,
            smart,
            openid: None,
            lifecycle: Lifecycle::default(),
            store,
            client_keys: ClientKeySets::new(reqwest::Client::new()),
            providers: Providers::default(),
            audit,
            fhir: reqwest::Client::new(),
            brands: None,
        }
    }

    /// Returns this state serving `brands` at `{issuer}/brands`.
    #[must_use]
    pub fn with_brands(mut self, brands: crate::brands::Published) -> Self {
        self.brands = Some(brands);
        self
    }

    /// Returns the Brands Bundle as served, when the deployment publishes
    /// one.
    #[must_use]
    pub const fn brands(&self) -> Option<&crate::brands::Published> {
        self.brands.as_ref()
    }

    /// Returns this state logging people in at `providers`, and serving the
    /// authorization code flow when there is one.
    #[must_use]
    pub fn with_login(mut self, providers: Providers) -> Self {
        if providers.is_empty() {
            return self;
        }
        let metadata = discovery::metadata(&self.settings, true);
        self.smart = discovery::smart_configuration(&self.settings, &metadata, true);
        let mut openid = discovery::openid_configuration(&metadata);
        discovery::add_acr_values(&mut openid, &self.settings);
        self.openid = Some(openid);
        self.metadata = discovery::metadata_document(&metadata);
        discovery::add_acr_values(&mut self.metadata, &self.settings);
        self.providers = providers;
        self
    }

    /// Returns the upstream providers people log in at.
    #[must_use]
    pub const fn providers(&self) -> &Providers {
        &self.providers
    }

    /// Returns the clients' JWK Sets.
    #[must_use]
    pub const fn client_keys(&self) -> &ClientKeySets {
        &self.client_keys
    }

    /// Returns the HTTP client of the patient picker.
    #[must_use]
    pub const fn fhir(&self) -> &reqwest::Client {
        &self.fhir
    }

    /// Returns the audit lane.
    #[must_use]
    pub const fn audit(&self) -> &Audit {
        &self.audit
    }

    /// Returns the store.
    #[must_use]
    pub const fn store(&self) -> &Store {
        &self.store
    }

    /// Returns the settings.
    #[must_use]
    pub const fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Returns the process's phase.
    #[must_use]
    pub const fn lifecycle(&self) -> &Lifecycle {
        &self.lifecycle
    }
}

/// Returns the whole application: the routes inside the family's stack.
pub fn router(state: Arc<AppState>) -> Router {
    let registry = Registry::new(vec![Arc::new(Database(state.store.clone()))]);
    let health = Health::new(registry, state.lifecycle.clone());
    let section = state.settings.server.clone();
    let mut issuer = Router::new()
        .route(SMART_CONFIGURATION_ROUTE, get(smart_configuration))
        .route(JWKS_ROUTE, get(jwks))
        .route(UPSTREAM_JWKS_ROUTE, get(upstream_jwks))
        .route(TOKEN_ROUTE, post(crate::token::token))
        .route(crate::launch::LAUNCH_ROUTE, post(crate::launch::launch))
        .route(
            crate::audit_log::AUDIT_ROUTE,
            get(crate::audit_log::audit_log),
        )
        .route(INTROSPECT_ROUTE, post(crate::introspect::introspect))
        .route(REVOKE_ROUTE, post(crate::revoke::revoke))
        .route(OPENID_CONFIGURATION_ROUTE, get(openid_configuration))
        .route(
            AUTHORIZE_ROUTE,
            get(authorize::request::authorize_get).post(authorize::request::authorize_post),
        )
        .route(CALLBACK_ROUTE, get(authorize::callback::callback))
        .route(
            crate::upstream::saml::METADATA_ROUTE,
            get(authorize::saml::metadata),
        )
        .route(
            crate::upstream::saml::ACS_ROUTE,
            get(authorize::saml::acs).post(authorize::saml::acs),
        )
        .route(
            authorize::choose::LOGIN_ROUTE,
            get(authorize::choose::choose_get).post(authorize::choose::choose_post),
        )
        .route(
            crate::logout::BACKCHANNEL_LOGOUT_ROUTE,
            post(crate::logout::backchannel_logout),
        )
        .route(
            crate::logout::front::FRONTCHANNEL_LOGOUT_ROUTE,
            // NOTE: Front-Channel Logout 1.0 §2, the provider frames the URI, so it sets
            // its own headers and the stack's frame refusal stays off it.
            get(crate::logout::front::frontchannel_logout).layer(axum::middleware::map_response(
                ferrohealth_server::api_headers::exempt,
            )),
        )
        .route(
            crate::logout::end_session::END_SESSION_ROUTE,
            get(crate::logout::end_session::end_session_get)
                .post(crate::logout::end_session::end_session_post),
        )
        .route(
            crate::logout::end_session::END_SESSION_CONFIRM_ROUTE,
            post(crate::logout::end_session::end_session_confirm),
        )
        .route(
            crate::logout::end_session::END_SESSION_RETURN_ROUTE,
            get(crate::logout::end_session::end_session_return),
        )
        .route(
            CONSENT_ROUTE,
            get(authorize::consent::consent_get).post(authorize::consent::consent_post),
        )
        .route(
            crate::picker::PICKER_ROUTE,
            get(crate::picker::picker_get).post(crate::picker::picker_post),
        )
        .route(
            MANAGE_ROUTE,
            get(authorize::manage::manage_get).post(authorize::manage::manage_post),
        )
        .merge(crate::admin::router(&state))
        .merge(crate::admin::register::router())
        .with_state(Arc::clone(&state));
    if state.brands.is_some() {
        issuer = issuer.route(
            crate::brands::BRANDS_ROUTE,
            get(crate::brands::brands).with_state(Arc::clone(&state)),
        );
    }
    // NOTE: FerroUI docs/consoles.md, "How a console builds": the asset router at
    // its prefix, from the root, the path the shell's tags name.
    let beside = Router::new()
        .route(&state.settings.metadata_path(), get(metadata))
        .with_state(state)
        .nest_service(
            ferrohealth_ui::serve::PREFIX,
            ferrohealth_ui::serve::axum_router::router::<()>(),
        );
    Stack::new(issuer, health, &section, StackPolicy::default())
        .beside(beside)
        .into_router()
}

/// `GET /.well-known/oauth-authorization-server{path}` (RFC 8414 §3).
async fn metadata(State(state): State<Arc<AppState>>) -> Response {
    public(Json(&state.metadata).into_response())
}

/// `GET {issuer}/.well-known/smart-configuration`, answered as
/// `application/json` whatever the `Accept` header (SMART App Launch 2.2.0,
/// Conformance, Using well-known).
async fn smart_configuration(State(state): State<Arc<AppState>>) -> Response {
    public(Json(&state.smart).into_response())
}

/// `GET {issuer}/.well-known/openid-configuration` (OpenID Connect
/// Discovery 1.0 §4), served once people log in, since the document
/// describes an OpenID Provider.
async fn openid_configuration(State(state): State<Arc<AppState>>) -> Response {
    match &state.openid {
        Some(document) => public(Json(document).into_response()),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// `GET {issuer}/jwks`, the JWK Set (RFC 7517 §5), cacheable as
/// [`JWKS_CACHE_CONTROL`] says.
async fn jwks(State(state): State<Arc<AppState>>) -> Response {
    let mut response = public(Json(state.settings.keys.ring().published()).into_response());
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(JWKS_CACHE_CONTROL),
    );
    response
}

/// `GET {issuer}/upstream-jwks`, the JWK Set of the client assertion keys
/// (RFC 7517 §5), when people log in at an upstream provider; `404`
/// otherwise.
async fn upstream_jwks(State(state): State<Arc<AppState>>) -> Response {
    // NOTE: RFC 7517 §5, one set of every provider's assertion keys; each
    // provider's registration finds its own by kid.
    let mut keys: Vec<Value> = Vec::new();
    for set in state
        .settings
        .upstreams
        .iter()
        .filter_map(crate::upstream::Upstream::assertion_keys)
    {
        for key in set
            .get("keys")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if !keys.contains(key) {
                keys.push(key.clone());
            }
        }
    }
    if state.settings.upstreams.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let set = serde_json::json!({ "keys": keys });
    let mut response = public(Json(set).into_response());
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(JWKS_CACHE_CONTROL),
    );
    response
}

/// Returns `response` readable from any origin.
fn public(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}

/// The readiness indicator of the database: down while it answers no
/// statement, naming no URL and no error text.
#[derive(Debug)]
struct Database(Store);

impl HealthIndicator for Database {
    fn name(&self) -> &'static str {
        "database"
    }

    fn check(&self) -> Check<'_> {
        Box::pin(async {
            match self.0.ping().await {
                Ok(()) => Outcome::up(),
                Err(_unreachable) => Outcome::down("the database answers no statement"),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_jwks_max_age_is_the_cache_control_s() {
        assert_eq!(
            format!("public, max-age={}", JWKS_MAX_AGE.as_secs()),
            JWKS_CACHE_CONTROL
        );
    }
}
