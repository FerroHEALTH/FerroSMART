// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! FerroSMART as a SMART Backend Services client (`docs/architecture.md`
//! §13.33).
//!
//! FerroSMART reads a patient for whom no runtime user authorization exists
//! yet as a Backend Services client of its own token endpoint: a
//! confidential client authenticated by a `private_key_jwt` assertion
//! (RFC 7523 §2.2) in the client credentials grant, scope [`SCOPE`] (SMART
//! App Launch 2.2.0, Backend Services). The token's `sub` is the client's
//! `client_id` (IHE IUA ITI-71 §3.71.4.2.2.1). The request runs through the
//! token endpoint's own grant and record in process, so its acquisition is
//! the endpoint's `IHE.IUA.71` record (IUA §3.71.5.1, BALP 1.1.4 3:5.7.5).
//!
//! Before each request FerroSMART checks its registration against
//! `[ferrosmart.backend]` and writes it when they differ, with its assertion
//! keys by value and the bases it reads: our own design.

use std::net::{IpAddr, Ipv4Addr};

use http::{HeaderMap, HeaderValue, header};
use serde::Serialize;
use serde_json::{Value, json};

use crate::clients::{AuthMethod, Client, ClientKeys, GrantType};
use crate::config::settings::Backend;
use crate::discovery::TOKEN_ROUTE;
use crate::server::AppState;

/// The one scope FerroSMART's Backend Services token carries (SMART App
/// Launch 2.2.0, Scopes for requesting clinical data).
pub const SCOPE: &str = "system/Patient.rs";

/// How long FerroSMART's client assertion lives, within the five minutes
/// SMART App Launch 2.2.0, Client Authentication: Asymmetric, allows. No
/// specification governs the value: our own design.
const ASSERTION_SECONDS: i64 = 60;

/// Why FerroSMART could not obtain its Backend Services token.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// `[ferrosmart.backend]` is not set.
    #[error("`[ferrosmart.backend]` is not set")]
    NotConfigured,
    /// The client could not be registered.
    #[error("FerroSMART's own client could not be registered")]
    Register(#[source] crate::admin::AdminError),
    /// The registry could not be read.
    #[error("the client registry could not be read")]
    Store(#[source] crate::store::StoreError),
    /// The assertion could not be signed.
    #[error("the client assertion could not be signed")]
    Sign(#[source] ferrohealth_smart::client::assertion::AssertionError),
    /// No assertion id could be drawn.
    #[error("no assertion id could be drawn")]
    Random(#[source] aws_lc_rs::error::Unspecified),
    /// The token request could not be recorded.
    #[error("the token request could not be recorded")]
    Record(#[source] crate::audit::RecordFailure),
    /// The token endpoint refused the request.
    #[error("the token endpoint refused FerroSMART's request: {error}")]
    Refused {
        /// The RFC 6749 §5.2 error code.
        error: &'static str,
    },
}

/// A Backend Services token FerroSMART holds for one read.
#[derive(Debug)]
pub(crate) struct Token {
    /// The access token.
    pub(crate) value: secrecy::SecretString,
    /// Its `jti`.
    pub(crate) jti: String,
    /// The client it was issued to, its `sub`.
    pub(crate) client_id: String,
}

/// The claims of FerroSMART's client assertion (RFC 7523 §3).
#[derive(Debug, Serialize)]
struct AssertionClaims<'a> {
    /// The client.
    iss: &'a str,
    /// The client.
    sub: &'a str,
    /// The token endpoint.
    aud: &'a str,
    /// The expiry.
    exp: i64,
    /// The issue time.
    iat: i64,
    /// The assertion's id.
    jti: &'a str,
}

/// Returns a Backend Services token for `audience`, requested from the
/// token endpoint as any backend client requests one.
///
/// # Errors
/// Returns [`BackendError`] when the client is not configured or cannot be
/// registered, the assertion cannot be signed, the request cannot be
/// recorded, or the endpoint refuses it.
pub(crate) async fn token(state: &AppState, audience: &str) -> Result<Token, BackendError> {
    let backend = configured(state)?;
    client(state).await?;
    let settings = state.settings();
    let now = jiff::Timestamp::now().as_second();
    let jti = crate::authorize::random().map_err(BackendError::Random)?;
    let token_url = settings.endpoint(TOKEN_ROUTE);
    let claims = AssertionClaims {
        iss: &backend.client_id,
        sub: &backend.client_id,
        aud: &token_url,
        exp: now.saturating_add(ASSERTION_SECONDS),
        iat: now,
        jti: &jti,
    };
    // NOTE: SMART App Launch 2.2.0, Client Authentication: Asymmetric, the
    // assertion's header names `typ` `JWT` and the `kid` of the signing key.
    let assertion = backend
        .keys
        .current()
        .sign("JWT", &claims)
        .map_err(BackendError::Sign)?;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "client_credentials")
        .append_pair("scope", SCOPE)
        .append_pair("resource", audience)
        .append_pair("client_assertion_type", crate::token::JWT_BEARER)
        .append_pair("client_assertion", &assertion)
        .finish();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    // NOTE: IUA §3.71.5.1, the record's source is the requesting system, which is
    // FerroSMART itself on its own host.
    let from = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let issued = crate::token::answered(state, &headers, body.as_bytes(), from, None)
        .await
        .map_err(BackendError::Record)?
        .map_err(|refusal| BackendError::Refused {
            error: refusal.error,
        })?;
    Ok(Token {
        jti: issued.jti().to_owned(),
        value: secrecy::SecretString::from(issued.response.access_token),
        client_id: backend.client_id.clone(),
    })
}

/// Returns FerroSMART's own client as the registry holds it, writing the
/// registration `[ferrosmart.backend]` describes when the registry holds
/// none or another.
///
/// # Errors
/// Returns [`BackendError`] when the client is not configured, the registry
/// cannot be read, or the registration is refused.
pub(crate) async fn client(state: &AppState) -> Result<Client, BackendError> {
    let backend = configured(state)?;
    let wanted = described(state, backend);
    let stored = state
        .store()
        .client(&backend.client_id)
        .await
        .map_err(BackendError::Store)?;
    if let Some(client) = stored.filter(|client| matches(client, &wanted)) {
        return Ok(client);
    }
    let document = serde_json::from_value(wanted).map_err(|_unread| BackendError::Refused {
        error: "invalid_client_metadata",
    })?;
    let applied = crate::admin::apply(state, document)
        .await
        .map_err(BackendError::Register)?;
    Ok(applied.registered.client)
}

/// Returns `[ferrosmart.backend]`.
fn configured(state: &AppState) -> Result<&Backend, BackendError> {
    state
        .settings()
        .backend
        .as_ref()
        .ok_or(BackendError::NotConfigured)
}

/// Returns the client document of `backend`: a confidential asymmetric
/// client of the client credentials grant, its keys by value, reaching every
/// FHIR base and patient index FerroSMART serves.
fn described(state: &AppState, backend: &Backend) -> Value {
    let settings = state.settings();
    let mut bases: Vec<&str> = settings
        .resources
        .iter()
        .filter(|base| !settings.openehr_resources.contains(base))
        .map(String::as_str)
        .chain(
            settings
                .patient_indexes
                .values()
                .map(|index| index.base.as_str()),
        )
        .collect();
    bases.sort_unstable();
    bases.dedup();
    json!({
        "client_id": backend.client_id,
        "client_name": settings.name,
        "token_endpoint_auth_method": AuthMethod::PrivateKeyJwt.as_str(),
        "jwks": backend.keys.published(),
        "grant_types": ["client_credentials"],
        "scope": SCOPE,
        "resources": bases,
    })
}

/// Returns whether the registered `client` is the one `wanted` describes.
fn matches(client: &Client, wanted: &Value) -> bool {
    let strings = |name: &str| -> Vec<String> {
        wanted
            .get(name)
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    client.auth_method == AuthMethod::PrivateKeyJwt
        && client.keys == wanted.get("jwks").cloned().map(ClientKeys::Set)
        && client.grant_types == [GrantType::ClientCredentials]
        && client.scopes == [SCOPE]
        && client.resources == strings("resources")
}
