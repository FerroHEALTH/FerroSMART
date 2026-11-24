// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! `GET /admin/upstreams`: the state of each upstream provider, so an
//! administrator sees a provider that can no longer be read without the
//! logs (`docs/architecture.md` §13.8).
//!
//! An OpenID Connect provider's discovery document and key set are read
//! when the request is answered, since the relying party reads the key set
//! at each login and holds no copy. A SAML provider's metadata is reported
//! as this replica last read it, with the copy in use. The configuration,
//! secrets included, stays in the file. No specification governs the
//! endpoint: our own design.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use ferrohealth_smart::metadata::Http;
use jiff::Timestamp;
use serde_json::{Map, Value, json};
use x509_parser::prelude::{FromDer, X509Certificate};

use super::{AdminError, no_store};
use crate::server::AppState;
use crate::upstream::{LoginProvider, UPSTREAM_TIMEOUT};

/// The route.
pub const UPSTREAMS_ROUTE: &str = "/admin/upstreams";

/// `GET /admin/upstreams`: each provider in configuration order.
pub(super) async fn upstreams(State(state): State<Arc<AppState>>) -> Result<Response, AdminError> {
    let registered = state.store().registered().await?;
    let mut probes = tokio::task::JoinSet::new();
    for (index, provider) in state.providers().iter().enumerate() {
        if let Some(party) = provider.oidc() {
            let issuer = provider.upstream().issuer().to_owned();
            let jwks_uri = party.provider().jwks_uri().clone();
            probes.spawn(async move { (index, oidc_documents(&issuer, jwks_uri).await) });
        }
    }
    let mut read: Vec<Option<Vec<Value>>> = vec![None; state.providers().iter().count()];
    for (index, provider) in state.providers().iter().enumerate() {
        if let (Some(login), Some(slot)) = (provider.wallet(), read.get_mut(index))
            && let Some(list) = login.list_read().await
        {
            *slot = Some(wallet_documents(&list));
        }
    }
    while let Some(joined) = probes.join_next().await {
        // NOTE: our own design, a probe that panicked reports nothing; the others stand.
        if let Ok((index, documents)) = joined
            && let Some(slot) = read.get_mut(index)
        {
            *slot = Some(documents);
        }
    }
    let entries: Vec<Value> = state
        .providers()
        .iter()
        .zip(read)
        .map(|(provider, oidc)| {
            let clients: Vec<&str> = registered
                .iter()
                .filter(|client| {
                    client
                        .client
                        .upstreams
                        .iter()
                        .any(|name| name == provider.name())
                })
                .map(|client| client.client.client_id.as_str())
                .collect();
            let documents = oidc.unwrap_or_else(|| saml_documents(provider));
            json!({
                "name": provider.name(),
                "label": provider.upstream().label,
                "protocol": protocol(provider),
                "issuer": provider.upstream().issuer(),
                "clients": clients,
                "documents": documents,
            })
        })
        .collect();
    Ok(no_store(
        Json(json!({ "upstreams": entries })).into_response(),
    ))
}

/// Returns the name of the protocol `provider` speaks, as its table names it.
fn protocol(provider: &LoginProvider) -> &'static str {
    if provider.oidc().is_some() {
        "oidc"
    } else if provider.wallet().is_some() {
        "openid4vp"
    } else {
        "saml"
    }
}

/// Returns the state of an OpenID Connect provider's discovery document
/// and key set, each read now.
async fn oidc_documents(issuer: &str, jwks_uri: url::Url) -> Vec<Value> {
    let now = Timestamp::now();
    let http = match Http::new(UPSTREAM_TIMEOUT) {
        Ok(http) => http,
        Err(error) => {
            let failure = ferrohealth_server::run::chain(&error);
            return vec![
                document("openid_configuration", now, Some(&failure)),
                document("jwks", now, Some(&failure)),
            ];
        }
    };
    let discovery = http
        .discover(issuer)
        .await
        .err()
        .map(|error| ferrohealth_server::run::chain(&error));
    let mut entries = vec![document("openid_configuration", now, discovery.as_deref())];
    let key_set = match http.get(jwks_uri).await {
        Ok((_url, status, body)) if status == http::StatusCode::OK => {
            match serde_json::from_str::<Value>(&body) {
                Ok(set) if set.get("keys").is_some_and(Value::is_array) => Ok(set),
                _ => Err(String::from("the key set is no JWK Set")),
            }
        }
        Ok((_url, status, _body)) => Err(format!("the key set answered {status}")),
        Err(error) => Err(ferrohealth_server::run::chain(&error)),
    };
    let mut keys = document("jwks", now, key_set.as_ref().err().map(String::as_str));
    if let (Ok(set), Some(members)) = (&key_set, keys.as_object_mut()) {
        members.insert(
            String::from("certificates_expire_at"),
            json!(jwk_expiries(set)),
        );
    }
    entries.push(keys);
    entries
}

/// Returns the end of validity of the first certificate of each key in the
/// JWK Set `set` that carries an `x5c` (RFC 7517 §4.7).
fn jwk_expiries(set: &Value) -> Vec<String> {
    let mut expiries: Vec<String> = set["keys"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|key| key.get("x5c")?.as_array()?.first()?.as_str())
        // NOTE: our own design, a certificate that does not decode has no expiry to report.
        .filter_map(|text| base64::engine::general_purpose::STANDARD.decode(text).ok())
        .filter_map(|der| {
            let (_rest, certificate) = X509Certificate::from_der(&der).ok()?;
            Timestamp::from_second(certificate.validity().not_after.timestamp()).ok()
        })
        .map(|instant| instant.to_string())
        .collect();
    expiries.sort();
    expiries
}

/// Returns the state of a wallet's list of PID providers as this replica
/// last read it, with the next update of the list in use.
fn wallet_documents(read: &crate::upstream::wallet::ListRead) -> Vec<Value> {
    let at = read
        .read_at
        .and_then(|at| Timestamp::from_second(at).ok())
        .unwrap_or_else(Timestamp::now);
    let failure = if read.read_at.is_none() {
        Some("the list has not been read yet")
    } else {
        read.failure.as_deref()
    };
    let mut entry = document("pid_providers_list", at, failure);
    if let (Some(list), Some(members)) = (&read.list, entry.as_object_mut())
        && let Ok(until) = Timestamp::from_second(list.next_update)
    {
        members.insert(String::from("valid_until"), Value::from(until.to_string()));
    }
    vec![entry]
}

/// Returns the state of a SAML provider's metadata as this replica last
/// read it, with the copy in use.
fn saml_documents(provider: &LoginProvider) -> Vec<Value> {
    let Some(login) = provider.saml() else {
        return Vec::new();
    };
    let (read, held) = login.last_read();
    let mut entry = document("saml_metadata", read.at, read.failure.as_deref());
    if let Some(members) = entry.as_object_mut() {
        members.insert(
            String::from("last_good_read_at"),
            Value::from(read.good_at.to_string()),
        );
        if let Some(until) = held.valid_until() {
            members.insert(String::from("valid_until"), Value::from(until.to_string()));
        }
        let mut expiries: Vec<String> = held
            .signing_keys()
            .iter()
            .filter_map(crate::saml::keys::TrustedKey::not_after)
            .map(|instant| instant.to_string())
            .collect();
        expiries.sort();
        members.insert(String::from("certificates_expire_at"), json!(expiries));
    }
    vec![entry]
}

/// Returns the entry of the document `kind` read at `at`, with the
/// `failure` of a read that failed.
fn document(kind: &str, at: Timestamp, failure: Option<&str>) -> Value {
    let mut entry = Map::new();
    entry.insert(String::from("document"), Value::from(kind));
    entry.insert(String::from("read_at"), Value::from(at.to_string()));
    entry.insert(String::from("ok"), Value::from(failure.is_none()));
    if let Some(failure) = failure {
        entry.insert(String::from("error"), Value::from(failure));
    }
    Value::Object(entry)
}
