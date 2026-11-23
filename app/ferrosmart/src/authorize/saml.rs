// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The SAML 2.0 routes: FerroSMART's service provider metadata and the
//! assertion consumer service a SAML identity provider answers at
//! (`docs/architecture.md` §13.26).
//!
//! The assertion consumer service takes a `SAMLResponse` posted by the
//! HTTP-POST binding (saml-bindings-2.0-os §3.5), or a `SAMLart` posted or
//! redirected by the HTTP-Artifact binding (§3.6), which it resolves over
//! mutual TLS. The `RelayState` finds the pending request; a response with
//! none answers no request of FerroSMART's and is refused, since an
//! unsolicited login (saml-profiles-2.0-os §4.1.5) has no request to
//! complete. Every refusal is recorded as a DICOM `110122` Login event
//! naming the check that failed.

use std::net::IpAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};

use crate::audit::Connected;
use crate::form::Params;
use crate::pages::{self, Fault};
use crate::saml::Refusal;
use crate::saml::request::MAX_RELAY_STATE;
use crate::server::AppState;
use crate::store::{Pending, Purpose};
use crate::upstream::LoginProvider;
use crate::upstream::saml::{ResolveError, SamlLogin};

use super::choose::{SAML_COOKIE, saml_cookie};
use super::{Denial, cookie, forget, found};

/// The media type of SAML metadata (saml-metadata-2.0-os §4.1.1).
const METADATA_TYPE: &str = "application/samlmetadata+xml";

/// `GET {issuer}/saml/metadata`: FerroSMART's service provider metadata,
/// when `[ferrosmart.saml]` is set (saml-metadata-2.0-os §2.4.4, §4.1).
pub async fn metadata(State(state): State<Arc<AppState>>) -> Response {
    let Some(sp) = &state.settings().saml else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut response = (StatusCode::OK, sp.metadata()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(METADATA_TYPE),
    );
    response
}

/// What reached the assertion consumer service.
#[derive(Debug, Clone, Copy)]
enum Message<'a> {
    /// A `SAMLResponse` posted by the HTTP-POST binding.
    Response(&'a str),
    /// A `SAMLart` of the HTTP-Artifact binding.
    Artifact(&'a str),
}

/// `GET` or `POST {issuer}/saml/acs`: a `SAMLResponse` or a `SAMLart`
/// posted, or a `SAMLart` redirected (saml-bindings-2.0-os §3.6.3), with the
/// `RelayState`.
pub async fn acs(
    State(state): State<Arc<AppState>>,
    Connected(from): Connected,
    method: Method,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    let posted = method == Method::POST;
    let encoded = if posted {
        body.as_ref()
    } else {
        query.as_deref().unwrap_or_default().as_bytes()
    };
    let Ok(params) = Params::parse(encoded, &[]) else {
        return pages::fault(&state, Fault::BadRequest);
    };
    // NOTE: saml-profiles-2.0-os §4.1.2, the HTTP-Redirect binding never carries the
    // response, so a GET brings an artifact alone.
    let message = match (params.get("SAMLResponse"), params.get("SAMLart")) {
        (Some(response), None) if posted => Message::Response(response),
        (None, Some(artifact)) => Message::Artifact(artifact),
        _ => return pages::fault(&state, Fault::BadRequest),
    };
    complete(&state, from, &headers, message, params.get("RelayState")).await
}

/// Completes the SAML login `message` answers for the request
/// `relay_state` names.
async fn complete(
    state: &AppState,
    from: IpAddr,
    headers: &HeaderMap,
    message: Message<'_>,
    relay_state: Option<&str>,
) -> Response {
    let Some(relay_state) = relay_state.filter(|relay| relay.len() <= MAX_RELAY_STATE) else {
        return pages::fault(state, Fault::Lapsed);
    };
    let pending = match found(state, state.store().pending_by_upstream(relay_state).await) {
        Ok(pending) => pending,
        Err(response) => return *response,
    };
    // NOTE: RFC 9700 §4.7, the login completes in the browser that began it.
    if cookie(headers, SAML_COOKIE).as_deref() != Some(pending.id.as_str()) {
        return pages::fault(state, Fault::OtherBrowser);
    }
    let Some(provider) = pending
        .upstream_provider
        .as_deref()
        .and_then(|name| state.providers().named(name))
    else {
        return pages::fault(state, Fault::Lapsed);
    };
    let Some(login) = provider.saml() else {
        return pages::fault(state, Fault::BadRequest);
    };
    let mut response = match checked(state, &pending, login, message).await {
        Ok(identity) => super::callback::complete(state, &pending, provider, &identity, from).await,
        Err(failure) => refused(state, &pending, provider, &failure).await,
    };
    // NOTE: a login begun again for max_age binds the browser afresh; any other
    // answer ends the binding.
    let rebound = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|value| value.as_bytes().starts_with(SAML_COOKIE.as_bytes()));
    if !rebound {
        saml_cookie(state, &mut response, "", 0);
    }
    response
}

/// Why a SAML login did not complete.
#[derive(Debug, thiserror::Error)]
enum Failure {
    /// The response or the artifact is refused by a named check.
    #[error("the SAML response is refused: {0}")]
    Refused(#[from] Refusal),
    /// The artifact could not be resolved.
    #[error("the SAML artifact could not be resolved")]
    Transport(#[source] crate::upstream::saml::SamlError),
    /// The provider's metadata is past its validity.
    #[error("the identity provider's metadata has expired")]
    Metadata(#[source] crate::saml::metadata::MetadataError),
    /// The assertion was admitted before.
    #[error("the SAML assertion was already used")]
    Replayed,
    /// The login names no lasting identifier.
    #[error("the SAML login names no one: {0}")]
    Identity(#[from] crate::upstream::saml::IdentityError),
    /// The store failed.
    #[error("the SAML assertion could not be recorded")]
    Store(#[source] crate::store::StoreError),
}

/// Checks `message` as the answer to the request of `pending` at `login`,
/// admits its assertion once, and returns the identity it asserts.
async fn checked(
    state: &AppState,
    pending: &Pending,
    login: &SamlLogin,
    message: Message<'_>,
) -> Result<crate::upstream::Identity, Failure> {
    let idp = login.identity_provider().map_err(Failure::Metadata)?;
    let expect = login.expectations(&idp, &pending.upstream_nonce);
    let asserted = match message {
        Message::Response(response) => login.check_post(response, &expect)?,
        Message::Artifact(artifact) => {
            login
                .resolve(artifact, &expect)
                .await
                .map_err(|error| match error {
                    ResolveError::Refused(refusal) => Failure::Refused(refusal),
                    ResolveError::Transport(source) => Failure::Transport(source),
                })?
        }
    };
    // NOTE: saml-profiles-2.0-os §4.1.4.5, an assertion ID is admitted once, while the
    // assertion could still be confirmed.
    let first = state
        .store()
        .first_assertion(
            idp.entity_id(),
            &asserted.assertion_id,
            asserted.confirmable_until.as_second(),
        )
        .await
        .map_err(Failure::Store)?;
    if !first {
        return Err(Failure::Replayed);
    }
    let identity = login.upstream().identity(&asserted)?;
    tracing::info!(
        target: "ferrosmart::audit",
        event = "saml.login",
        client_id = ?pending.client_id,
        authn_context = %asserted.authn_context,
        "a SAML login was admitted"
    );
    Ok(identity)
}

/// Answers the SAML login of `pending` at `provider` that failed with
/// `failure`: the request ends, the failure is recorded by name, and the
/// browser goes back to the app with `access_denied` when the provider
/// declined, `server_error` otherwise (RFC 6749 §4.1.2.1).
async fn refused(
    state: &AppState,
    pending: &Pending,
    provider: &LoginProvider,
    failure: &Failure,
) -> Response {
    if let Failure::Store(error) = failure {
        return pages::server_error(state, error);
    }
    forget(state, pending).await;
    tracing::warn!(error = %ferrohealth_server::run::chain(failure), "the SAML login failed");
    let reason = failure.to_string();
    if let Err(response) =
        super::callback::record_login(state, provider.upstream(), Err(&reason)).await
    {
        return *response;
    }
    if pending.purpose == Purpose::Manage {
        return pages::fault(state, Fault::Lapsed);
    }
    // NOTE: saml-core-2.0-os §3.2.2.2, a status other than success is the provider's
    // answer, as an OpenID Provider's error is: the login was declined.
    let denial = if matches!(failure, Failure::Refused(Refusal::Status(_))) {
        Denial {
            error: "access_denied",
            description: "the login was declined",
        }
    } else {
        Denial {
            error: "server_error",
            description: "the login could not be completed",
        }
    };
    super::deny_unsigned(state, pending, denial).await
}
