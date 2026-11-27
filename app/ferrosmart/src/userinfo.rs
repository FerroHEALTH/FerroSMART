// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The UserInfo Endpoint (OpenID Connect Core 1.0 §5.3).
//!
//! It answers `GET` and `POST` (§5.3.1) for an active access token
//! FerroSMART issued under a person's grant with `openid`, presented in the
//! `Authorization` header (RFC 6750 §2.1), or under the `DPoP` scheme with
//! its proof when the token is `DPoP`-bound (RFC 9449 §7). The answer is
//! the token's `sub`, the `fhirUser` the grant carries and the standard
//! claims its scope passes on, the claims of the ID Token issued with it
//! (§5.3.2, §5.4). A refusal is the RFC 6750 §3 challenge (§5.3.3).

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use ferrohealth_smart::sender::ClientCertificate;
use ferrohealth_smart::sender::proof::{self, ProofCheck, ProofSettings};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use serde_json::{Map, Value};

use crate::server::AppState;
use crate::token::no_store;

/// The UserInfo Endpoint's route under the issuer (no specification names
/// the route: our own design).
pub const USERINFO_ROUTE: &str = "/userinfo";

/// Why a UserInfo request is refused (RFC 6750 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refused {
    /// The request carries no access token: a challenge with no error code.
    NoToken,
    /// The `Authorization` header is malformed.
    InvalidRequest,
    /// The token is not an active access token FerroSMART issued, or its
    /// sender constraint does not hold.
    InvalidToken,
    /// The token was not issued under a person's grant with `openid`.
    InsufficientScope,
    /// The store could not be read.
    Unavailable,
}

impl IntoResponse for Refused {
    fn into_response(self) -> Response {
        let (status, challenge) = match self {
            Self::NoToken => (StatusCode::UNAUTHORIZED, "Bearer"),
            Self::InvalidRequest => (StatusCode::BAD_REQUEST, "Bearer error=\"invalid_request\""),
            Self::InvalidToken => (StatusCode::UNAUTHORIZED, "Bearer error=\"invalid_token\""),
            Self::InsufficientScope => {
                (StatusCode::FORBIDDEN, "Bearer error=\"insufficient_scope\"")
            }
            Self::Unavailable => return no_store(StatusCode::SERVICE_UNAVAILABLE.into_response()),
        };
        let mut response = status.into_response();
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(challenge),
        );
        no_store(response)
    }
}

impl Refused {
    /// Returns the code the audit line names.
    const fn code(self) -> &'static str {
        match self {
            Self::NoToken => "no_token",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidToken => "invalid_token",
            Self::InsufficientScope => "insufficient_scope",
            Self::Unavailable => "unavailable",
        }
    }
}

/// The scheme an access token arrived under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    /// `Bearer` (RFC 6750 §2.1).
    Bearer,
    /// `DPoP` (RFC 9449 §7.1).
    Dpop,
}

/// `GET {issuer}/userinfo`.
pub async fn userinfo_get(
    State(state): State<Arc<AppState>>,
    certificates: Option<axum::Extension<ferrohealth_server::tls::PeerCertificates>>,
    headers: HeaderMap,
) -> Response {
    respond(&state, &Method::GET, certificates, &headers).await
}

/// `POST {issuer}/userinfo`.
pub async fn userinfo_post(
    State(state): State<Arc<AppState>>,
    certificates: Option<axum::Extension<ferrohealth_server::tls::PeerCertificates>>,
    headers: HeaderMap,
) -> Response {
    respond(&state, &Method::POST, certificates, &headers).await
}

/// Answers a UserInfo request by `method` with `headers`.
async fn respond(
    state: &AppState,
    method: &Method,
    certificates: Option<axum::Extension<ferrohealth_server::tls::PeerCertificates>>,
    headers: &HeaderMap,
) -> Response {
    let certificate = certificates
        .as_ref()
        .and_then(|axum::Extension(chain)| chain.0.first())
        .map(|leaf| ClientCertificate::from_der(leaf));
    match claims(state, method, headers, certificate.as_ref()).await {
        Ok((client_id, claims)) => {
            tracing::info!(
                target: "ferrosmart::audit",
                event = "userinfo.answered",
                client_id = %client_id,
                "the UserInfo Endpoint answered"
            );
            no_store(Json(Value::Object(claims)).into_response())
        }
        Err(refused) => {
            tracing::info!(
                target: "ferrosmart::audit",
                event = "userinfo.refused",
                error = refused.code(),
                "a UserInfo request was refused"
            );
            refused.into_response()
        }
    }
}

/// Returns the client the token was issued to and the claims the request
/// is answered with.
async fn claims(
    state: &AppState,
    method: &Method,
    headers: &HeaderMap,
    certificate: Option<&ClientCertificate>,
) -> Result<(String, Map<String, Value>), Refused> {
    let (scheme, token) = presented(headers)?;
    let claims =
        crate::token::own_jwt(state.settings(), token, "at+jwt").ok_or(Refused::InvalidToken)?;
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .ok_or(Refused::InvalidToken)?;
    let record = state
        .store()
        .access_token(jti)
        .await
        .map_err(|error| {
            tracing::error!(error = %ferrohealth_server::run::chain(&error), "the token record cannot be read");
            Refused::Unavailable
        })?
        .filter(|record| record.active)
        .ok_or(Refused::InvalidToken)?;
    constrained(state, method, headers, scheme, token, &claims, certificate).await?;
    // NOTE: OpenID Connect Core 1.0 §5.3, the Access Token is the one an OpenID
    // Connect Authentication Request obtained; a client's own token holds no person.
    let grant = record.grant.as_ref().ok_or(Refused::InsufficientScope)?;
    if !record.scope.split(' ').any(|granted| granted == "openid") {
        return Err(Refused::InsufficientScope);
    }
    let person = state.store().person_claims(&grant.id).await.map_err(|error| {
        tracing::error!(error = %ferrohealth_server::run::chain(&error), "the grant's claims cannot be read");
        Refused::Unavailable
    })?;
    let mut answer = Map::new();
    // NOTE: OpenID Connect Core 1.0 §5.3.2, the `sub` Claim MUST always be returned.
    answer.insert(String::from("sub"), Value::String(record.subject.clone()));
    if let Some(fhir_user) = &grant.fhir_user {
        answer.insert(String::from("fhirUser"), Value::String(fhir_user.clone()));
    }
    match serde_json::to_value(person.granted(&record.scope)) {
        Ok(Value::Object(standard)) => answer.extend(standard),
        Ok(_) => return Err(Refused::Unavailable),
        Err(error) => {
            tracing::error!(error = %error, "the grant's claims cannot be written");
            return Err(Refused::Unavailable);
        }
    }
    Ok((record.client_id, answer))
}

/// Returns the scheme and the access token of the `Authorization` header.
fn presented(headers: &HeaderMap) -> Result<(Scheme, &str), Refused> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Err(Refused::NoToken);
    };
    if values.next().is_some() {
        return Err(Refused::InvalidRequest);
    }
    let (scheme, token) = value
        .to_str()
        .ok()
        .and_then(|value| value.split_once(' '))
        .ok_or(Refused::InvalidRequest)?;
    let token = token.trim();
    if token.is_empty() || token.contains(' ') {
        return Err(Refused::InvalidRequest);
    }
    if scheme.eq_ignore_ascii_case("bearer") {
        Ok((Scheme::Bearer, token))
    } else if scheme.eq_ignore_ascii_case("dpop") {
        Ok((Scheme::Dpop, token))
    } else {
        Err(Refused::NoToken)
    }
}

/// Holds the token to what its `cnf` binds it to: a `DPoP`-bound token
/// arrives under the `DPoP` scheme with a proof of its key for this request
/// (RFC 9449 §7.1, §7.2), and a certificate-bound one over a connection
/// that presents its certificate (RFC 8705 §3). A token bound to nothing
/// arrives as `Bearer`.
async fn constrained(
    state: &AppState,
    method: &Method,
    headers: &HeaderMap,
    scheme: Scheme,
    token: &str,
    claims: &Value,
    certificate: Option<&ClientCertificate>,
) -> Result<(), Refused> {
    let cnf = claims.get("cnf");
    let jkt = cnf.and_then(|cnf| cnf.get("jkt")).and_then(Value::as_str);
    let bound_certificate = cnf
        .and_then(|cnf| cnf.get("x5t#S256"))
        .and_then(Value::as_str);
    if let Some(bound) = bound_certificate
        && certificate.map(ClientCertificate::thumbprint) != Some(bound)
    {
        return Err(Refused::InvalidToken);
    }
    match (scheme, jkt) {
        (Scheme::Bearer, None) => Ok(()),
        (Scheme::Dpop, Some(jkt)) => {
            let check = ProofCheck::new(
                ProofSettings::new(state.settings().issuer_url.clone()),
                crate::token::sender::replays(state),
            )
            .map_err(|error| {
                tracing::error!(error = %ferrohealth_server::run::chain(&error), "the DPoP proof check cannot be built");
                Refused::Unavailable
            })?;
            let proof = check
                .check(&proof::Presented {
                    method,
                    path: USERINFO_ROUTE,
                    headers,
                    token,
                    certificate,
                })
                .map_err(|_refused| Refused::InvalidToken)?;
            if proof.key().jkt() != jkt {
                return Err(Refused::InvalidToken);
            }
            check
                .consume(&proof)
                .await
                .map_err(|refused| match refused {
                    ferrohealth_smart::resource::Rejection::Upstream { .. } => Refused::Unavailable,
                    _ => Refused::InvalidToken,
                })
        }
        (Scheme::Bearer, Some(_)) | (Scheme::Dpop, None) => Err(Refused::InvalidToken),
    }
}
