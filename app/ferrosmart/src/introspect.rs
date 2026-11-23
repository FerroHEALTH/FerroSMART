// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The introspection endpoint (RFC 7662 §2), with SMART App Launch 2.2.0,
//! Token Introspection.
//!
//! The caller is a confidential client authenticated as at the token
//! endpoint, by its `private_key_jwt` assertion or its client secret (RFC
//! 6749 §2.3.1, RFC 7662 §2.1), or presents an access token FerroSMART
//! issued for its own issuer; either way it holds the scope
//! [`INTROSPECT_SCOPE`] (`docs/architecture.md` §13.6 item 8). Such a
//! caller may introspect any client's token ("Clients authorized in this
//! way are able to introspect tokens issued to any client"). A token that is not active, for any
//! reason, answers `{"active": false}` and nothing else (RFC 7662 §2.2).

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde_json::{Map, Value, json};

use crate::clients::Client;
use crate::form::Params;
use crate::server::AppState;
use crate::store::grant::{AccessRecord, GrantRecord, RefreshRecord};
use crate::token::{Refusal, assertion, no_store, read_form, secret, server_error, uses_basic};

/// The scope that lets a caller introspect (`docs/architecture.md` §13.6
/// item 8).
pub const INTROSPECT_SCOPE: &str = "system/introspect";

/// A token FerroSMART issued, found by its value.
#[derive(Debug)]
pub(crate) enum Found {
    /// An access token, by its `jti`.
    Access {
        /// Its `jti`.
        jti: String,
        /// Its record.
        record: AccessRecord,
    },
    /// A refresh token, found by the SHA-256 of its value.
    Refresh {
        /// Its record.
        record: RefreshRecord,
    },
}

/// `POST {issuer}/introspect`.
pub async fn introspect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match answer(&state, &headers, &body).await {
        Ok((caller, answer)) => {
            let active = answer.get("active").and_then(Value::as_bool) == Some(true);
            tracing::info!(
                target: "ferrosmart::audit",
                event = "token.introspected",
                caller = %caller,
                active,
                "a token was introspected"
            );
            no_store(Json(answer).into_response())
        }
        Err(refused) => {
            tracing::info!(
                target: "ferrosmart::audit",
                event = "introspection.refused",
                error = refused.error(),
                "an introspection request was refused"
            );
            refused.answer(&headers)
        }
    }
}

/// Why an introspection request is refused.
#[derive(Debug)]
pub(crate) enum Refused {
    /// The bearer token is not one that may introspect: "the authorization
    /// server responds with an HTTP 401 code as described in Section 3 of
    /// OAuth 2.0 Bearer Token Usage" (RFC 7662 §2.3).
    Bearer(&'static str),
    /// The client did not authenticate or holds no right to introspect: an
    /// HTTP 401 as RFC 6749 §5.2 describes (RFC 7662 §2.3).
    Client(Refusal),
    /// The request is malformed.
    Request(Refusal),
}

impl Refused {
    /// Returns the error code the answer carries.
    const fn error(&self) -> &'static str {
        match self {
            Self::Bearer(error) => error,
            Self::Client(refusal) | Self::Request(refusal) => refusal.error,
        }
    }

    /// Returns the response of this refusal to a request with `headers`: a
    /// client refused after it presented its secret by HTTP Basic is also
    /// challenged for that scheme ("include the `WWW-Authenticate` response
    /// header field matching the authentication scheme used by the client",
    /// RFC 6749 §5.2, which RFC 7662 §2.3 names).
    fn answer(self, headers: &HeaderMap) -> Response {
        let basic = matches!(self, Self::Client(_)) && uses_basic(headers);
        let mut response = self.into_response();
        if basic {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic"));
        }
        response
    }
}

impl IntoResponse for Refused {
    fn into_response(self) -> Response {
        match self {
            Self::Bearer(error) => {
                let challenge = format!("Bearer error=\"{error}\"");
                let mut response = StatusCode::UNAUTHORIZED.into_response();
                if let Ok(value) = HeaderValue::from_str(&challenge) {
                    response
                        .headers_mut()
                        .insert(header::WWW_AUTHENTICATE, value);
                }
                no_store(response)
            }
            Self::Client(refusal) => {
                let body =
                    json!({ "error": refusal.error, "error_description": refusal.description });
                no_store((StatusCode::UNAUTHORIZED, Json(body)).into_response())
            }
            Self::Request(refusal) => refusal.into_response(),
        }
    }
}

/// Answers the introspection request, with who asked.
async fn answer(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(String, Value), Refused> {
    let form = read_form(headers, body).map_err(Refused::Request)?;
    let caller = caller(state, headers, &form).await?;
    let token = form.get("token").ok_or(Refused::Request(Refusal::request(
        "the request carries no token",
    )))?;
    let found = find(state, token).await.map_err(Refused::Request)?;
    let inactive = json!({ "active": false });
    let answer = match found {
        Some(Found::Access { record, .. }) if record.active => access_answer(state, &record),
        Some(Found::Refresh { record, .. }) if record.active => refresh_answer(state, &record),
        _ => inactive,
    };
    Ok((caller, answer))
}

/// Returns the `client_id` of the caller, once it holds the right to
/// introspect.
async fn caller(state: &AppState, headers: &HeaderMap, form: &Params) -> Result<String, Refused> {
    if !uses_basic(headers)
        && let Some(token) = presented(headers)?
    {
        return bearer(state, token, INTROSPECT_SCOPE).await;
    }
    let client = authenticated(state, headers, form).await?;
    if !client.scopes.iter().any(|scope| scope == INTROSPECT_SCOPE) {
        return Err(Refused::Client(Refusal {
            error: "unauthorized_client",
            description: "the client may not introspect",
        }));
    }
    Ok(client.client_id)
}

/// Returns the confidential client of `headers` and `form`, authenticated
/// as at the token endpoint: by its client secret, in the `Authorization`
/// header or the form (RFC 6749 §2.3.1), or by its client assertion (RFC
/// 7523 §2.2). A public client cannot authenticate (RFC 6749 §2.1), so a
/// request that only names a `client_id` is refused `invalid_client`.
async fn authenticated(
    state: &AppState,
    headers: &HeaderMap,
    form: &Params,
) -> Result<Client, Refused> {
    let client = match secret::presented(headers, form) {
        Ok(Some(presented)) => secret::authenticate(state, presented).await,
        Ok(None) => assertion::authenticate(state, form).await,
        Err(refusal) => Err(refusal),
    };
    // NOTE: RFC 6749 §2.3 and §5.2, two methods at once is a malformed request and
    // a store failure a server error; only invalid_client is a failed authentication.
    client.map_err(|refusal| match refusal.error {
        "invalid_client" => Refused::Client(refusal),
        _ => Refused::Request(refusal),
    })
}

/// Returns the bearer token the `Authorization` header presents (RFC 6750
/// §2.1), or none when the request has no such header.
pub(crate) fn presented(headers: &HeaderMap) -> Result<Option<&str>, Refused> {
    headers
        .get(header::AUTHORIZATION)
        .map(|authorization| {
            authorization
                .to_str()
                .ok()
                .and_then(|value| value.split_once(' '))
                .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
                .map(|(_, token)| token.trim())
                .ok_or(Refused::Bearer("invalid_request"))
        })
        .transpose()
}

/// Returns the client of the bearer token `token` when it is an active
/// access token FerroSMART issued for its own issuer with `scope` (RFC 9068
/// §4: the `aud` names the resource server that checks it).
pub(crate) async fn bearer(state: &AppState, token: &str, scope: &str) -> Result<String, Refused> {
    let Some(jti) = own_access_token(state, token) else {
        return Err(Refused::Bearer("invalid_token"));
    };
    let record = state
        .store()
        .access_token(&jti)
        .await
        .map_err(|error| Refused::Request(server_error("the token record cannot be read", &error)))?
        .filter(|record| record.active)
        .ok_or(Refused::Bearer("invalid_token"))?;
    if record.audience != state.settings().issuer {
        return Err(Refused::Bearer("invalid_token"));
    }
    if !record.scope.split(' ').any(|granted| granted == scope) {
        return Err(Refused::Bearer("insufficient_scope"));
    }
    Ok(record.client_id)
}

/// Returns the token FerroSMART issued whose value is `token`: an access
/// token whose signature one of its own keys verifies, or a refresh token
/// whose SHA-256 it recorded; none for any other value.
pub(crate) async fn find(state: &AppState, token: &str) -> Result<Option<Found>, Refusal> {
    if let Some(jti) = own_access_token(state, token) {
        let record = state
            .store()
            .access_token(&jti)
            .await
            .map_err(|error| server_error("the token record cannot be read", &error))?;
        return Ok(record.map(|record| Found::Access { jti, record }));
    }
    let hash = crate::authorize::sha256(token);
    let record = state
        .store()
        .refresh_token(&hash)
        .await
        .map_err(|error| server_error("the token record cannot be read", &error))?;
    Ok(record.map(|record| Found::Refresh { record }))
}

/// Returns the `jti` of `token` when it is an RFC 9068 access token signed
/// by a key FerroSMART publishes and issued by it, whatever its `exp`,
/// which the record decides.
pub(crate) fn own_access_token(state: &AppState, token: &str) -> Option<String> {
    // NOTE: RFC 7662 §2.2, a value that does not verify is a token this server did
    // not issue, which is legitimately absent here and answers inactive.
    // NOTE: RFC 9068 §2.1 and §4, an access token is typed at+jwt and signed RS256 here.
    let claims = crate::token::own_jwt(state.settings(), token, "at+jwt")?;
    claims.get("jti").and_then(Value::as_str).map(str::to_owned)
}

/// Returns the answer for the active access token `record`: the members
/// RFC 7662 §2.2 names, and those SMART App Launch 2.2.0, Token
/// Introspection, requires (`scope`, `client_id`, `exp`, the launch
/// context, the ID Token's `iss`, `sub` and `fhirUser`).
fn access_answer(state: &AppState, record: &AccessRecord) -> Value {
    let mut answer = Map::new();
    answer.insert(String::from("active"), json!(true));
    answer.insert(String::from("scope"), json!(record.scope));
    answer.insert(String::from("client_id"), json!(record.client_id));
    answer.insert(String::from("exp"), json!(record.expires_at));
    answer.insert(String::from("iat"), json!(record.issued_at));
    answer.insert(String::from("sub"), json!(record.subject));
    answer.insert(String::from("aud"), json!(record.audience));
    answer.insert(String::from("iss"), json!(state.settings().issuer));
    if let Some(grant) = &record.grant {
        context(&mut answer, grant);
    }
    Value::Object(answer)
}

/// Returns the answer for the active refresh token `record`: its grant's
/// scope, client and subject, the launch context, and when it lapses
/// unused.
fn refresh_answer(state: &AppState, record: &RefreshRecord) -> Value {
    let grant = &record.grant;
    let mut answer = Map::new();
    answer.insert(String::from("active"), json!(true));
    answer.insert(String::from("scope"), json!(grant.scope));
    answer.insert(String::from("client_id"), json!(grant.client_id));
    answer.insert(String::from("exp"), json!(record.expires_at));
    answer.insert(String::from("sub"), json!(grant.subject));
    answer.insert(String::from("iss"), json!(state.settings().issuer));
    context(&mut answer, grant);
    Value::Object(answer)
}

/// Adds the launch context, `fhirUser` and `roles` of `grant` to `answer`,
/// never over a member it already holds.
fn context(answer: &mut Map<String, Value>, grant: &GrantRecord) {
    if let Some(members) = grant.context.as_object() {
        for (name, value) in members {
            answer.entry(name.clone()).or_insert_with(|| value.clone());
        }
    }
    if let Some(fhir_user) = &grant.fhir_user {
        answer
            .entry(String::from("fhirUser"))
            .or_insert_with(|| json!(fhir_user));
    }
    // NOTE: RFC 9068 §2.2.3.1 names `roles` for the access token; the answer carries
    // it too, so a resource server that introspects learns what one that reads the JWT does.
    if !grant.roles.is_empty() {
        answer
            .entry(String::from("roles"))
            .or_insert_with(|| json!(grant.roles));
    }
    // NOTE: RFC 9470 §6.2, the introspection answer names the login's acr and auth_time.
    if let Some(auth_time) = grant.auth_time {
        answer.insert(String::from("auth_time"), json!(auth_time));
    }
    if let Some(acr) = grant.acr {
        answer.insert(String::from("acr"), json!(crate::assurance::uri(acr)));
    }
}
