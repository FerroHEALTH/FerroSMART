// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The token endpoint (RFC 6749 §3.2).
//!
//! It serves the authorization code grant (RFC 6749 §4.1.3), the client
//! credentials grant of SMART Backend Services (§4.4), the refresh token
//! grant (§6) and the token exchange of a person's own token (RFC 8693 §2).
//! A client authenticates by the method it registered: PKCE alone, its
//! secret (§2.3.1), or a `private_key_jwt` assertion (RFC 7523 §2.2) checked
//! as SMART App Launch 2.2.0, Client Authentication: Asymmetric, Signature
//! Verification, has it. The answer is the JSON of RFC 6749 §5.1, or the
//! error of §5.2, never cached, and the token is an RFC 9068 JWT.

pub mod assertion;
pub mod exchange;
pub mod grants;
pub mod mint;
pub mod secret;
pub mod sender;

use self::grants::{authorization_code, client_credentials};

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::audit::exchanges::{Token, TokenRequest, token_request};
use crate::audit::{self, Connected};
use crate::discovery::TOKEN_ROUTE;
use crate::form::Params;
use crate::server::AppState;
use crate::store::IssuedToken;

/// The `client_assertion_type` of a JWT client assertion (RFC 7523 §2.2).
pub const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Returns the grant types the token endpoint serves, with a login or
/// without.
///
/// The client credentials and refresh token grants are always served, since
/// a refresh token keeps its grant when the deployment stops logging people
/// in; the authorization code grant and the token exchange of a person's
/// token need a login.
///
/// The metadata's `grant_types_supported` is this list (RFC 8414 §2), and
/// the token endpoint refuses every other grant as
/// `unsupported_grant_type` (RFC 6749 §5.2), so the two never disagree.
#[must_use]
pub const fn grant_types(login: bool) -> &'static [&'static str] {
    if login {
        &[
            "authorization_code",
            "client_credentials",
            "refresh_token",
            exchange::TOKEN_EXCHANGE,
        ]
    } else {
        &["client_credentials", "refresh_token"]
    }
}

/// The longest a client assertion may live: "This time SHALL be no more than
/// five minutes in the future" (SMART App Launch 2.2.0, Client
/// Authentication: Asymmetric, Request).
pub const MAX_ASSERTION_SECONDS: u64 = 300;

/// The clock skew admitted on `exp`. No specification governs the value:
/// our own design, the one `ferrohealth-smart` admits on a token.
pub const LEEWAY_SECONDS: u64 = 30;

/// The `typ` values a client assertion may carry: `JWT`, which SMART App
/// Launch 2.2.0 fixes, and `client-authentication+jwt` of RFC 10070 §4
/// (`docs/architecture.md` §13.6 item 1).
const ASSERTION_TYPES: [&str; 2] = ["JWT", "client-authentication+jwt"];

/// A refusal of the token endpoint: an RFC 6749 §5.2 error code with a
/// description that names no secret and quotes no input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The `error` code.
    pub error: &'static str,
    /// The `error_description`, which SMART Backend Services has the server
    /// include ("SHOULD include an `error_uri` or `error_description`").
    pub description: &'static str,
}

impl Refusal {
    /// The `invalid_request` refusal.
    pub(crate) const fn request(description: &'static str) -> Self {
        Self {
            error: "invalid_request",
            description,
        }
    }

    /// The `invalid_client` refusal every failure of client authentication
    /// answers ("the server SHALL respond with an `invalid_client` error",
    /// SMART App Launch 2.2.0, Client Authentication: Asymmetric, Response).
    pub(crate) const fn client(description: &'static str) -> Self {
        Self {
            error: "invalid_client",
            description,
        }
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        // NOTE: RFC 6749 §5.2, 400 unless otherwise specified; no Authorization
        // header carried the credential, so invalid_client is 400 too.
        let body = json!({ "error": self.error, "error_description": self.description });
        no_store((StatusCode::BAD_REQUEST, Json(body)).into_response())
    }
}

impl Refusal {
    /// Returns the response of this refusal to a request with `headers`.
    ///
    /// "If the client attempted to authenticate via the `Authorization`
    /// request header field, the authorization server MUST respond with an
    /// HTTP 401 (Unauthorized) status code and include the
    /// `WWW-Authenticate` response header field matching the authentication
    /// scheme used by the client" (RFC 6749 §5.2, `invalid_client`).
    pub(crate) fn answer(self, headers: &HeaderMap) -> Response {
        let invalid_client = self.error == "invalid_client";
        let mut response = self.into_response();
        if uses_basic(headers) && invalid_client {
            *response.status_mut() = StatusCode::UNAUTHORIZED;
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic"));
        }
        response
    }
}

/// Returns whether the `Authorization` header of `headers` uses the HTTP
/// Basic scheme (RFC 7617 §2), as a client secret does (RFC 6749 §2.3.1).
pub(crate) fn uses_basic(headers: &HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("Basic"))
}

/// `POST {issuer}/token`.
///
/// Each request is recorded before its answer is returned: an issued token
/// and its record commit in one transaction, and a request whose record
/// could not be stored is answered `503` with no token (no specification
/// governs the refusal: our own design).
pub async fn token(
    State(state): State<Arc<AppState>>,
    Connected(from): Connected,
    certificates: Option<axum::Extension<ferrohealth_server::tls::PeerCertificates>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let certificates = certificates.map(|axum::Extension(chain)| chain);
    let answer = match answered(&state, &headers, &body, from, certificates.as_ref()).await {
        Ok(answer) => answer,
        Err(error) => {
            tracing::error!(error = %ferrohealth_server::run::chain(&error), "a token request could not be recorded");
            return unrecorded();
        }
    };
    let client_id = match &answer {
        Ok(issued) => Some(issued.client_id.clone()),
        Err(_) => Params::parse(&body, &[])
            .ok()
            .and_then(|form| form.get("client_id").map(str::to_owned)),
    };
    let mut response = match answer {
        Ok(issued) => no_store(Json(issued.response).into_response()),
        Err(refusal) => refusal.answer(&headers),
    };
    if let Some(client_id) = client_id {
        allow_registered_origin(&state, &headers, &client_id, &mut response).await;
    }
    response
}

/// Lets the browser read `response` when the request came from one of the
/// registered origins of the client `client_id`: "For requests from a
/// client's registered origin(s), CORS configuration permits access to the
/// token endpoint" (SMART App Launch 2.2.0, App Launch, Considerations for
/// CORS support). A client's registered origins are the origins (RFC 6454
/// §4) of its registered redirect URIs, which SMART leaves open: our own
/// design. Every other request gets no CORS header.
async fn allow_registered_origin(
    state: &AppState,
    headers: &HeaderMap,
    client_id: &str,
    response: &mut Response,
) {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return;
    };
    // NOTE: a registry that cannot be read admits no origin, so the browser reads
    // nothing; the answer itself is unchanged.
    let Ok(Some(client)) = state.store().client(client_id).await else {
        return;
    };
    let registered = client.redirect_uris.iter().any(|uri| {
        url::Url::parse(uri)
            .is_ok_and(|url| origin.as_bytes() == url.origin().ascii_serialization().as_bytes())
    });
    if registered && origin.as_bytes() != b"null" {
        let headers = response.headers_mut();
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
        headers.append(header::VARY, HeaderValue::from_static("origin"));
    }
}

/// Answers the token request `body` and commits its record, as the token
/// endpoint does for every request, a request FerroSMART sends itself
/// included (`docs/architecture.md` §13.33).
///
/// # Errors
/// Returns the [`audit::RecordFailure`] of a record that could not be
/// stored; no token is issued then.
pub(crate) async fn answered(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
    from: std::net::IpAddr,
    certificates: Option<&ferrohealth_server::tls::PeerCertificates>,
) -> Result<Result<Issued, Refusal>, audit::RecordFailure> {
    let answer = issue(state, headers, body, from, certificates).await;
    // NOTE: a form that cannot be read names no client; the record then says so.
    let form = Params::parse(body, &[]).ok();
    let endpoint = state.settings().endpoint_url(TOKEN_ROUTE);
    let request = TokenRequest {
        client_id: form.as_ref().and_then(|form| form.get("client_id")),
        from,
        endpoint: &endpoint,
        content_type: headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        body,
    };
    commit(state, &answer, &request).await?;
    Ok(answer)
}

/// Commits the record of `request` answered `answer`: an issued token
/// together with its record, a refusal's record alone.
async fn commit(
    state: &AppState,
    answer: &Result<Issued, Refusal>,
    request: &TokenRequest<'_>,
) -> Result<(), audit::RecordFailure> {
    let lane = state.audit();
    match answer {
        Ok(issued) => {
            let exchange = token_request(
                request,
                Ok(Token {
                    issuer: &state.settings().issuer,
                    jti: &issued.jti,
                    client_id: &issued.client_id,
                    audience: &issued.audience,
                    subject: issued.person.as_deref(),
                }),
            );
            let mut tx = state
                .store()
                .begin()
                .await
                .map_err(audit::RecordFailure::Store)?;
            tx.insert_token(&issued.record())
                .await
                .map_err(audit::RecordFailure::Store)?;
            lane.commit(
                tx,
                &exchange,
                "token",
                issued.person.as_deref(),
                Some(&issued.client_id),
            )
            .await
        }
        Err(refusal) => {
            let exchange = token_request(request, Err(refusal.error));
            let row = lane.row(&exchange, "token", None, request.client_id)?;
            lane.record(state.store(), &row).await
        }
    }
}

/// The answer to a token request that could not be recorded.
fn unrecorded() -> Response {
    no_store(StatusCode::SERVICE_UNAVAILABLE.into_response())
}

/// Returns `response` with the headers every token response carries: "The
/// authorization server's response SHALL include the HTTP 'Cache-Control'
/// response header field with a value of 'no-store'" and "'Pragma' ... with
/// a value of 'no-cache'" (SMART App Launch 2.2.0, Obtain access token,
/// Response; RFC 6749 §5.1).
pub(crate) fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// The RFC 6749 §5.1 token response.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    /// The access token.
    pub access_token: String,
    /// `Bearer` for an app, `bearer` for a backend service: the fixed value
    /// each of SMART App Launch 2.2.0's grants names (compared without case,
    /// RFC 6749 §5.1).
    pub token_type: &'static str,
    /// The lifetime in seconds.
    pub expires_in: u64,
    /// The scope granted.
    pub scope: String,
    /// The ID Token, when `openid` is granted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// The refresh token, when the grant carries `offline_access` or
    /// `online_access` (SMART App Launch 2.2.0, Obtain access token).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// The type of the token issued by a token exchange (RFC 8693 §2.2.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_token_type: Option<&'static str>,
    /// The launch context parameters of an app's grant, each a member of the
    /// response (SMART App Launch 2.2.0, Scopes and Launch Context, Launch
    /// context arrives with your `access_token`): `smart_style_url` when
    /// `[ferrosmart.branding]` names one.
    #[serde(flatten)]
    pub context: Map<String, Value>,
}

/// An issued token with what the audit record names.
#[derive(Debug)]
pub(crate) struct Issued {
    /// The response.
    pub(crate) response: TokenResponse,
    /// The client.
    client_id: String,
    /// The token's `jti`.
    jti: String,
    /// The token's `aud`.
    audience: String,
    /// The person the token was issued for, when one logged in.
    person: Option<String>,
    /// The token's `sub`.
    subject: String,
    /// Its `iat`.
    iat: i64,
    /// Its `exp`.
    exp: i64,
    /// The SHA-256 of the code it answers, if any.
    code_hash: Option<String>,
    /// The grant it was issued under; none for a client credentials token.
    grant_id: Option<String>,
}

impl Issued {
    /// Returns the token's `jti`.
    pub(crate) fn jti(&self) -> &str {
        &self.jti
    }

    /// Returns this answer as a token exchange's, naming the type issued
    /// (RFC 8693 §2.2.1).
    fn exchanged(mut self) -> Self {
        self.response.issued_token_type = Some(exchange::ACCESS_TOKEN_TYPE);
        self
    }

    /// Returns the access token as the store records it.
    pub(crate) fn record(&self) -> IssuedToken<'_> {
        IssuedToken {
            jti: &self.jti,
            client_id: &self.client_id,
            subject: &self.subject,
            audience: &self.audience,
            scope: &self.response.scope,
            issued_at: self.iat,
            expires_at: self.exp,
            code_hash: self.code_hash.as_deref(),
            grant_id: self.grant_id.as_deref(),
        }
    }
}

/// Answers the token request `body`.
async fn issue(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
    from: std::net::IpAddr,
    certificates: Option<&ferrohealth_server::tls::PeerCertificates>,
) -> Result<Issued, Refusal> {
    let form = read_form(headers, body)?;
    let grant = form
        .get("grant_type")
        .ok_or_else(|| Refusal::request("the request names no grant_type"))?;
    let unsupported = Refusal {
        error: "unsupported_grant_type",
        description: "the grant type is not supported",
    };
    if !grant_types(!state.providers().is_empty()).contains(&grant) {
        return Err(unsupported);
    }
    let presented = sender::presented(state, headers, certificates).await?;
    match grant {
        "client_credentials" => client_credentials(state, &form, &presented).await,
        "authorization_code" => authorization_code(from, state, headers, &form, &presented).await,
        "refresh_token" => crate::refresh::refresh(state, headers, &form, from, &presented).await,
        exchange::TOKEN_EXCHANGE => {
            exchange::token_exchange(state, headers, &form, from, &presented).await
        }
        _ => Err(unsupported),
    }
}

/// Reads the form `body`, refused unless `headers` name it form-encoded,
/// as the token (RFC 6749 §3.2), introspection (RFC 7662 §2.1) and
/// revocation (RFC 7009 §2.1) requests all are.
pub(crate) fn read_form(headers: &HeaderMap, body: &[u8]) -> Result<Params, Refusal> {
    let form_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| {
            media
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        });
    if !form_type {
        return Err(Refusal::request("the request is not form-encoded"));
    }
    Params::parse(body, &[]).map_err(|_repeated| Refusal::request("a parameter is repeated"))
}

/// Returns the `server_error` refusal described by `description`, after the
/// cause is logged with its whole chain and never a value of the request.
pub(crate) fn server_error(description: &'static str, cause: &dyn std::error::Error) -> Refusal {
    tracing::error!(error = %ferrohealth_server::run::chain(cause), "{description}");
    Refusal {
        error: "server_error",
        description,
    }
}

/// Returns the claims of `token` when it is a JWT of type `typ` that a key
/// FerroSMART publishes signed under that key's algorithm and FerroSMART
/// issued, whatever its `exp` and `aud`, which the caller decides.
///
/// A value that does not verify is one FerroSMART did not issue, which a
/// caller reads as absent (RFC 7662 §2.2; RP-Initiated Logout 1.0 §2).
pub(crate) fn own_jwt(
    settings: &crate::config::settings::Settings,
    token: &str,
    typ: &str,
) -> Option<Value> {
    use ferrohealth_smart::jws::jwk::Jwk;
    let jws = ferrohealth_smart::jws::compact::decode(token).ok()?;
    let header = jws.header();
    if header.typ.as_deref() != Some(typ) || !settings.keys.algorithms().contains(&header.alg) {
        return None;
    }
    let kid = header.kid.as_deref()?;
    // NOTE: RFC 7517 §5, a member that is no supported key verifies nothing.
    let keys: Vec<Jwk> = settings
        .keys
        .published()
        .get("keys")?
        .as_array()?
        .iter()
        .filter_map(|key| Jwk::try_from(key).ok())
        .collect();
    let key = ferrohealth_smart::jws::jwk::select(&keys, Some(kid), header.alg)?;
    let claims = jws.verify_claims(key).ok()?;
    (claims.get("iss").and_then(Value::as_str) == Some(settings.issuer.as_str()))
        .then_some(Value::Object(claims))
}
