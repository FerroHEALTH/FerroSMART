// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The calls to the authorization server: the metadata read that finds
//! the token endpoint, and the token requests of every grant.

use http::HeaderValue;
use http::StatusCode;
use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::Deserialize;
use url::Url;

use crate::client::CLIENT_AUTHENTICATION_TYP;
use crate::client::ClientAuth;
use crate::client::ClientCredentials;
use crate::client::Endpoint;
use crate::client::OAuthError;
use crate::client::TokenError;
use crate::client::assertion::ASSERTION_TYPE;
use crate::client::authorization_details::AuthorizationDetails;
use crate::client::binding::Bound;
use crate::client::binding::Confirmation;
use crate::client::binding::IssuedToken;
use crate::client::dpop;
use crate::client::fapi2;
use crate::client::fapi2::SecurityProfile;
use crate::client::keys::KeyRing;
use crate::metadata::DiscoveryError;
use crate::metadata::Http;

/// The members of an access token response the product reads (RFC 6749
/// §5.1).
#[derive(Deserialize)]
pub(super) struct TokenResponse {
    /// The access token.
    pub(super) access_token: String,
    /// The token type, compared case-insensitively.
    pub(super) token_type: String,
    /// The lifetime of the token in seconds, when the server sent one.
    pub(super) expires_in: Option<u64>,
    /// The confirmation the token is bound by, in the form RFC 8705 §3.2
    /// gives an introspection response.
    pub(super) cnf: Option<Confirmation>,
    /// The authorization details granted (RFC 9396 §7).
    pub(super) authorization_details: Option<serde_json::Value>,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

/// Returns the token endpoint the metadata of `issuer` names for `config`,
/// which sends `grant_types`: its mutual-TLS alias in preference when the
/// client presents a certificate, held to the FAPI 2.0 rules under that
/// profile, and refused when the metadata does not list an authorization
/// details type the grant sends (RFC 9396 §10).
pub(super) async fn discover(
    http: &Http,
    issuer: &str,
    config: &ClientCredentials,
    grant_types: &[&'static str],
) -> Result<Url, TokenError> {
    let (metadata, media_type) = http.discover_document(issuer).await?;
    if let Some(details) = &config.authorization_details {
        let listed = metadata
            .authorization_details_types_supported
            .as_deref()
            .unwrap_or_default();
        if let Some(kind) = details.types().iter().find(|kind| !listed.contains(kind)) {
            return Err(TokenError::AuthorizationDetailsType { kind: kind.clone() });
        }
    }
    if let SecurityProfile::Fapi2(profile) = &config.profile {
        return fapi2::check_metadata(
            config,
            profile,
            (&metadata, media_type.as_deref()),
            grant_types,
        )
        .map_err(|source| TokenError::Fapi2 { source });
    }
    // NOTE: RFC 8705 §5, a client intending to do mutual TLS "MUST use the alias
    // URL of the endpoint within the `mtls_endpoint_aliases`, when present".
    let alias = metadata
        .mtls_endpoint_aliases
        .as_ref()
        .and_then(|aliases| aliases.token_endpoint.as_deref())
        .filter(|_alias| config.tls.presents_identity());
    let (member, text) = match alias {
        Some(alias) => ("mtls_endpoint_aliases.token_endpoint", alias),
        None => (
            "token_endpoint",
            metadata
                .token_endpoint
                .as_deref()
                .ok_or(TokenError::NoTokenEndpoint)?,
        ),
    };
    let url: Url = text
        .parse()
        .map_err(|source| TokenError::TokenEndpointUrl { source })?;
    crate::client::check_token_endpoint(&url, member)?;
    Ok(url)
}

/// Returns the access token response `endpoint` answers the client
/// credentials grant of `config` with (RFC 6749 §4.4.2 and §4.4.3).
pub(super) async fn request_token(
    http: &Http,
    endpoint: &Url,
    config: &ClientCredentials,
) -> Result<TokenResponse, TokenError> {
    config.validate()?;
    let answer = post(http, endpoint, config, |form| {
        form.append_pair("grant_type", "client_credentials");
        if let Some(scope) = config.scope.as_deref() {
            form.append_pair("scope", scope);
        }
        if let Some(audience) = config.audience.as_deref() {
            form.append_pair("audience", audience);
        }
        if let Some(resource) = config.resource.as_ref() {
            form.append_pair("resource", resource.as_str());
        }
        if let Some(details) = config.authorization_details.as_ref() {
            form.append_pair("authorization_details", details.as_str());
        }
        Ok(())
    })
    .await?;
    if answer.status != StatusCode::OK {
        return Err(answer.refused());
    }
    serde_json::from_str(&answer.body).map_err(|source| TokenError::Malformed {
        source: source.into(),
    })
}

/// What a token endpoint answered: its status and its body, as received.
pub(crate) struct Answer {
    /// The status.
    pub(crate) status: StatusCode,
    /// The body.
    pub(crate) body: String,
    /// The `DPoP` nonce the answer carries, when it carries one (RFC 9449 §8).
    pub(crate) nonce: Option<String>,
}

impl std::fmt::Debug for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Answer")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl Answer {
    /// Returns the refusal a status other than `200` is, with the OAuth
    /// error when the body is one (RFC 6749 §5.2).
    pub(crate) fn refused(self) -> TokenError {
        // NOTE: RFC 6749 §5.2 makes the error body JSON with `error`; a body
        // that is not one is legitimately absent, and nothing of it is kept.
        let error = serde_json::from_str::<OAuthError>(&self.body)
            .ok()
            .map(OAuthError::bounded);
        TokenError::Refused {
            status: self.status,
            error,
        }
    }
}

/// Returns what `endpoint` answers a form-encoded token request whose grant
/// parameters `fill` writes, authenticated as the client of `config`.
///
/// Under a `DPoP` grant each send carries a proof, a nonce the endpoint sends
/// is kept for the next proof, and a `400` [`dpop::USE_NONCE`] that carries
/// one is answered by sending the request once more (RFC 9449 §8). Each send
/// has a form `fill` writes anew, so its assertions are signed anew (RFC
/// 7523 §3).
pub(crate) async fn post(
    http: &Http,
    endpoint: &Url,
    config: &ClientCredentials,
    fill: impl Fn(&mut url::form_urlencoded::Serializer<'_, String>) -> Result<(), TokenError>,
) -> Result<Answer, TokenError> {
    let key = config.dpop_key();
    let mut resend = key.is_some();
    loop {
        let answer = send(http, endpoint, config, &fill).await?;
        let Some((key, nonce)) = key.zip(answer.nonce.as_deref()) else {
            return Ok(answer);
        };
        key.remember(dpop::Role::Authorization, endpoint, nonce);
        if !(resend && dpop::demands_nonce(answer.status, &answer.body)) {
            return Ok(answer);
        }
        tracing::debug!("the token endpoint demands a DPoP nonce; sending once more");
        resend = false;
    }
}

/// Sends one token request to `endpoint`, with a `DPoP` proof under a
/// `DPoP` grant.
async fn send(
    http: &Http,
    endpoint: &Url,
    config: &ClientCredentials,
    fill: &impl Fn(&mut url::form_urlencoded::Serializer<'_, String>) -> Result<(), TokenError>,
) -> Result<Answer, TokenError> {
    http.clear(endpoint).await;
    // NOTE: no specification governs this: our own design; the form encoder
    // is not `Sync`, so it is finished and dropped before the request awaits.
    let (mut request, body) = {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        fill(&mut form)?;
        let request = http
            .client()
            .post(endpoint.clone())
            .header(http::header::ACCEPT, "application/json");
        let request = authenticate(request, &mut form, config, endpoint)?;
        (request, form.finish())
    };
    if let Some(key) = config.dpop_key() {
        // NOTE: RFC 9449 §4.2, a token request presents no access token, so its
        // proof carries no ath.
        let proof = key
            .proof(
                &http::Method::POST,
                endpoint,
                dpop::Role::Authorization,
                None,
            )
            .map_err(|source| TokenError::Proof { source })?;
        request = request.header(dpop::HEADER, proof);
    }
    let mut response = request
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .send()
        .await
        .map_err(|source| DiscoveryError::Transport {
            url: endpoint.clone(),
            source,
        })?;
    let status = response.status();
    let nonce = dpop::nonce(response.headers()).map(str::to_owned);
    let body = crate::metadata::capped_body(&mut response, endpoint).await?;
    Ok(Answer {
        status,
        body,
        nonce,
    })
}

/// Returns the credential the token `access_token` of `token_type`, bound by
/// `cnf`, is for `config`, refused when it is of another type than the grant
/// asks for, bound to another certificate, or cannot be sent.
pub(crate) fn credential(
    config: &ClientCredentials,
    token_type: &str,
    access_token: String,
    (cnf, granted): (Option<&Confirmation>, Option<&serde_json::Value>),
) -> Result<IssuedToken, TokenError> {
    // NOTE: RFC 6749 §5.1 makes token_type case-insensitive; RFC 9449 §5 names a
    // DPoP-bound token DPoP, and a grant that asked for one takes no other.
    let expected = if config.dpop_key().is_some() {
        dpop::SCHEME
    } else {
        "Bearer"
    };
    if !token_type.eq_ignore_ascii_case(expected) {
        return Err(TokenError::TokenType {
            found: token_type.to_owned(),
            expected,
        });
    }
    // NOTE: RFC 8705 §3, a certificate-bound token travels only over a connection
    // presenting that certificate, so one whose stated binding names another is refused.
    if let Some(certificate) = config.bound_certificate()
        && crate::client::binding::bound(&access_token, cnf, certificate.thumbprint())
            == Bound::Mismatch
    {
        return Err(TokenError::CertificateMismatch);
    }
    let granted = granted_details(config, granted)?;
    let header = authorization(expected, &access_token)?;
    Ok(IssuedToken::new(
        header,
        SecretString::from(access_token),
        config.dpop_key().cloned(),
        granted,
    ))
}

/// Returns the authorization details `granted` states, held to RFC 9396 §2
/// when the grant asked for some, which the response must then state (§7).
fn granted_details(
    config: &ClientCredentials,
    granted: Option<&serde_json::Value>,
) -> Result<Option<AuthorizationDetails>, TokenError> {
    let read = |value: &serde_json::Value| AuthorizationDetails::parse(&value.to_string());
    if config.authorization_details.is_none() {
        // NOTE: RFC 9396 §7, the server determines the details at its discretion
        // when none were asked for; ones not of §2 shape are legitimately unread.
        return Ok(granted.and_then(|value| read(value).ok()));
    }
    let value = granted.ok_or(TokenError::AuthorizationDetails)?;
    read(value)
        .map(Some)
        .map_err(|source| TokenError::GrantedDetails { source })
}

/// Returns the `Authorization` field value of `token` under `scheme`, marked
/// sensitive.
pub(crate) fn authorization(scheme: &str, token: &str) -> Result<HeaderValue, TokenError> {
    // NOTE: RFC 6750 §2.1 and RFC 9449 §7.1, b64token is 1*( ALPHA / DIGIT /
    // "-" / "." / "_" / "~" / "+" / "/" ) *"=", so anything else cannot travel.
    let b64token = !token.is_empty()
        && token
            .trim_end_matches('=')
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/".contains(&byte));
    if !b64token {
        return Err(TokenError::Unusable);
    }
    let mut value = HeaderValue::from_str(&format!("{scheme} {token}"))
        .map_err(|_illegal| TokenError::Unusable)?;
    value.set_sensitive(true);
    Ok(value)
}

/// Returns the client assertion of `config` signed with `key` for
/// `endpoint`, its `aud` and `typ` fixed by the grant's security profile:
/// the token endpoint under `JWT` for a SMART grant ("The FHIR
/// authorization server's 'token URL'", `typ` "Fixed value: JWT", SMART App
/// Launch 2.2.0, Client Authentication: Asymmetric), and the issuer
/// identifier as a string under `client-authentication+jwt` for a FAPI 2.0
/// grant (FAPI 2.0 Security Profile §5.3.3.1; RFC 10070 §4), which is
/// always configured by its issuer.
pub(crate) fn client_assertion(
    key: &crate::client::assertion::AssertionKey,
    config: &ClientCredentials,
    endpoint: &Url,
) -> Result<String, TokenError> {
    let (audience, typ) = match (&config.profile, &config.endpoint) {
        (SecurityProfile::Fapi2(_), Endpoint::Issuer(issuer)) => {
            (issuer.as_str(), CLIENT_AUTHENTICATION_TYP)
        }
        (SecurityProfile::Fapi2(_), Endpoint::Token(_)) => {
            return Err(TokenError::Credential {
                what: "issuer for the FAPI 2.0 assertion audience",
            });
        }
        (SecurityProfile::OAuth2, _) => (endpoint.as_str(), "JWT"),
    };
    key.assertion(&config.client_id, audience, typ)
        .map_err(|source| TokenError::Assertion { source })
}

/// Returns the actor assertion of `config` signed with `key` for
/// `endpoint`: the JWT that names the client the actor of a token exchange
/// (RFC 8693 §2.1, `actor_token_type` JWT), typed `JWT` because it
/// authenticates no client, with the audience of the client assertion.
pub(crate) fn actor_assertion(
    key: &crate::client::assertion::AssertionKey,
    config: &ClientCredentials,
    endpoint: &Url,
) -> Result<String, TokenError> {
    let audience = match (&config.profile, &config.endpoint) {
        (SecurityProfile::Fapi2(_), Endpoint::Issuer(issuer)) => issuer.as_str(),
        (SecurityProfile::Fapi2(_) | SecurityProfile::OAuth2, _) => endpoint.as_str(),
    };
    key.assertion(&config.client_id, audience, "JWT")
        .map_err(|source| TokenError::Assertion { source })
}

/// Returns `request`, posted to `endpoint`, authenticated as the client of
/// `config`: HTTP Basic under `client_secret_basic`, or `form` extended with
/// the client's id and secret under `client_secret_post`, the assertion
/// under `private_key_jwt` (RFC 7523 §2.2), or the `client_id` under mutual
/// TLS (RFC 8705 §2). The token request and the introspection request share
/// it (RFC 7662 §2.1 and §4 admit the token endpoint's client authentication).
///
/// The assertion's `aud` is `endpoint`, or the issuer identifier when the
/// grant names one and asks for it.
pub(crate) fn authenticate(
    mut request: reqwest::RequestBuilder,
    form: &mut url::form_urlencoded::Serializer<'_, String>,
    config: &ClientCredentials,
    endpoint: &Url,
) -> Result<reqwest::RequestBuilder, TokenError> {
    if config.client_auth == ClientAuth::ClientSecretBasic
        && let Some(secret) = &config.client_secret
    {
        // NOTE: RFC 6749 §2.3.1 form-encodes the id and the secret
        // (Appendix B) before they become the RFC 7617 user-pass.
        let user: String =
            url::form_urlencoded::byte_serialize(config.client_id.as_bytes()).collect();
        let password: String =
            url::form_urlencoded::byte_serialize(secret.expose_secret().as_bytes()).collect();
        request = request.basic_auth(user, Some(password));
    }
    match config.client_auth {
        ClientAuth::ClientSecretPost => {
            if let Some(secret) = &config.client_secret {
                form.append_pair("client_id", &config.client_id);
                form.append_pair("client_secret", secret.expose_secret());
            }
        }
        ClientAuth::PrivateKeyJwt => {
            if let Some(key) = config.assertion_keys.as_deref().map(KeyRing::current) {
                let assertion = client_assertion(key, config, endpoint)?;
                form.append_pair("client_assertion_type", ASSERTION_TYPE);
                form.append_pair("client_assertion", &assertion);
            }
        }
        // NOTE: RFC 8705 §2, "the client MUST include the `client_id`
        // parameter" with mutual-TLS client authentication.
        ClientAuth::TlsClientAuth | ClientAuth::SelfSignedTlsClientAuth => {
            form.append_pair("client_id", &config.client_id);
        }
        ClientAuth::ClientSecretBasic => {}
    }
    Ok(request)
}
