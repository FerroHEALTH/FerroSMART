// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The OpenID Connect relying-party client an operator console signs in with.
//!
//! The authorization code flow of OpenID Connect Core 1.0 §3.1: the
//! authorization request carries `state`, `nonce` and a PKCE `S256`
//! challenge (RFC 7636 §4.2, §4.3; RFC 9700 §2.1.1), the code is exchanged at
//! the token endpoint with the verifier (RFC 6749 §4.1.3, RFC 7636 §4.5),
//! and the ID Token is checked as OpenID Connect Core 1.0 §3.1.3.7 says.
//! The refresh grant renews an access token (RFC 6749 §6), the end-session
//! URL signs the operator out at the provider (OpenID Connect RP-Initiated
//! Logout 1.0 §2), and revocation tells the provider a token is finished
//! with (RFC 7009 §2.1).
//!
//! The client keeps no state between calls: the console stores the
//! [`PendingSignIn`] between the redirect and the callback, and the tokens
//! of a [`SignedIn`] in its own session. Every token, the verifier and the
//! code are held in a [`Secret`] or never kept, and none reaches a log line,
//! a `Debug` rendering or an error message.

pub mod logout;

use std::fmt;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ferrohealth_secret::secret::Secret;
use http::StatusCode;
use secrecy::ExposeSecret as _;
use secrecy::SecretString;
use serde::Deserialize;
use url::Url;

use crate::jws::algorithm::Algorithm;
use crate::jws::claims::JwtError;
use crate::jws::claims::Validation;
use crate::jws::compact::Unverified;
use crate::jws::jwk::Jwk;

use crate::client::OAuthError;
use crate::client::assertion::{ASSERTION_TYPE, AssertionError, AssertionKey};
use crate::metadata::{DiscoveryError, Http, ServerMetadata};

/// The scope value every OpenID Connect request carries (OpenID Connect
/// Core 1.0 §3.1.2.1).
pub const OPENID: &str = "openid";

/// The scope value that asks for a refresh token usable while the operator
/// is away (OpenID Connect Core 1.0 §11).
pub const OFFLINE_ACCESS: &str = "offline_access";

/// The random bytes behind each `state`, `nonce` and PKCE verifier: 256
/// bits, which RFC 7636 §4.1 recommends for the verifier.
const RANDOM_BYTES: usize = 32;

/// Why a sign-in, a refresh, or a revocation could not be completed.
///
/// No variant carries a token, the code, the verifier or the client secret.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OidcError {
    /// The provider's metadata or key set could not be read, or a request to
    /// it never completed.
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
    /// The metadata names no endpoint the client needs.
    #[error("the provider's metadata names no {what}")]
    NoEndpoint {
        /// The metadata member that is missing.
        what: &'static str,
    },
    /// The metadata names an endpoint that is not a URL.
    #[error("the provider's metadata names a {what} that is not a URL")]
    EndpointUrl {
        /// The metadata member.
        what: &'static str,
        /// What the URL parser reported.
        #[source]
        source: url::ParseError,
    },
    /// The system's random source failed while a sign-in was minted.
    #[error("the random source could not mint a sign-in")]
    Random,
    /// The client assertion of `private_key_jwt` could not be signed.
    #[error("the client assertion could not be signed")]
    Assertion {
        /// What the signer reported.
        #[source]
        source: AssertionError,
    },
    /// The redirect's `state` is absent or not the one the request carried.
    #[error("the redirect's state is not the sign-in's")]
    StateMismatch,
    /// The provider sent the operator back with an error (RFC 6749
    /// §4.1.2.1).
    #[error("the provider refused the authorization request: {error}")]
    Authorization {
        /// The error the redirect carried.
        error: OAuthError,
    },
    /// The redirect carries no authorization code.
    #[error("the redirect carries no authorization code")]
    NoCode,
    /// The token endpoint answered anything other than `200`, with the OAuth
    /// error when the body carried one (RFC 6749 §5.2).
    #[error("the token endpoint answered {status}{}", oauth_clause(error.as_ref()))]
    Refused {
        /// The status it answered.
        status: StatusCode,
        /// The OAuth error, when the body was one.
        error: Option<OAuthError>,
    },
    /// The `200` body is not the token response of RFC 6749 §5.1.
    #[error("the token endpoint answered a body that is not a token response")]
    Malformed {
        /// What the JSON reader reported.
        #[source]
        source: crate::json::JsonError,
    },
    /// The access token is not a bearer token (RFC 6750).
    #[error("the token endpoint issued a token of type {found:?}; a console sends bearer tokens")]
    TokenType {
        /// The `token_type` the response named.
        found: String,
    },
    /// The code exchange answered no ID Token (OpenID Connect Core 1.0
    /// §3.1.3.3).
    #[error("the token endpoint answered no ID Token")]
    NoIdToken,
    /// The provider's key set location answered anything other than `200`.
    #[error("the provider's key set answered {status}")]
    KeySet {
        /// The status it answered.
        status: StatusCode,
    },
    /// The provider's key set is not a JWK Set (RFC 7517 §5).
    #[error("the provider's key set is not a JWK Set")]
    KeySetBody {
        /// What the JSON reader reported.
        #[source]
        source: crate::json::JsonError,
    },
    /// The ID Token is signed with an algorithm the client refuses, or by a
    /// key the key set does not hold.
    #[error("the ID Token is signed with a key or an algorithm the client does not accept")]
    Key,
    /// The ID Token's signature or its `iss`, `aud`, `exp`, `sub` or `iat`
    /// do not verify.
    #[error("the ID Token does not verify")]
    IdToken {
        /// What the verifier reported.
        #[source]
        source: JwtError,
    },
    /// The ID Token names an audience beyond this client.
    #[error("the ID Token names an audience beyond this client")]
    Audience,
    /// The ID Token was issued to another client (`azp`).
    #[error("the ID Token was issued to another client")]
    AuthorizedParty,
    /// The ID Token's `nonce` is absent or not the one the sign-in sent.
    #[error("the ID Token's nonce is not the sign-in's")]
    Nonce,
    /// The revocation endpoint answered anything other than `200` (RFC 7009
    /// §2.2).
    #[error("the revocation endpoint answered {status}")]
    Revocation {
        /// The status it answered.
        status: StatusCode,
    },
    /// The Logout Token's signature or its `iss`, `aud`, `iat` or `exp` do
    /// not verify (OpenID Connect Back-Channel Logout 1.0 §2.6).
    #[error("the Logout Token does not verify")]
    LogoutToken {
        /// What the verifier reported.
        #[source]
        source: JwtError,
    },
    /// The Logout Token breaks a rule of OpenID Connect Back-Channel Logout
    /// 1.0 §2.4 that §2.6 checks.
    #[error("the Logout Token {rule}")]
    LogoutClaims {
        /// The rule it breaks.
        rule: &'static str,
    },
}

impl OidcError {
    /// Returns the OAuth error code the provider answered with, from the
    /// redirect or the token endpoint, when the failure carries one.
    #[must_use]
    pub fn oauth_error(&self) -> Option<&str> {
        match self {
            Self::Authorization { error } => Some(&error.error),
            Self::Refused { error, .. } => error.as_ref().map(|error| error.error.as_str()),
            _ => None,
        }
    }

    /// Returns the status the provider answered, when the failure carries
    /// one.
    #[must_use]
    pub const fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Discovery(DiscoveryError::Status { status, .. })
            | Self::Refused { status, .. }
            | Self::KeySet { status }
            | Self::Revocation { status } => Some(*status),
            _ => None,
        }
    }

    /// Whether the failure is the ID Token's or the redirect's, which refuses
    /// the sign-in, rather than the provider's, which the operator can retry.
    #[must_use]
    pub const fn refuses_the_operator(&self) -> bool {
        matches!(
            self,
            Self::StateMismatch
                | Self::Key
                | Self::IdToken { .. }
                | Self::Audience
                | Self::AuthorizedParty
                | Self::Nonce
        )
    }

    /// Whether the provider answered and refused, or answered something no
    /// token response is, rather than not answering or failing on its side
    /// (`5xx`). A refresh refused this way ends the session.
    #[must_use]
    pub fn is_answered_refusal(&self) -> bool {
        match self {
            Self::Refused { status, .. } => status.is_client_error(),
            Self::Authorization { .. }
            | Self::Malformed { .. }
            | Self::TokenType { .. }
            | Self::NoIdToken => true,
            _ => self.refuses_the_operator(),
        }
    }
}

/// Returns the OAuth clause of a refusal's display.
fn oauth_clause(error: Option<&OAuthError>) -> String {
    error.map_or_else(String::new, |error| format!(": {error}"))
}

/// The provider's endpoints, read from its metadata (RFC 8414 §2, OpenID
/// Connect Discovery 1.0 §3, OpenID Connect RP-Initiated Logout 1.0 §2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    issuer: String,
    authorization_endpoint: Url,
    token_endpoint: Url,
    jwks_uri: Url,
    end_session_endpoint: Option<Url>,
    revocation_endpoint: Option<Url>,
}

impl Provider {
    /// Reads the metadata of `issuer` over `http` and returns its endpoints.
    ///
    /// # Errors
    ///
    /// Returns [`OidcError::Discovery`] when the metadata cannot be read, and
    /// the error of [`Provider::from_metadata`] for metadata a relying party
    /// cannot use.
    pub async fn discover(http: &Http, issuer: &str) -> Result<Self, OidcError> {
        Self::from_metadata(&http.discover(issuer).await?)
    }

    /// Returns the endpoints `metadata` names.
    ///
    /// # Errors
    ///
    /// Returns [`OidcError::NoEndpoint`] when the authorization endpoint, the
    /// token endpoint or `jwks_uri` is missing, [`OidcError::EndpointUrl`]
    /// for an endpoint that is no URL, and [`OidcError::Discovery`] with
    /// [`DiscoveryError::Insecure`] for one that is not `https` (or plain
    /// `http` on a loopback host).
    pub fn from_metadata(metadata: &ServerMetadata) -> Result<Self, OidcError> {
        Ok(Self {
            issuer: metadata.issuer.clone(),
            authorization_endpoint: required(
                metadata.authorization_endpoint.as_deref(),
                "authorization_endpoint",
            )?,
            token_endpoint: required(metadata.token_endpoint.as_deref(), "token_endpoint")?,
            jwks_uri: required(metadata.jwks_uri.as_deref(), "jwks_uri")?,
            end_session_endpoint: optional(
                metadata.end_session_endpoint.as_deref(),
                "end_session_endpoint",
            )?,
            revocation_endpoint: optional(
                metadata.revocation_endpoint.as_deref(),
                "revocation_endpoint",
            )?,
        })
    }

    /// Returns the issuer identifier.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns the authorization endpoint.
    #[must_use]
    pub const fn authorization_endpoint(&self) -> &Url {
        &self.authorization_endpoint
    }

    /// Returns the token endpoint.
    #[must_use]
    pub const fn token_endpoint(&self) -> &Url {
        &self.token_endpoint
    }

    /// Returns the key set location.
    #[must_use]
    pub const fn jwks_uri(&self) -> &Url {
        &self.jwks_uri
    }

    /// Returns the end-session endpoint, when the provider publishes one.
    #[must_use]
    pub const fn end_session_endpoint(&self) -> Option<&Url> {
        self.end_session_endpoint.as_ref()
    }

    /// Returns the revocation endpoint, when the provider publishes one.
    #[must_use]
    pub const fn revocation_endpoint(&self) -> Option<&Url> {
        self.revocation_endpoint.as_ref()
    }
}

/// Returns the endpoint `value` names, refusing an absent one.
fn required(value: Option<&str>, what: &'static str) -> Result<Url, OidcError> {
    optional(value, what)?.ok_or(OidcError::NoEndpoint { what })
}

/// Returns the endpoint `value` names, when it names one.
///
/// The authorization and end-session endpoints may carry a query (RFC 6749
/// §3.1), so the query is set aside before the scheme rule is checked.
fn optional(value: Option<&str>, what: &'static str) -> Result<Option<Url>, OidcError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let url: Url = value
        .parse()
        .map_err(|source| OidcError::EndpointUrl { what, source })?;
    let mut bare = url.clone();
    bare.set_query(None);
    crate::metadata::secure(&bare, what)?;
    Ok(Some(url))
}

/// How the client authenticates at the token and revocation endpoints.
#[derive(Clone, Default)]
enum ClientAuth {
    /// A public client, which names itself in the form (RFC 6749 §2.1,
    /// §3.2.1).
    #[default]
    Public,
    /// A confidential client with a secret, sent as HTTP Basic (RFC 6749
    /// §2.3.1).
    SecretBasic(SecretString),
    /// A confidential client signing a JWT with its private key
    /// (`private_key_jwt`, OpenID Connect Core 1.0 §9).
    PrivateKeyJwt(Box<AssertionKey>),
}

/// The relying-party client of one console at one provider.
///
/// It holds the configuration alone: every call takes what it needs and
/// returns what the console keeps.
#[derive(Clone)]
pub struct RelyingParty {
    http: Http,
    provider: Provider,
    client_id: String,
    auth: ClientAuth,
    redirect_uri: Url,
    scopes: Vec<String>,
    offline_access: bool,
    post_logout_redirect_uri: Option<Url>,
    algorithms: Vec<Algorithm>,
    clock_skew: Duration,
    trusted_audiences: Vec<String>,
}

impl fmt::Debug for RelyingParty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelyingParty")
            .field("issuer", &self.provider.issuer)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri.as_str())
            .field("scopes", &self.scopes)
            .finish_non_exhaustive()
    }
}

impl RelyingParty {
    /// The public client `client_id` at `provider`, whose redirection
    /// endpoint is `redirect_uri`, calling the provider over `http`.
    ///
    /// It asks for the `openid` scope alone, accepts an ID Token signed with
    /// RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384 or `EdDSA`,
    /// and allows 60 seconds of clock skew.
    #[must_use]
    pub fn new(
        http: Http,
        provider: Provider,
        client_id: impl Into<String>,
        redirect_uri: Url,
    ) -> Self {
        Self {
            http,
            provider,
            client_id: client_id.into(),
            auth: ClientAuth::Public,
            redirect_uri,
            scopes: vec![OPENID.to_owned()],
            offline_access: false,
            post_logout_redirect_uri: None,
            algorithms: vec![
                Algorithm::Rs256,
                Algorithm::Rs384,
                Algorithm::Rs512,
                Algorithm::Ps256,
                Algorithm::Ps384,
                Algorithm::Ps512,
                Algorithm::Es256,
                Algorithm::Es384,
                Algorithm::EdDsa,
            ],
            clock_skew: Duration::from_secs(60),
            trusted_audiences: Vec::new(),
        }
    }

    /// Makes the client a confidential one, authenticating with `secret` as
    /// HTTP Basic (RFC 6749 §2.3.1).
    #[must_use]
    pub fn with_client_secret(mut self, secret: SecretString) -> Self {
        self.auth = ClientAuth::SecretBasic(secret);
        self
    }

    /// Makes the client a confidential one, authenticating with a JWT
    /// `key` signs (`private_key_jwt`, OpenID Connect Core 1.0 §9).
    ///
    /// Each request to the token or revocation endpoint carries a fresh
    /// assertion (RFC 7523 §2.2, §3): `iss` and `sub` the client id, `aud`
    /// the provider's issuer identifier as its sole value and the type
    /// `client-authentication+jwt` (RFC 10070 §4, which updates RFC 7523
    /// and supersedes the token endpoint URL OpenID Connect Core 1.0 §9
    /// recommends; §6 has such a client work with a provider of either
    /// rule).
    #[must_use]
    pub fn with_private_key_jwt(mut self, key: AssertionKey) -> Self {
        self.auth = ClientAuth::PrivateKeyJwt(Box::new(key));
        self
    }

    /// Asks for `scopes`, with `openid` first whether or not they name it
    /// (OpenID Connect Core 1.0 §3.1.2.1).
    #[must_use]
    pub fn with_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut all = vec![OPENID.to_owned()];
        for scope in scopes {
            let scope = scope.into();
            if !scope.is_empty() && !all.contains(&scope) {
                all.push(scope);
            }
        }
        self.scopes = all;
        self
    }

    /// Asks for `offline_access`, so the provider issues a refresh token,
    /// with the `prompt` value `consent` that request needs (OpenID Connect
    /// Core 1.0 §11).
    #[must_use]
    pub const fn with_offline_access(mut self) -> Self {
        self.offline_access = true;
        self
    }

    /// Sends the operator to `redirect` after signing out at the provider
    /// (OpenID Connect RP-Initiated Logout 1.0 §2).
    #[must_use]
    pub fn with_post_logout_redirect_uri(mut self, redirect: Url) -> Self {
        self.post_logout_redirect_uri = Some(redirect);
        self
    }

    /// Accepts an ID Token signed with one of `algorithms`, an ML-DSA
    /// parameter set (RFC 9964) among them when named.
    #[must_use]
    pub fn with_algorithms(mut self, algorithms: impl IntoIterator<Item = Algorithm>) -> Self {
        self.algorithms = algorithms.into_iter().collect();
        self
    }

    /// Allows `skew` of clock difference on the ID Token's times.
    #[must_use]
    pub const fn with_clock_skew(mut self, skew: Duration) -> Self {
        self.clock_skew = skew;
        self
    }

    /// Trusts `audiences` beside this client in the `aud` of an ID Token or
    /// a logout token: "The ID Token MUST be rejected if ... it contains
    /// additional audiences not trusted by the Client" (OpenID Connect Core
    /// 1.0 §3.1.3.7 item 3), so a provider that names more than the client,
    /// such as the project an application belongs to, is accepted for
    /// exactly these. A token with several audiences then carries an `azp`
    /// naming this client (item 4).
    #[must_use]
    pub fn with_trusted_audiences<I, S>(mut self, audiences: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.trusted_audiences = audiences.into_iter().map(Into::into).collect();
        self
    }

    /// Returns the provider's endpoints.
    #[must_use]
    pub const fn provider(&self) -> &Provider {
        &self.provider
    }

    /// Returns the scopes the authorization request asks for, `openid` first
    /// and `offline_access` last when asked for.
    #[must_use]
    pub fn scopes(&self) -> Vec<&str> {
        let mut scopes: Vec<&str> = self.scopes.iter().map(String::as_str).collect();
        if self.offline_access && !scopes.contains(&OFFLINE_ACCESS) {
            scopes.push(OFFLINE_ACCESS);
        }
        scopes
    }

    /// Mints a sign-in and returns the authorization request that begins it
    /// (RFC 6749 §4.1.1, RFC 7636 §4.3, OpenID Connect Core 1.0 §3.1.2.1).
    ///
    /// The parameters are appended to whatever query the authorization
    /// endpoint already carries, which RFC 6749 §3.1 has a client keep. The
    /// console stores the [`PendingSignIn`] until the callback.
    ///
    /// # Errors
    ///
    /// Returns [`OidcError::Random`] when the random source fails.
    pub fn authorization_request(&self) -> Result<AuthorizationRequest, OidcError> {
        let pending = PendingSignIn::mint()?;
        let mut url = self.provider.authorization_endpoint.clone();
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("response_type", "code")
                .append_pair("client_id", &self.client_id)
                .append_pair("redirect_uri", self.redirect_uri.as_str())
                .append_pair("scope", &self.scopes().join(" "))
                .append_pair("state", &pending.state)
                .append_pair("nonce", &pending.nonce)
                .append_pair("code_challenge", &pending.challenge())
                .append_pair("code_challenge_method", "S256");
            // NOTE: OpenID Connect Core 1.0 §11: a request for `offline_access`
            // carries the `prompt` value `consent`.
            if self.offline_access {
                query.append_pair("prompt", "consent");
            }
        }
        Ok(AuthorizationRequest { url, pending })
    }

    /// Completes the sign-in `pending` from the redirect `callback`: holds
    /// the `state` to it, exchanges the code with the verifier, and checks
    /// the ID Token.
    ///
    /// # Errors
    ///
    /// Returns [`OidcError::StateMismatch`] before anything else the
    /// redirect says is read, [`OidcError::Authorization`] for a redirect
    /// that carries an error, [`OidcError::NoCode`], the token endpoint's
    /// errors ([`OidcError::Refused`] with the provider's error code,
    /// [`OidcError::Malformed`], [`OidcError::TokenType`],
    /// [`OidcError::NoIdToken`]) and the ID Token's ([`OidcError::Key`],
    /// [`OidcError::IdToken`], [`OidcError::Audience`],
    /// [`OidcError::AuthorizedParty`], [`OidcError::Nonce`]).
    pub async fn exchange(
        &self,
        pending: &PendingSignIn,
        callback: &Callback,
    ) -> Result<SignedIn, OidcError> {
        // NOTE: RFC 6749 §10.12: a redirect whose `state` is not the one the
        // request carried is refused before anything else it says is read.
        if !callback
            .state
            .as_deref()
            .is_some_and(|sent| equal(sent, &pending.state))
        {
            return Err(OidcError::StateMismatch);
        }
        if let Some(error) = &callback.error {
            return Err(OidcError::Authorization {
                error: OAuthError {
                    error: error.clone(),
                    error_description: callback.error_description.clone(),
                    error_uri: callback.error_uri.clone(),
                },
            });
        }
        let code = callback.code.as_ref().ok_or(OidcError::NoCode)?;
        let grant = [
            ("grant_type", "authorization_code"),
            ("code", code.expose()),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("code_verifier", pending.verifier.expose()),
        ];
        let tokens = self.token_request(&grant).await?;
        let id_token = tokens.id_token.ok_or(OidcError::NoIdToken)?;
        let claims = self.verify_id_token(&id_token, &pending.nonce).await?;
        // NOTE: RFC 6749 §5.1: an answer that names no scope granted the scope
        // requested, so the requested scopes stand for it.
        let scopes = tokens.scope.as_deref().map_or_else(
            || self.scopes().into_iter().map(str::to_owned).collect(),
            split_scopes,
        );
        Ok(SignedIn {
            access_token: Secret::new(tokens.access_token),
            expires_in: tokens.expires_in.map(Duration::from_secs),
            refresh_token: tokens.refresh_token.map(Secret::new),
            id_token: Secret::new(id_token),
            scopes,
            claims,
        })
    }

    /// Sends `refresh_token` to the token endpoint for a new access token
    /// (RFC 6749 §6).
    ///
    /// # Errors
    ///
    /// Returns [`OidcError::Discovery`] when the provider cannot be reached,
    /// [`OidcError::Refused`] with the provider's error code
    /// (`invalid_grant` among them), [`OidcError::Malformed`] and
    /// [`OidcError::TokenType`].
    pub async fn refresh(&self, refresh_token: &Secret) -> Result<Refreshed, OidcError> {
        self.refresh_grant(refresh_token, None).await
    }

    /// Sends `refresh_token` to the token endpoint for a new access token
    /// for the resource server `resource` (RFC 6749 §6, RFC 8707 §2.2), on
    /// the same grant.
    ///
    /// The provider audience-restricts the token to `resource` and decides
    /// which resources the grant reaches; the refresh token it rotates stays
    /// bound to the whole grant (RFC 8707 §2.2).
    ///
    /// # Errors
    ///
    /// As [`RelyingParty::refresh`], with [`OidcError::Refused`] carrying
    /// `invalid_target` for a resource the provider refuses (RFC 8707 §2).
    pub async fn refresh_for(
        &self,
        refresh_token: &Secret,
        resource: &str,
    ) -> Result<Refreshed, OidcError> {
        self.refresh_grant(refresh_token, Some(resource)).await
    }

    /// The refresh grant of `refresh_token`, naming `resource` when given.
    async fn refresh_grant(
        &self,
        refresh_token: &Secret,
        resource: Option<&str>,
    ) -> Result<Refreshed, OidcError> {
        let mut grant = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.expose()),
        ];
        if let Some(resource) = resource {
            grant.push(("resource", resource));
        }
        let tokens = self.token_request(&grant).await?;
        // NOTE: OpenID Connect Core 1.0 §12.2: a refresh answer might not contain
        // an `id_token`, so one it carries is not read; the sign-in's stays.
        Ok(Refreshed {
            access_token: Secret::new(tokens.access_token),
            expires_in: tokens.expires_in.map(Duration::from_secs),
            refresh_token: tokens.refresh_token.map(Secret::new),
            scopes: tokens.scope.as_deref().map(split_scopes),
        })
    }

    /// Returns the provider's end-session request, or `None` when the
    /// provider publishes no end-session endpoint (OpenID Connect
    /// RP-Initiated Logout 1.0 §2).
    ///
    /// It carries the ID Token hint when given, the client id, the
    /// post-logout redirect when configured, and `state` when given,
    /// appended to whatever query the endpoint already carries.
    #[must_use]
    pub fn end_session_url(
        &self,
        id_token_hint: Option<&Secret>,
        state: Option<&str>,
    ) -> Option<Url> {
        let mut url = self.provider.end_session_endpoint.clone()?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(hint) = id_token_hint {
                query.append_pair("id_token_hint", hint.expose());
            }
            query.append_pair("client_id", &self.client_id);
            if let Some(redirect) = &self.post_logout_redirect_uri {
                query.append_pair("post_logout_redirect_uri", redirect.as_str());
                if let Some(state) = state {
                    query.append_pair("state", state);
                }
            }
        }
        Some(url)
    }

    /// Tells the provider's revocation endpoint that `token` is finished with
    /// (RFC 7009 §2.1). A provider that publishes no revocation endpoint is
    /// left alone, and the call succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`OidcError::Discovery`] when the provider cannot be reached
    /// and [`OidcError::Revocation`] for any answer but `200` (RFC 7009
    /// §2.2).
    pub async fn revoke(&self, token: &Secret, hint: TokenTypeHint) -> Result<(), OidcError> {
        let Some(endpoint) = self.provider.revocation_endpoint.as_ref() else {
            return Ok(());
        };
        let form = [
            ("token", token.expose()),
            ("token_type_hint", hint.as_str()),
        ];
        let (status, _body) = self.post(endpoint, &form).await?;
        // NOTE: RFC 7009 §2.2: the provider answers 200 whether or not it knew
        // the token, so 200 is the one success.
        if status == StatusCode::OK {
            Ok(())
        } else {
            Err(OidcError::Revocation { status })
        }
    }

    /// Posts `grant` to the token endpoint and reads its bearer token answer
    /// (RFC 6749 §3.2, §5.1, §5.2).
    async fn token_request(&self, grant: &[(&str, &str)]) -> Result<TokenResponse, OidcError> {
        let (status, body) = self.post(&self.provider.token_endpoint, grant).await?;
        if status != StatusCode::OK {
            // NOTE: RFC 6749 §5.2 makes the error body JSON with `error`; a body
            // that is not one is a refusal without a code, never another fault.
            let error = serde_json::from_str::<OAuthError>(&body)
                .ok()
                .map(OAuthError::bounded);
            return Err(OidcError::Refused { status, error });
        }
        let tokens: TokenResponse =
            serde_json::from_str(&body).map_err(|source| OidcError::Malformed {
                source: source.into(),
            })?;
        if !tokens.token_type.eq_ignore_ascii_case("bearer") {
            return Err(OidcError::TokenType {
                found: tokens.token_type,
            });
        }
        Ok(tokens)
    }

    /// Posts `form` to `endpoint` as this client and returns the status and
    /// the body, capped at [`crate::metadata::MAX_DOCUMENT_BYTES`].
    async fn post(
        &self,
        endpoint: &Url,
        form: &[(&str, &str)],
    ) -> Result<(StatusCode, String), OidcError> {
        let transport = |source| DiscoveryError::Transport {
            url: endpoint.clone(),
            source,
        };
        let body = {
            let mut encoded = url::form_urlencoded::Serializer::new(String::new());
            encoded.extend_pairs(form);
            match &self.auth {
                ClientAuth::Public => {
                    encoded.append_pair("client_id", &self.client_id);
                }
                ClientAuth::SecretBasic(_) => {}
                ClientAuth::PrivateKeyJwt(key) => {
                    // NOTE: RFC 10070 §4: the issuer identifier is the sole `aud`;
                    // RFC 7521 §4.2 lets the client name itself beside the assertion.
                    let assertion = key
                        .assertion(
                            &self.client_id,
                            &self.provider.issuer,
                            crate::client::CLIENT_AUTHENTICATION_TYP,
                        )
                        .map_err(|source| OidcError::Assertion { source })?;
                    encoded
                        .append_pair("client_id", &self.client_id)
                        .append_pair("client_assertion_type", ASSERTION_TYPE)
                        .append_pair("client_assertion", &assertion);
                }
            }
            encoded.finish()
        };
        let mut request = self
            .http
            .client()
            .post(endpoint.clone())
            .header(http::header::ACCEPT, "application/json")
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            );
        if let ClientAuth::SecretBasic(secret) = &self.auth {
            // NOTE: RFC 6749 §2.3.1 form-encodes the id and the secret
            // (Appendix B) before they become the RFC 7617 user-pass.
            let user: String =
                url::form_urlencoded::byte_serialize(self.client_id.as_bytes()).collect();
            let password: String =
                url::form_urlencoded::byte_serialize(secret.expose_secret().as_bytes()).collect();
            request = request.basic_auth(user, Some(password));
        }
        let mut response = request.body(body).send().await.map_err(transport)?;
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(transport)? {
            if bytes.len().saturating_add(chunk.len()) > crate::metadata::MAX_DOCUMENT_BYTES {
                return Err(DiscoveryError::TooLarge {
                    url: endpoint.clone(),
                }
                .into());
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
    }

    /// Checks `id_token` against the provider's key set and `nonce`, and
    /// returns its claims (OpenID Connect Core 1.0 §3.1.3.7).
    async fn verify_id_token(
        &self,
        id_token: &str,
        nonce: &str,
    ) -> Result<IdTokenClaims, OidcError> {
        let (jws, key) = self.signing_key(id_token).await?;
        // NOTE: OpenID Connect Core 1.0 §3.1.3.7 items 2, 3, 6, 9 and 10: the `iss`
        // match, this client in `aud`, the signature by the issuer's key, `exp` and `iat`.
        let claims: IdTokenClaims = self
            .verified(&jws, &key, &["exp", "sub", "iat"])
            .map_err(|source| OidcError::IdToken { source })?;
        // NOTE: OpenID Connect Core 1.0 §3.1.3.7 item 3: an audience the client
        // does not trust refuses the token; it trusts itself and its trusted audiences.
        if !claims
            .audience
            .is_trusted(&self.client_id, &self.trusted_audiences)
        {
            return Err(OidcError::Audience);
        }
        // NOTE: OpenID Connect Core 1.0 §3.1.3.7 items 4 and 5: several audiences
        // need an `azp`, and an `azp` names the client the token was issued to.
        if claims
            .authorized_party
            .as_deref()
            .map_or(claims.audience.is_several(), |azp| azp != self.client_id)
        {
            return Err(OidcError::AuthorizedParty);
        }
        // NOTE: OpenID Connect Core 1.0 §3.1.3.7 item 11: the `nonce` must be the
        // one the authorization request sent, so a replayed ID Token is refused.
        let sent = claims.nonce.as_deref().ok_or(OidcError::Nonce)?;
        if !equal(sent, nonce) {
            return Err(OidcError::Nonce);
        }
        Ok(claims)
    }
}

impl RelyingParty {
    /// Returns the JWT `token` read into its parts and the provider's key
    /// that signed it: the key its `kid` names, or the set's one key that
    /// fits its algorithm when it names none, under an algorithm the client
    /// accepts.
    async fn signing_key<'t>(&self, token: &'t str) -> Result<(Unverified<'t>, Jwk), OidcError> {
        let jws = crate::jws::compact::decode(token).map_err(|_unreadable| OidcError::Key)?;
        let alg = jws.header().alg;
        if !self.algorithms.contains(&alg) {
            return Err(OidcError::Key);
        }
        let (_url, status, body) = self.http.get(self.provider.jwks_uri.clone()).await?;
        if status != StatusCode::OK {
            return Err(OidcError::KeySet { status });
        }
        let set: KeySet = serde_json::from_str(&body).map_err(|source| OidcError::KeySetBody {
            source: source.into(),
        })?;
        // NOTE: RFC 7517 §5, a member the reader does not understand is ignored,
        // so a member that is no supported public key is legitimately left out.
        let keys: Vec<Jwk> = set
            .keys
            .iter()
            .filter_map(|member| Jwk::try_from(member).ok())
            .collect();
        // NOTE: RFC 7515 §4.1.4 makes `kid` OPTIONAL, and OpenID Connect Core 1.0 §10.1
        // asks for one among several keys: without it, the one key that can verify `alg`.
        let key = crate::jws::jwk::select(&keys, jws.header().kid.as_deref(), alg)
            .ok_or(OidcError::Key)?
            .clone();
        Ok((jws, key))
    }

    /// Returns the claims of `jws`, which the provider signed with `key` for
    /// this client: the signature, the provider as `iss`, this client in
    /// `aud`, `exp` and `nbf` within the clock skew, and `required` present.
    fn verified<T: serde::de::DeserializeOwned>(
        &self,
        jws: &Unverified<'_>,
        key: &Jwk,
        required: &[&'static str],
    ) -> Result<T, JwtError> {
        let claims = jws.verify_claims(key)?;
        Validation::default()
            .with_issuer(self.provider.issuer.as_str())
            .with_audiences([self.client_id.as_str()])
            .with_required(required)
            .with_leeway(self.clock_skew)
            .check(&claims)?;
        serde_json::from_value(serde_json::Value::Object(claims))
            .map_err(|source| JwtError::Shape { source })
    }
}

/// A JWK Set document (RFC 7517 §5), each member read on its own.
#[derive(Deserialize)]
struct KeySet {
    /// The keys, as JSON objects.
    keys: Vec<serde_json::Value>,
}

/// Whether `a` and `b` are equal, compared in constant time.
fn equal(a: &str, b: &str) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a.as_bytes(), b.as_bytes()).is_ok()
}

/// Returns the scopes a `scope` member names (RFC 6749 §3.3).
fn split_scopes(scope: &str) -> Vec<String> {
    scope.split_whitespace().map(str::to_owned).collect()
}

/// Returns `RANDOM_BYTES` random bytes, base64url-encoded without padding.
fn random() -> Result<String, OidcError> {
    let mut bytes = [0_u8; RANDOM_BYTES];
    aws_lc_rs::rand::fill(&mut bytes).map_err(|_unspecified| OidcError::Random)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Returns the `S256` challenge of `verifier`: the base64url SHA-256 of its
/// ASCII (RFC 7636 §4.2).
#[must_use]
pub fn challenge(verifier: &str) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.as_ref())
}

/// A begun sign-in, which the console stores until the callback.
#[derive(Clone)]
pub struct PendingSignIn {
    state: String,
    nonce: String,
    verifier: Secret,
}

impl fmt::Debug for PendingSignIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingSignIn").finish_non_exhaustive()
    }
}

impl PendingSignIn {
    /// Mints a sign-in: a `state`, a `nonce` and a PKCE verifier of 256
    /// random bits each, base64url-encoded (RFC 7636 §4.1).
    ///
    /// # Errors
    ///
    /// Returns [`OidcError::Random`] when the random source fails.
    pub fn mint() -> Result<Self, OidcError> {
        Ok(Self {
            state: random()?,
            nonce: random()?,
            verifier: Secret::new(random()?),
        })
    }

    /// Rebuilds a sign-in the console stored from its parts.
    #[must_use]
    pub const fn from_parts(state: String, nonce: String, verifier: Secret) -> Self {
        Self {
            state,
            nonce,
            verifier,
        }
    }

    /// Returns the `state` the authorization request carries.
    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }

    /// Returns the `nonce` the authorization request carries.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Returns the PKCE verifier, which only the code exchange sends.
    #[must_use]
    pub const fn verifier(&self) -> &Secret {
        &self.verifier
    }

    /// Returns the `S256` challenge of the verifier.
    #[must_use]
    pub fn challenge(&self) -> String {
        challenge(self.verifier.expose())
    }
}

/// An authorization request: the URL the browser is redirected to and the
/// sign-in the console stores.
#[derive(Debug)]
#[non_exhaustive]
pub struct AuthorizationRequest {
    /// The authorization endpoint with the request's parameters.
    pub url: Url,
    /// The sign-in the callback completes.
    pub pending: PendingSignIn,
}

/// The query the provider sends the operator back with (RFC 6749 §4.1.2,
/// §4.1.2.1), as the console's callback route reads it.
#[derive(Default, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Callback {
    /// The authorization code.
    #[serde(deserialize_with = "secret_code")]
    pub code: Option<Secret>,
    /// The `state` the authorization request carried.
    pub state: Option<String>,
    /// The error code of a refused request.
    pub error: Option<String>,
    /// The error's description, when the provider sent one.
    pub error_description: Option<String>,
    /// The page describing the error, when the provider sent one.
    pub error_uri: Option<String>,
}

impl Callback {
    /// The redirect of a granted request: `code` for the sign-in whose
    /// `state` it names.
    #[must_use]
    pub fn granted(code: impl Into<String>, state: impl Into<String>) -> Self {
        Self {
            code: Some(Secret::new(code)),
            state: Some(state.into()),
            ..Self::default()
        }
    }

    /// The redirect of a refused request: the error code `error` for the
    /// sign-in whose `state` it names.
    #[must_use]
    pub fn refused(error: impl Into<String>, state: impl Into<String>) -> Self {
        Self {
            error: Some(error.into()),
            state: Some(state.into()),
            ..Self::default()
        }
    }
}

impl fmt::Debug for Callback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Callback")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

/// Reads the `code` parameter into a [`Secret`].
fn secret_code<'de, D>(deserializer: D) -> Result<Option<Secret>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.map(Secret::new))
}

/// The hint a revocation request names (RFC 7009 §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenTypeHint {
    /// An access token.
    AccessToken,
    /// A refresh token.
    RefreshToken,
}

impl TokenTypeHint {
    /// The hint's wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccessToken => "access_token",
            Self::RefreshToken => "refresh_token",
        }
    }
}

/// A completed sign-in: the operator's tokens and the checked ID Token's
/// claims, which the console keeps in its session.
#[non_exhaustive]
pub struct SignedIn {
    /// The access token.
    pub access_token: Secret,
    /// Its lifetime, when the provider stated one.
    pub expires_in: Option<Duration>,
    /// The refresh token, when the provider issued one.
    pub refresh_token: Option<Secret>,
    /// The ID Token, the hint of a later sign-out.
    pub id_token: Secret,
    /// The scopes granted.
    pub scopes: Vec<String>,
    /// The ID Token's claims.
    pub claims: IdTokenClaims,
}

impl fmt::Debug for SignedIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedIn")
            .field("claims", &self.claims)
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

/// A refreshed access token (RFC 6749 §5.1).
#[non_exhaustive]
pub struct Refreshed {
    /// The new access token.
    pub access_token: Secret,
    /// Its lifetime, when the provider stated one.
    pub expires_in: Option<Duration>,
    /// The rotated refresh token, when the provider issued one; the old one
    /// is then spent.
    pub refresh_token: Option<Secret>,
    /// The scopes granted, when the provider stated them.
    pub scopes: Option<Vec<String>>,
}

impl fmt::Debug for Refreshed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Refreshed")
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

/// The claims of a checked ID Token (OpenID Connect Core 1.0 §2, §5.1).
///
/// Its `Debug` rendering names the issuer and the subject alone.
#[derive(Clone, Deserialize)]
#[non_exhaustive]
pub struct IdTokenClaims {
    /// The issuer.
    #[serde(rename = "iss")]
    pub issuer: String,
    /// The subject: the operator at the provider.
    #[serde(rename = "sub")]
    pub subject: String,
    /// The audience.
    #[serde(rename = "aud")]
    audience: Audience,
    /// The client the token was issued to.
    #[serde(rename = "azp", default)]
    authorized_party: Option<String>,
    /// The nonce of the authorization request.
    #[serde(default)]
    nonce: Option<String>,
    /// The operator's full name.
    #[serde(default)]
    pub name: Option<String>,
    /// The name the operator goes by at the provider.
    #[serde(default)]
    pub preferred_username: Option<String>,
    /// Every other claim, for a product that reads one of its own.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

impl fmt::Debug for IdTokenClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdTokenClaims")
            .field("issuer", &self.issuer)
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

impl IdTokenClaims {
    /// The name a console shows: `name`, else `preferred_username`, each
    /// trimmed and skipped when empty.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        [self.name.as_deref(), self.preferred_username.as_deref()]
            .into_iter()
            .flatten()
            .map(str::trim)
            .find(|name| !name.is_empty())
    }
}

/// An ID Token's `aud`: one string or an array (OpenID Connect Core 1.0
/// §2).
#[derive(Clone, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Several(Vec<String>),
}

impl Audience {
    /// Whether the audience names `client_id` and nothing beside it but
    /// `trusted`.
    fn is_trusted(&self, client_id: &str, trusted: &[String]) -> bool {
        match self {
            Self::One(audience) => audience == client_id,
            Self::Several(audiences) => {
                audiences.iter().any(|audience| audience == client_id)
                    && audiences
                        .iter()
                        .all(|audience| audience == client_id || trusted.contains(audience))
            }
        }
    }

    /// Whether the audience names more than one value.
    fn is_several(&self) -> bool {
        matches!(self, Self::Several(audiences) if audiences.len() > 1)
    }
}

/// The token endpoint's answer (RFC 6749 §5.1, OpenID Connect Core 1.0
/// §3.1.3.3).
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
    id_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{Audience, Callback, PendingSignIn, challenge};

    #[test]
    fn the_challenge_is_the_rfc_7636_appendix_b_example() {
        assert_eq!(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        );
    }

    #[test]
    fn a_minted_sign_in_is_fresh_and_its_verifier_is_43_characters() {
        let one = PendingSignIn::mint().expect("a sign-in");
        let two = PendingSignIn::mint().expect("a sign-in");
        assert_eq!(43, one.verifier().expose().len());
        assert_ne!(one.state(), two.state());
        assert_ne!(one.nonce(), two.nonce());
        assert_ne!(one.state(), one.nonce());
    }

    #[test]
    fn nothing_secret_is_rendered() {
        let pending = PendingSignIn::mint().expect("a sign-in");
        let rendered = format!("{pending:?}");
        assert!(!rendered.contains(pending.state()), "{rendered}");
        assert!(
            !rendered.contains(pending.verifier().expose()),
            "{rendered}"
        );
        let callback = Callback::granted("the-code", "the-state");
        assert!(!format!("{callback:?}").contains("the-code"));
    }

    #[test]
    fn an_audience_beyond_the_client_is_refused() {
        assert!(Audience::One("console".into()).is_trusted("console", &[]));
        assert!(Audience::Several(vec!["console".into()]).is_trusted("console", &[]));
        let wide = Audience::Several(vec!["console".into(), "other".into()]);
        assert!(!wide.is_trusted("console", &[]));
        assert!(wide.is_several());
        assert!(!Audience::One("other".into()).is_trusted("console", &[]));
    }

    #[test]
    fn a_trusted_audience_beside_the_client_is_accepted() {
        let trusted = [String::from("project")];
        let wide = Audience::Several(vec!["console".into(), "project".into()]);
        assert!(wide.is_trusted("console", &trusted));
        let stranger = Audience::Several(vec!["console".into(), "project".into(), "other".into()]);
        assert!(
            !stranger.is_trusted("console", &trusted),
            "an untrusted third"
        );
        let without = Audience::Several(vec!["project".into()]);
        assert!(
            !without.is_trusted("console", &trusted),
            "the client is missing"
        );
    }
}
