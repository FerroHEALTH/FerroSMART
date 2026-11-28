// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The credential a product obtains for itself with the OAuth 2.0 client
//! credentials grant (RFC 6749 §4.4), cached and renewed before it expires.
//!
//! A product reaches an upstream under its own token for the upstream's
//! audience and never forwards a caller's token, because an access token
//! names the resource server it is for (RFC 9068 §4). The token endpoint is
//! configured outright or discovered from the issuer's metadata
//! ([`crate::metadata`]). The client authenticates with `client_secret_basic`
//! or `client_secret_post` (RFC 6749 §2.3.1), with a `private_key_jwt`
//! assertion (RFC 7523 §2.2, [`assertion`]), or with a client certificate
//! over mutual TLS (RFC 8705 §2). Extra trust roots and the client
//! certificate travel in [`Tls`]. `cache::TokenSource`, behind the default
//! `fetch` feature, fetches on first use, shares one fetch among concurrent callers, hands out the
//! bearer credential per attempt, and sends a call once more with a new
//! token when the upstream refuses the held one with `401`.
//!
//! A grant may bind its tokens ([`binding::TokenBinding`]): to a `DPoP` key
//! ([`dpop`]), whose proof every token request and every resource request
//! carries (RFC 9449), or to the client certificate it presents, which every
//! issued token that states a binding must name (RFC 8705 §3).
//!
//! `onward`, behind `fetch` as well, obtains a token for another service on behalf of a caller, by
//! token exchange (RFC 8693 §2.1) or the JWT bearer grant (RFC 7523 §2.1),
//! and refuses one that fails the onward check.

pub mod assertion;
pub mod authorization_details;
pub mod binding;
#[cfg(feature = "fetch")]
pub mod cache;
pub mod dpop;
#[cfg(feature = "fetch")]
pub(crate) mod endpoint;
pub mod fapi2;
pub mod keys;
#[cfg(feature = "fetch")]
pub mod onward;
#[cfg(feature = "fetch")]
pub mod outbound;

use std::sync::Arc;
use std::time::Duration;

use http::StatusCode;
use secrecy::SecretString;
use serde::Deserialize;
use serde::Serialize;
use url::Url;

use crate::client::assertion::AssertionKey;
use crate::client::authorization_details::AuthorizationDetails;
use crate::client::authorization_details::AuthorizationDetailsError;
use crate::client::binding::TokenBinding;
use crate::client::dpop::DpopKey;
use crate::client::fapi2::Fapi2Error;
use crate::client::fapi2::SecurityProfile;
use crate::client::keys::KeyRing;
use crate::metadata::DiscoveryError;

/// Where the token endpoint comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// The issuer identifier, whose metadata names the token endpoint
    /// (RFC 8414 §2). Kept as configured, because the metadata's `issuer`
    /// must be identical to it (RFC 8414 §3.3).
    Issuer(String),
    /// The token endpoint itself (RFC 6749 §3.2).
    Token(Url),
}

/// How the client authenticates to the token endpoint, configured and
/// never guessed from the server's metadata.
#[expect(
    clippy::enum_variant_names,
    reason = "the variants mirror the RFC 8705 §2 method names tls_client_auth and self_signed_tls_client_auth"
)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ClientAuth {
    /// HTTP Basic over the form-encoded client id and secret, the scheme every
    /// authorization server must support (RFC 6749 §2.3.1).
    #[default]
    ClientSecretBasic,
    /// The client id and secret as `client_id` and `client_secret` in the
    /// request body (RFC 6749 §2.3.1), for an authorization server that
    /// accepts nothing else.
    ClientSecretPost,
    /// A signed client assertion in the request body (RFC 7523 §2.2), the
    /// form RFC 9700 §2.5 recommends and SMART Backend Services requires.
    PrivateKeyJwt,
    /// A client certificate the authorization server checks against its
    /// PKI and the client's registered subject (RFC 8705 §2.1), with
    /// `client_id` in the request body.
    TlsClientAuth,
    /// A self-signed client certificate the authorization server checks
    /// against the client's registered keys (RFC 8705 §2.2), with
    /// `client_id` in the request body.
    SelfSignedTlsClientAuth,
}

impl ClientAuth {
    /// Returns whether the method authenticates with a client certificate
    /// over mutual TLS (RFC 8705 §2).
    #[must_use]
    pub const fn is_mutual_tls(self) -> bool {
        matches!(self, Self::TlsClientAuth | Self::SelfSignedTlsClientAuth)
    }
}

/// The explicit type of a FAPI 2.0 grant's client assertion, the type RFC
/// 10070 §4 has every client authentication JWT carry.
pub const CLIENT_AUTHENTICATION_TYP: &str = "client-authentication+jwt";

/// Returns what of `url` a token endpoint must not carry: `userinfo`
/// (RFC 9110 §4.2.4, RFC 3986 §3.2.1) or a `fragment` (RFC 6749 §3.2). A
/// query is admitted (RFC 6749 §3.2).
pub(crate) fn forbidden_part(url: &Url) -> Option<&'static str> {
    if !url.username().is_empty() || url.password().is_some() {
        Some("userinfo")
    } else if url.fragment().is_some() {
        Some("a fragment")
    } else {
        None
    }
}

/// Refuses the token endpoint `url`, named by `member`, when it carries
/// what [`forbidden_part`] finds.
pub(crate) fn check_token_endpoint(url: &Url, member: &'static str) -> Result<(), TokenError> {
    forbidden_part(url).map_or(Ok(()), |part| {
        Err(TokenError::TokenEndpointShape { member, part })
    })
}

/// The TLS of an outbound connection.
///
/// It is the configuration the product built from the table's `tls` keys,
/// or, when the table names no TLS material and the product built none, the
/// platform's roots at the table's minimum version.
///
/// The crate reads no TLS file: a table that names material is built by the
/// product's [`TlsBuilder`](crate::config::TlsBuilder), so the family has one
/// reader of TLS material, `ferrohealth-server`'s `TlsClient`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tls {
    /// The TLS configuration the product built, with the client certificate
    /// it presents.
    pub presented: Option<PresentedTls>,
    /// The oldest TLS version the connection speaks when the product built
    /// no configuration; a built configuration keeps its own versions.
    pub min_version: ferrohealth_config::tls::TlsVersion,
}

impl Tls {
    /// Returns the certificate the connection presents in the handshake,
    /// the end-entity certificate of `presented` (RFC 8446 §4.4.2), or
    /// `None` when it presents none.
    #[must_use]
    pub fn presented_certificate(&self) -> Option<crate::sender::ClientCertificate> {
        self.presented
            .as_ref()
            .and_then(PresentedTls::certificate)
            .map(|certificate| crate::sender::ClientCertificate::from_der(certificate))
    }

    /// Returns whether the connection presents a client certificate.
    #[must_use]
    pub fn presents_identity(&self) -> bool {
        self.presented
            .as_ref()
            .is_some_and(|presented| presented.certificate().is_some())
    }
}

/// A rustls client configuration a product built from TLS material it read
/// once, such as with `ferrohealth-server`'s `TlsClient`, and the end-entity
/// certificate of the client identity it presents.
///
/// The configuration carries the trust roots, the protocol versions and the
/// client identity; the crate reads no file and holds no key bytes for it.
/// The certificate is public material: a mutual-TLS method needs one
/// (RFC 8705 §2), and a certificate-bound grant compares the token's
/// `x5t#S256` with its thumbprint (RFC 8705 §3.1).
#[derive(Clone)]
pub struct PresentedTls {
    config: Arc<rustls::ClientConfig>,
    certificate: Option<rustls::pki_types::CertificateDer<'static>>,
    unchecked_roots: Option<String>,
    kept: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

impl PresentedTls {
    /// Returns the configuration `config`, whose client identity presents
    /// `certificate`; `None` when it presents no client certificate.
    #[must_use]
    pub fn new(
        config: Arc<rustls::ClientConfig>,
        certificate: Option<rustls::pki_types::CertificateDer<'static>>,
    ) -> Self {
        Self {
            config,
            certificate,
            unchecked_roots: None,
            kept: None,
        }
    }

    /// Returns the configuration naming `roots`, the line that names the
    /// roots it trusts with no revocation check, for the product's startup
    /// banner.
    #[must_use]
    pub fn with_unchecked_roots(mut self, roots: String) -> Self {
        self.unchecked_roots = Some(roots);
        self
    }

    /// Returns the configuration holding `kept` for as long as it lives,
    /// such as the task that keeps its endpoints cleared for revocation.
    #[must_use]
    pub fn keeping(mut self, kept: Arc<dyn std::any::Any + Send + Sync>) -> Self {
        self.kept = Some(kept);
        self
    }

    /// Returns the line that names the roots the configuration trusts with
    /// no revocation check, or `None` when it trusts none so.
    #[must_use]
    pub fn unchecked_roots(&self) -> Option<&str> {
        self.unchecked_roots.as_deref()
    }

    /// Returns the rustls client configuration.
    #[must_use]
    pub fn config(&self) -> &Arc<rustls::ClientConfig> {
        &self.config
    }

    /// Returns the end-entity certificate the configuration presents.
    #[must_use]
    pub fn certificate(&self) -> Option<&rustls::pki_types::CertificateDer<'static>> {
        self.certificate.as_ref()
    }
}

// NOTE: no specification governs this: our own design; two values are the same
// configuration when they share one built configuration and one certificate.
impl PartialEq for PresentedTls {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.config, &other.config) && self.certificate == other.certificate
    }
}

impl Eq for PresentedTls {}

impl std::fmt::Debug for PresentedTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresentedTls")
            .field("certificate", &self.certificate.is_some())
            .field("unchecked_roots", &self.unchecked_roots)
            .field("kept", &self.kept.is_some())
            .finish_non_exhaustive()
    }
}

/// How a connection reaches its server beyond its TLS material.
///
/// It names the lowest TLS version the connection negotiates, and the hosts
/// it reaches at a fixed address in place of resolving their names, for a
/// server whose name resolves only inside a private network (no
/// specification governs the override: our own design). An override replaces the name lookup only. The URL's port and the
/// certificate check against the host name stay as the URL names them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reach {
    min_tls_version: ferrohealth_config::tls::TlsVersion,
    resolve: Vec<(String, std::net::SocketAddr)>,
}

impl Default for Reach {
    fn default() -> Self {
        Self {
            // NOTE: RFC 9325 §3.1.1 allows TLS 1.2; the table's own minimum raises it.
            min_tls_version: ferrohealth_config::tls::TlsVersion::Tls12,
            resolve: Vec::new(),
        }
    }
}

impl Reach {
    /// Returns this reach negotiating no TLS version below `version`.
    #[must_use]
    pub const fn with_min_tls_version(
        mut self,
        version: ferrohealth_config::tls::TlsVersion,
    ) -> Self {
        self.min_tls_version = version;
        self
    }

    /// Returns this reach reaching `host` at `address`.
    #[must_use]
    pub fn with_resolve(mut self, host: impl Into<String>, address: std::net::SocketAddr) -> Self {
        self.resolve.push((host.into(), address));
        self
    }

    /// The lowest TLS version the connection negotiates.
    #[must_use]
    pub const fn min_tls_version(&self) -> ferrohealth_config::tls::TlsVersion {
        self.min_tls_version
    }

    /// The hosts reached at a fixed address, each with its address.
    #[must_use]
    pub fn resolve(&self) -> &[(String, std::net::SocketAddr)] {
        &self.resolve
    }
}

/// Everything a product needs to obtain its upstream token.
///
/// The secret is a [`SecretString`] and the key redacts itself, so a
/// `Debug` rendering never carries either.
#[derive(Debug, Clone)]
pub struct ClientCredentials {
    /// Where the token endpoint comes from.
    pub endpoint: Endpoint,
    /// The client identifier (RFC 6749 §2.2).
    pub client_id: String,
    /// How the client authenticates to the token endpoint.
    pub client_auth: ClientAuth,
    /// The client secret, under `client_secret_basic` and
    /// `client_secret_post`.
    pub client_secret: Option<SecretString>,
    /// The keys the client assertion is signed with under
    /// `private_key_jwt`, and the actor assertion of an onward exchange
    /// whatever the client authentication (RFC 8693 §2.1): the ring's
    /// current key signs, and the ring is shared with whatever else
    /// publishes or signs with it. Under another method it signs no
    /// `client_assertion`.
    pub assertion_keys: Option<Arc<KeyRing>>,
    /// The `scope` request parameter (RFC 6749 §3.3), when the deployment
    /// asks for one.
    pub scope: Option<String>,
    /// The `audience` request parameter some authorization servers read in
    /// place of a resource indicator; no specification defines it for this
    /// grant, so it is sent only when configured.
    pub audience: Option<String>,
    /// The `resource` request parameter (RFC 8707 §2), the upstream the
    /// token is for.
    pub resource: Option<Url>,
    /// How long before the token expires a new one is fetched.
    pub refresh_margin: Duration,
    /// How long one call to the authorization server may take.
    pub timeout: Duration,
    /// The trust roots and the client certificate of the token endpoint
    /// connection.
    pub tls: Tls,
    /// What the issued tokens are bound to, when they are sender-constrained
    /// (RFC 9449, RFC 8705 §3); `None` for bearer tokens.
    pub token_binding: Option<TokenBinding>,
    /// The `authorization_details` every token request carries (RFC 9396
    /// §6), and the token response must state as granted (§7).
    pub authorization_details: Option<AuthorizationDetails>,
    /// The security profile the grant is held to.
    pub profile: SecurityProfile,
}

impl ClientCredentials {
    /// Returns a grant for `client_id` with `client_secret` at `endpoint`.
    ///
    /// The client authenticates with HTTP Basic, sends no `scope`, `audience`
    /// or `resource`, renews its token 30 seconds before it expires, and
    /// gives the authorization server 10 seconds per call.
    #[must_use]
    pub fn new(endpoint: Endpoint, client_id: String, client_secret: SecretString) -> Self {
        Self {
            client_secret: Some(client_secret),
            ..Self::authenticating(endpoint, client_id, ClientAuth::default())
        }
    }

    /// Returns a grant for `client_id` at `endpoint` authenticating with a
    /// client assertion signed by `key`.
    #[must_use]
    pub fn with_private_key_jwt(endpoint: Endpoint, client_id: String, key: AssertionKey) -> Self {
        Self::with_key_ring(endpoint, client_id, Arc::new(KeyRing::new(key)))
    }

    /// Returns a grant for `client_id` at `endpoint` authenticating with a
    /// client assertion signed by the current key of `keys`.
    #[must_use]
    pub fn with_key_ring(endpoint: Endpoint, client_id: String, keys: Arc<KeyRing>) -> Self {
        Self {
            assertion_keys: Some(keys),
            ..Self::authenticating(endpoint, client_id, ClientAuth::PrivateKeyJwt)
        }
    }

    /// Returns a grant for `client_id` at `endpoint` authenticating with the
    /// client certificate `tls` presents over mutual TLS (RFC 8705 §2), the
    /// TLS configuration a product built from material it already read:
    /// [`ClientAuth::SelfSignedTlsClientAuth`] when `self_signed`,
    /// [`ClientAuth::TlsClientAuth`] otherwise.
    #[must_use]
    pub fn with_presented_tls(
        endpoint: Endpoint,
        client_id: String,
        tls: PresentedTls,
        self_signed: bool,
    ) -> Self {
        let client_auth = if self_signed {
            ClientAuth::SelfSignedTlsClientAuth
        } else {
            ClientAuth::TlsClientAuth
        };
        Self {
            tls: Tls {
                presented: Some(tls),
                ..Tls::default()
            },
            ..Self::authenticating(endpoint, client_id, client_auth)
        }
    }

    /// Returns a grant for `client_id` at `endpoint` authenticating with
    /// `client_auth`, holding no credential yet, with the defaults of
    /// [`ClientCredentials::new`].
    fn authenticating(endpoint: Endpoint, client_id: String, client_auth: ClientAuth) -> Self {
        Self {
            endpoint,
            client_id,
            client_auth,
            client_secret: None,
            assertion_keys: None,
            scope: None,
            audience: None,
            resource: None,
            refresh_margin: Duration::from_secs(30),
            timeout: Duration::from_secs(10),
            tls: Tls::default(),
            token_binding: None,
            authorization_details: None,
            profile: SecurityProfile::OAuth2,
        }
    }

    /// Returns this grant binding its tokens to `key`: every token request
    /// and every resource request carries a proof of it, and only a token of
    /// type `DPoP` is taken (RFC 9449 §5, §7.1).
    #[must_use]
    pub fn with_dpop(mut self, key: Arc<DpopKey>) -> Self {
        self.token_binding = Some(TokenBinding::Dpop(key));
        self
    }

    /// Returns this grant taking only tokens whose stated binding names the
    /// client certificate of its TLS identity (RFC 8705 §3).
    #[must_use]
    pub fn with_certificate_binding(mut self) -> Self {
        self.token_binding = Some(TokenBinding::Certificate);
        self
    }

    /// Returns the `DPoP` key the grant's tokens are bound to, when they are.
    #[must_use]
    pub fn dpop_key(&self) -> Option<&Arc<DpopKey>> {
        match &self.token_binding {
            Some(TokenBinding::Dpop(key)) => Some(key),
            Some(TokenBinding::Certificate) | None => None,
        }
    }

    /// Returns the thumbprint of the certificate a certificate-bound grant
    /// presents, when its tokens are bound to one and its identity holds one.
    pub(crate) fn bound_certificate(&self) -> Option<crate::sender::ClientCertificate> {
        match self.token_binding {
            Some(TokenBinding::Certificate) => self.tls.presented_certificate(),
            Some(TokenBinding::Dpop(_)) | None => None,
        }
    }

    /// Checks that the grant carries the credential its method needs.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::Credential`] naming what is missing: a secret,
    /// an assertion key, a client certificate under a mutual-TLS method or
    /// a certificate binding, or the issuer an issuer assertion audience
    /// names; [`TokenError::TokenEndpointShape`] for a configured token
    /// endpoint with userinfo or a fragment; and [`TokenError::Fapi2`] for a FAPI 2.0 grant that breaks a
    /// rule of the profile.
    pub fn validate(&self) -> Result<(), TokenError> {
        self.validate_credential()?;
        if let SecurityProfile::Fapi2(profile) = &self.profile {
            fapi2::check_grant(self, profile).map_err(|source| TokenError::Fapi2 { source })?;
        }
        Ok(())
    }

    /// Checks that the grant carries the credential its method needs.
    fn validate_credential(&self) -> Result<(), TokenError> {
        if let Endpoint::Token(url) = &self.endpoint {
            check_token_endpoint(url, "configured token endpoint")?;
        }
        // NOTE: RFC 8705 §3, a certificate-bound token is bound to the certificate
        // the client presents, so a grant that presents none cannot take one.
        if matches!(self.token_binding, Some(TokenBinding::Certificate))
            && self.bound_certificate().is_none()
        {
            return Err(TokenError::Credential {
                what: "client certificate for the certificate binding",
            });
        }
        match self.client_auth {
            ClientAuth::ClientSecretBasic | ClientAuth::ClientSecretPost
                if self.client_secret.is_none() =>
            {
                Err(TokenError::Credential {
                    what: "a client secret",
                })
            }
            ClientAuth::PrivateKeyJwt if self.assertion_keys.is_none() => {
                Err(TokenError::Credential {
                    what: "an assertion key",
                })
            }
            ClientAuth::TlsClientAuth | ClientAuth::SelfSignedTlsClientAuth
                if !self.tls.presents_identity() =>
            {
                Err(TokenError::Credential {
                    what: "client certificate",
                })
            }
            _ => Ok(()),
        }
    }
}

/// The most characters a refusal keeps of each member of an upstream
/// [`OAuthError`]; no specification governs the bound: our own design.
pub const MAX_ERROR_TEXT: usize = 256;

/// The error response of a token endpoint (RFC 6749 §5.2).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct OAuthError {
    /// The error code: `invalid_request`, `invalid_client`, `invalid_grant`,
    /// `unauthorized_client`, `unsupported_grant_type` or `invalid_scope`.
    pub error: String,
    /// The human-readable description, when the server sent one.
    pub error_description: Option<String>,
    /// The page describing the error, when the server sent one.
    pub error_uri: Option<String>,
}

#[cfg(feature = "fetch")]
impl OAuthError {
    /// Returns the error with each member cut to [`MAX_ERROR_TEXT`]
    /// characters, as a refusal keeps it.
    #[must_use]
    pub(crate) fn bounded(self) -> Self {
        let cut = |text: String| text.chars().take(MAX_ERROR_TEXT).collect::<String>();
        Self {
            error: cut(self.error),
            error_description: self.error_description.map(cut),
            error_uri: self.error_uri.map(cut),
        }
    }
}

impl std::fmt::Display for OAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.error_description.as_deref() {
            Some(description) => write!(f, "{} ({description})", self.error),
            None => f.write_str(&self.error),
        }
    }
}

/// A token the product could not obtain.
///
/// No variant carries the client secret, the key or a token.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TokenError {
    /// The metadata naming the token endpoint could not be read, or the
    /// token request never completed.
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
    /// The grant lacks the credential its authentication method needs.
    #[error("the client credentials grant carries no {what}")]
    Credential {
        /// What is missing.
        what: &'static str,
    },
    /// The client assertion could not be signed.
    #[error("the client assertion could not be signed")]
    Assertion {
        /// Why.
        #[source]
        source: assertion::AssertionError,
    },
    /// The metadata names no token endpoint.
    #[error("the authorization server metadata names no token_endpoint")]
    NoTokenEndpoint,
    /// The token endpoint carries userinfo or a fragment, which RFC 6749
    /// §3.2 and RFC 9110 §4.2.4 keep out of a token endpoint; the URL is
    /// never quoted.
    #[error(
        "the {member} carries {part}, which a token endpoint must not (RFC 6749 §3.2, RFC 9110 §4.2.4)"
    )]
    TokenEndpointShape {
        /// Where the endpoint came from: the configured endpoint or the
        /// metadata member that named it.
        member: &'static str,
        /// What it carries: `userinfo` or a `fragment`.
        part: &'static str,
    },
    /// The metadata names a token endpoint that is not a URL.
    #[error("the authorization server metadata names a token endpoint that is not a URL")]
    TokenEndpointUrl {
        /// What the URL parser reported.
        #[source]
        source: url::ParseError,
    },
    /// The token endpoint answered anything other than `200`, with the OAuth
    /// error when the body carried one (RFC 6749 §5.2), each of its members
    /// cut to [`MAX_ERROR_TEXT`] characters; nothing else of the body is
    /// kept.
    #[error("the token endpoint answered {status}{}", oauth_clause(error.as_ref()))]
    Refused {
        /// The status it answered.
        status: StatusCode,
        /// The OAuth error, when the body was one.
        error: Option<OAuthError>,
    },
    /// The `200` body is not the access token response of RFC 6749 §5.1.
    #[error("the token endpoint answered a body that is not an access token response")]
    Malformed {
        /// What the JSON reader reported.
        #[source]
        source: crate::json::JsonError,
    },
    /// The token is not of the type the grant asks for: `Bearer` (RFC 6750),
    /// or `DPoP` for a grant whose tokens are bound to a `DPoP` key (RFC 9449
    /// §5).
    #[error("the token endpoint issued a token of type {found:?}; the grant asks for {expected}")]
    TokenType {
        /// The `token_type` the response named.
        found: String,
        /// The type the grant asks for.
        expected: &'static str,
    },
    /// The token cannot travel as an RFC 6750 §2.1 or RFC 9449 §7.1
    /// credential: it carries a byte outside the `b64token` alphabet.
    #[error("the issued token cannot travel as a credential")]
    Unusable,
    /// The `DPoP` proof of the token request could not be signed (RFC 9449
    /// §4.2); nothing was sent.
    #[error("the DPoP proof of the token request could not be signed")]
    Proof {
        /// Why.
        #[source]
        source: dpop::DpopError,
    },
    /// The issued token states a binding to another certificate than the
    /// one the grant presents, or to another confirmation method, so it was
    /// neither kept nor used (RFC 8705 §3).
    #[error("the issued token is not bound to the certificate the client presents (RFC 8705 §3)")]
    CertificateMismatch,
    /// A FAPI 2.0 grant, or its authorization server's metadata, breaks a
    /// rule of the profile; nothing was sent to the token endpoint.
    #[error("the grant breaks the FAPI 2.0 Security Profile")]
    Fapi2 {
        /// The rule.
        #[source]
        source: Fapi2Error,
    },
    /// The metadata does not list an authorization details type the grant
    /// asks for (RFC 9396 §10); nothing was sent to the token endpoint.
    #[error("the authorization server does not list the authorization details type {kind:?}")]
    AuthorizationDetailsType {
        /// The type.
        kind: String,
    },
    /// The grant asked for `authorization_details` and the token response
    /// states none it granted (RFC 9396 §7).
    #[error("the token response states no authorization_details, which RFC 9396 §7 requires")]
    AuthorizationDetails,
    /// The `authorization_details` the token response states it granted
    /// are not of RFC 9396 §2 shape.
    #[error("the authorization_details the token response granted are not of RFC 9396 §2 shape")]
    GrantedDetails {
        /// Why.
        #[source]
        source: AuthorizationDetailsError,
    },
    /// The fetch ended without an outcome.
    #[error("the token fetch ended without an outcome")]
    Abandoned,
}

impl TokenError {
    /// Returns the status the authorization server answered, when the failure
    /// carries one.
    #[must_use]
    pub const fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Discovery(DiscoveryError::Status { status, .. })
            | Self::Refused { status, .. } => Some(*status),
            _ => None,
        }
    }
}

/// The upstream refused the token (`401`) and no new one could be obtained.
#[derive(Debug, thiserror::Error)]
#[error("the upstream refused the token (401) and no new token could be obtained")]
pub struct RenewalError {
    /// Why the new token could not be obtained.
    #[source]
    source: Arc<TokenError>,
}

impl RenewalError {
    /// Returns the renewal failure `source` caused.
    #[must_use]
    pub const fn new(source: Arc<TokenError>) -> Self {
        Self { source }
    }

    /// Returns why the new token could not be obtained.
    #[must_use]
    pub fn token_error(&self) -> &TokenError {
        &self.source
    }
}

/// Why a call under a token failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CallError<E> {
    /// No token could be obtained before the first attempt.
    #[error("no token could be obtained for the call")]
    Token {
        /// Why.
        #[source]
        source: Arc<TokenError>,
    },
    /// The upstream refused the token and no new one could be obtained.
    #[error(transparent)]
    Renewal(RenewalError),
    /// The call itself failed.
    #[error("the call failed")]
    Call {
        /// What the call reported.
        #[source]
        source: E,
    },
    /// The source's tokens are bound to a `DPoP` key, so a call that is
    /// handed the `Authorization` value alone cannot prove it; nothing was
    /// sent (RFC 9449 §7.1).
    #[error("the token is DPoP-bound and the call carries no proof; nothing was sent")]
    Unproven,
    /// The `DPoP` proof of the call could not be signed; nothing was sent.
    #[error("the DPoP proof of the call could not be signed")]
    Proof {
        /// Why.
        #[source]
        source: dpop::DpopError,
    },
}

/// Returns the OAuth clause of a refusal's display.
fn oauth_clause(error: Option<&OAuthError>) -> String {
    error.map_or_else(String::new, |error| format!(": {error}"))
}

#[cfg(test)]
mod tests {
    use super::{ClientAuth, ClientCredentials, Endpoint, OAuthError, TokenError};
    use http::StatusCode;
    use secrecy::SecretString;

    #[test]
    fn a_refusal_displays_the_oauth_error_and_its_description() {
        let error = TokenError::Refused {
            status: StatusCode::UNAUTHORIZED,
            error: Some(OAuthError {
                error: String::from("invalid_client"),
                error_description: Some(String::from("unknown client")),
                error_uri: None,
            }),
        };
        assert_eq!(
            "the token endpoint answered 401 Unauthorized: invalid_client (unknown client)",
            error.to_string()
        );
        assert_eq!(Some(StatusCode::UNAUTHORIZED), error.status());
    }

    #[test]
    fn a_grant_needs_the_credential_of_its_method() {
        let mut grant = ClientCredentials::new(
            Endpoint::Issuer(String::from("https://as.example.org")),
            String::from("client"),
            SecretString::from("synthetic-pw"),
        );
        assert!(grant.validate().is_ok());
        grant.client_auth = ClientAuth::PrivateKeyJwt;
        assert!(matches!(
            grant.validate(),
            Err(TokenError::Credential {
                what: "an assertion key"
            })
        ));
        grant.client_auth = ClientAuth::ClientSecretPost;
        grant.client_secret = None;
        assert!(matches!(
            grant.validate(),
            Err(TokenError::Credential {
                what: "a client secret"
            })
        ));
        assert!(!format!("{grant:?}").contains("synthetic-pw"));
        grant.client_auth = ClientAuth::TlsClientAuth;
        assert!(matches!(
            grant.validate(),
            Err(TokenError::Credential {
                what: "client certificate"
            })
        ));
    }

    #[cfg(feature = "fetch")]
    #[test]
    fn the_assertion_audience_and_type_follow_the_security_profile() {
        use super::{CLIENT_AUTHENTICATION_TYP, SecurityProfile, endpoint, fapi2};
        use url::Url;

        let key = super::assertion::AssertionKey::from_pem(
            &aws_lc_rs::signature::EcdsaKeyPair::generate(
                &aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            )
            .and_then(|pair| pair.to_pkcs8v1())
            .map(|der| pem(der.as_ref()))
            .expect("a generated key"),
            None,
            None,
        )
        .expect("a P-384 key");
        let token: Url = "https://as.example.org/token".parse().expect("a URL");
        let claims = |assertion: &str| -> (Option<String>, serde_json::Value) {
            let header = crate::jws::compact::decode(assertion)
                .expect("a header")
                .header()
                .clone();
            let payload = assertion.split('.').nth(1).expect("a payload");
            let bytes =
                base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
                    .expect("base64url");
            let claims: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
            (header.typ, claims["aud"].clone())
        };
        let mut grant = ClientCredentials::with_private_key_jwt(
            Endpoint::Issuer(String::from("https://as.example.org")),
            String::from("client"),
            key,
        );
        let ring = grant.assertion_keys.clone().expect("a key ring");
        // NOTE: SMART App Launch 2.2.0, Client Authentication: Asymmetric, Request.
        let smart = endpoint::client_assertion(ring.current(), &grant, &token).expect("signs");
        assert_eq!(
            (Some(String::from("JWT")), serde_json::json!(token.as_str())),
            claims(&smart)
        );
        // NOTE: FAPI 2.0 §5.3.3.1 and RFC 10070 §4, the issuer as a string.
        grant.profile = SecurityProfile::Fapi2(fapi2::Fapi2::new());
        let fapi = endpoint::client_assertion(ring.current(), &grant, &token).expect("signs");
        assert_eq!(
            (
                Some(String::from(CLIENT_AUTHENTICATION_TYP)),
                serde_json::json!("https://as.example.org")
            ),
            claims(&fapi)
        );
        grant.endpoint = Endpoint::Token(token.clone());
        assert!(matches!(
            endpoint::client_assertion(ring.current(), &grant, &token),
            Err(TokenError::Credential {
                what: "issuer for the FAPI 2.0 assertion audience"
            })
        ));
    }

    #[cfg(feature = "fetch")]
    fn pem(der: &[u8]) -> Vec<u8> {
        use base64::Engine as _;
        let body = base64::engine::general_purpose::STANDARD.encode(der);
        let mut out = String::from("-----BEGIN PRIVATE KEY-----\n");
        for line in body.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
            out.push('\n');
        }
        out.push_str("-----END PRIVATE KEY-----\n");
        out.into_bytes()
    }
}
