// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The client of one outbound integration, built from its
//! [`EndpointSection`]: the HTTP engine with the table's TLS, timeouts and
//! no redirects, the authorization its `credentials` name, and its `retry`.
//!
//! [`OutboundClient::build`] builds the client from the table alone, and
//! [`OutboundClient::builder`] starts an [`OutboundBuilder`] that also takes
//! the grant's TLS from the connection, a clock for the token source, or an
//! [`Authorizer`] of the product's own in place of the table's credential.
//!
//! A product hands [`OutboundClient::http`] and
//! [`OutboundClient::authorization`] to a protocol client of its own, or
//! sends through [`OutboundClient::send`], which applies both and the retry
//! table. A call is tried again when the integration could not be reached,
//! the try timed out, or it answered a `5xx`; any other answer is the
//! caller's. No specification governs the seam or the retry rule: our own
//! design.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use http::HeaderMap;
use http::Method;
use http::StatusCode;
use url::Url;

use crate::basic::Credential;
use crate::client::CallError;
use crate::client::ClientCredentials;
use crate::client::PresentedTls;
use crate::client::TokenError;
use crate::client::binding::TokenBinding;
use crate::client::cache::Clock;
use crate::client::cache::SystemClock;
use crate::client::cache::TokenSource;
use crate::client::dpop;
use crate::config::ConfigError;
use crate::config::TlsBuilder;
use crate::config::credentials::Outbound;
use crate::config::endpoint::EndpointSection;
use crate::config::endpoint::RetrySection;

/// What every request to the integration carries.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Authorization {
    /// HTTP Basic (RFC 7617).
    Basic(Credential),
    /// A client credentials token, renewed once when the integration answers
    /// `401` (RFC 6750 §3.1).
    Bearer(TokenSource),
    /// The product's own authorization, asked for the headers of every try
    /// and told of every answer.
    Product(Arc<dyn Authorizer>),
}

/// The headers an [`Authorizer`] gives one try, or why it gives none.
pub type Authorized<'a> =
    Pin<Box<dyn Future<Output = Result<HeaderMap, AuthorizerError>> + Send + 'a>>;

/// An authorization the product supplies, for a grant the endpoint table
/// cannot name: a token of the product's own with a `DPoP` proof per request,
/// for one.
///
/// [`OutboundClient::send`] asks [`Authorizer::headers`] for every try, a
/// retry included, and tells [`Authorizer::answered`] of every answer. When
/// the integration answers `401`, the request is sent once more with new
/// headers, so the product drops a refused token in `answered` and the
/// renewal obtains another; a second `401` reaches the caller as it is
/// (RFC 6750 §3.1). No specification governs the seam: our own design.
///
/// The `Debug` rendering of an implementation never carries a credential.
pub trait Authorizer: Send + Sync + fmt::Debug {
    /// Returns the headers of a `method` request to `url`, the URL with its
    /// query, so a proof can bind to both (RFC 9449 §4.2).
    ///
    /// The headers replace any of the same name the request was prepared
    /// with. A value carrying a credential is marked sensitive.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthorizerError`] carrying the product's own error when
    /// no credential can be given; the request is then not sent.
    fn headers<'a>(&'a self, method: &'a Method, url: &'a Url) -> Authorized<'a>;

    /// Is told of the answer `status` with `headers` to a request to `url`,
    /// a `DPoP-Nonce` to keep or a `401` that refuses the credential.
    ///
    /// The default keeps nothing.
    fn answered(&self, _url: &Url, _status: StatusCode, _headers: &HeaderMap) {}
}

/// Why an [`Authorizer`] gave no headers, carrying the product's own error as
/// its source.
///
/// The product's error never carries a credential.
#[derive(Debug, thiserror::Error)]
#[error("the product's authorization gave no credential for the request")]
pub struct AuthorizerError(#[source] Box<dyn std::error::Error + Send + Sync + 'static>);

impl AuthorizerError {
    /// Returns the refusal `source` causes.
    pub fn new(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self(Box::new(source))
    }
}

/// Why an outbound client could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OutboundError {
    /// The endpoint table, its TLS or its credential is refused.
    #[error("the endpoint table {key} is refused")]
    Config {
        /// The endpoint table's dotted key.
        key: &'static str,
        /// The rule the table breaks.
        #[source]
        source: Box<ConfigError>,
    },
    /// The HTTP engine could not be built.
    #[error("the HTTP client of {key} could not be built")]
    Build {
        /// The endpoint table's dotted key.
        key: &'static str,
        /// What the engine reported.
        #[source]
        source: reqwest::Error,
    },
    /// The token source of the client credentials grant could not be built.
    #[error("the token source of {key} could not be built")]
    Token {
        /// The endpoint table's dotted key.
        key: &'static str,
        /// What the source reported.
        #[source]
        source: Box<TokenError>,
    },
    /// The grant binds its tokens to a client certificate the connection to
    /// the integration does not present, so the integration would refuse
    /// every token it is issued (RFC 8705 §3).
    #[error("the grant of {key} binds its tokens to a certificate the connection does not present")]
    CertificateBinding {
        /// The endpoint table's dotted key.
        key: &'static str,
    },
    /// The product supplies an [`Authorizer`] and the endpoint table names a
    /// credential too, which would never be sent.
    #[error("the endpoint table {key} names a credential beside the product's authorization")]
    CredentialBesideAuthorizer {
        /// The endpoint table's dotted key.
        key: &'static str,
    },
}

/// Where the grant of an outbound client takes its TLS from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantTls {
    /// The grant's own `oauth.tls` table only.
    Own,
    /// The grant's own `oauth.tls` table when it names material, the
    /// connection's TLS otherwise.
    Shared,
}

/// Why a call through [`OutboundClient::send`] got no answer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SendError {
    /// The integration could not be reached, or the last try timed out.
    #[error("the integration could not be reached")]
    Transport(#[source] reqwest::Error),
    /// No token could be obtained, or a refused token could not be renewed.
    #[error("no token for the integration could be obtained")]
    Token(#[source] CallError<reqwest::Error>),
    /// The product's [`Authorizer`] gave no headers, so the try was not sent.
    #[error("the product's authorization refused the request")]
    Authorization(#[source] AuthorizerError),
}

/// The builder of an [`OutboundClient`], started by
/// [`OutboundClient::builder`].
#[must_use = "the builder builds nothing until `build` is called"]
pub struct OutboundBuilder<'a> {
    endpoint: &'a EndpointSection,
    key: &'static str,
    tls: &'a dyn TlsBuilder,
    grant_tls: GrantTls,
    clock: Arc<dyn Clock>,
    authorizer: Option<Arc<dyn Authorizer>>,
}

impl OutboundBuilder<'_> {
    /// Has a client credentials grant whose `oauth.tls` names no material
    /// present the TLS configuration built from the table's `tls`: the
    /// connection's trust roots and the client certificate it presents to
    /// the integration.
    ///
    /// A mutual-TLS `client_auth` then authenticates at the token endpoint
    /// with the certificate the connection presents (RFC 8705 §2), and a
    /// `certificate_bound` grant binds its tokens to it, the certificate
    /// the integration checks every token's `cnf` against (RFC 8705 §3). An
    /// `oauth.tls` that names material is built as it is without this.
    pub const fn sharing_tls(mut self) -> Self {
        self.grant_tls = GrantTls::Shared;
        self
    }

    /// Has the client credentials token source read its tokens' expiry and
    /// its renewal margin against `clock` in place of the system clock, as
    /// [`TokenSource::with_clock`] does.
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Has every request carry the headers `authorizer` gives, as
    /// [`Authorization::Product`], in place of a credential of the table's.
    pub fn authorizer(mut self, authorizer: Arc<dyn Authorizer>) -> Self {
        self.authorizer = Some(authorizer);
        self
    }

    /// Returns the client.
    ///
    /// # Errors
    ///
    /// [`OutboundError::Config`] when [`EndpointSection::validate`] or
    /// [`crate::config::credentials::CredentialsSection::resolve_with_tls`]
    /// (or, sharing the connection's TLS,
    /// [`crate::config::credentials::CredentialsSection::resolve_sharing_tls`])
    /// refuses the table or `tls` refuses its TLS,
    /// [`OutboundError::Build`] when the engine cannot be built,
    /// [`OutboundError::Token`] when the token source cannot be built,
    /// [`OutboundError::CertificateBinding`] when, sharing the connection's
    /// TLS, a `certificate_bound` grant presents another certificate than
    /// the connection or the connection presents none, and
    /// [`OutboundError::CredentialBesideAuthorizer`] when the table names a
    /// credential and the product supplies an [`Authorizer`].
    pub fn build(self) -> Result<OutboundClient, OutboundError> {
        let Self {
            endpoint,
            key,
            tls,
            grant_tls,
            clock,
            authorizer,
        } = self;
        let refused = |source: ConfigError| OutboundError::Config {
            key,
            source: Box::new(source),
        };
        let url = endpoint.validate().map_err(refused)?;
        let presented = crate::config::build_tls(
            tls,
            &format!("{key}.tls"),
            &endpoint.tls,
            std::slice::from_ref(&url),
        )
        .map_err(refused)?;
        let mut builder = reqwest::Client::builder()
            .timeout(endpoint.timeout.get())
            .redirect(reqwest::redirect::Policy::none())
            .tls_backend_preconfigured(rustls::ClientConfig::clone(presented.config()));
        if let Some(connect) = endpoint.connect_timeout {
            builder = builder.connect_timeout(connect.get());
        }
        let http = builder
            .build()
            .map_err(|source| OutboundError::Build { key, source })?;
        let credential = match grant_tls {
            GrantTls::Own => endpoint.credentials.resolve_with_tls(tls),
            GrantTls::Shared => endpoint.credentials.resolve_sharing_tls(tls, &presented),
        };
        let authorization = match (credential.map_err(refused)?, authorizer) {
            (None, None) => None,
            (None, Some(authorizer)) => Some(Authorization::Product(authorizer)),
            (Some(_), Some(_)) => return Err(OutboundError::CredentialBesideAuthorizer { key }),
            (Some(Outbound::Basic(credential)), None) => Some(Authorization::Basic(credential)),
            (Some(Outbound::Oauth(grant)), None) => {
                if grant_tls == GrantTls::Shared && !binding_agrees(&grant, &presented) {
                    return Err(OutboundError::CertificateBinding { key });
                }
                Some(Authorization::Bearer(
                    TokenSource::with_clock(*grant, clock).map_err(|source| {
                        OutboundError::Token {
                            key,
                            source: Box::new(source),
                        }
                    })?,
                ))
            }
        };
        Ok(OutboundClient {
            url,
            http,
            presented,
            authorization,
            retry: endpoint.retry,
        })
    }
}

impl fmt::Debug for OutboundBuilder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundBuilder")
            .field("key", &self.key)
            .field("grant_tls", &self.grant_tls)
            .field("clock", &self.clock)
            .field("authorizer", &self.authorizer)
            .finish_non_exhaustive()
    }
}

/// The client of one outbound integration.
#[derive(Debug, Clone)]
pub struct OutboundClient {
    url: Url,
    http: reqwest::Client,
    presented: PresentedTls,
    authorization: Option<Authorization>,
    retry: RetrySection,
}

impl OutboundClient {
    /// Returns the client `endpoint` describes, its TLS built by `tls`.
    ///
    /// `key` is the table's dotted key (`terminology.endpoint`), which a
    /// refusal names, and `tls` builds the table's TLS at `<key>.tls`
    /// (`terminology.endpoint.tls`), the key its refusals name. The engine
    /// bounds a whole call by `timeout` and opening the connection by
    /// `connect_timeout`, follows no redirect, and presents
    /// the TLS configuration `tls` builds from the table's `tls`. The
    /// `credentials` table resolves to [`Authorization::Basic`] or, under a
    /// client credentials grant, [`Authorization::Bearer`] over a token
    /// source whose own TLS `tls` builds too and whose clock is the system's.
    /// It is [`OutboundClient::builder`] with nothing more set.
    ///
    /// # Errors
    ///
    /// As [`OutboundBuilder::build`].
    pub fn build(
        endpoint: &EndpointSection,
        key: &'static str,
        tls: &dyn TlsBuilder,
    ) -> Result<Self, OutboundError> {
        Self::builder(endpoint, key, tls).build()
    }

    /// Returns the client `endpoint` describes, as
    /// [`OutboundClient::build`] does, except that the grant shares the
    /// connection's TLS as [`OutboundBuilder::sharing_tls`] says.
    ///
    /// # Errors
    ///
    /// As [`OutboundBuilder::build`] after [`OutboundBuilder::sharing_tls`].
    pub fn build_sharing_tls(
        endpoint: &EndpointSection,
        key: &'static str,
        tls: &dyn TlsBuilder,
    ) -> Result<Self, OutboundError> {
        Self::builder(endpoint, key, tls).sharing_tls().build()
    }

    /// Starts the builder of the client `endpoint` describes, at the dotted
    /// `key`, its TLS built by `tls`.
    pub fn builder<'a>(
        endpoint: &'a EndpointSection,
        key: &'static str,
        tls: &'a dyn TlsBuilder,
    ) -> OutboundBuilder<'a> {
        OutboundBuilder {
            endpoint,
            key,
            tls,
            grant_tls: GrantTls::Own,
            clock: Arc::new(SystemClock),
            authorizer: None,
        }
    }

    /// Returns the integration's URL, as the table names it.
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }

    /// Returns the HTTP engine. Its connections to the integration's URL
    /// stay cleared for revocation while this client lives, so a caller
    /// that sends through it keeps the client.
    #[must_use]
    pub const fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// Returns what every request carries, when the table names a
    /// credential.
    #[must_use]
    pub const fn authorization(&self) -> Option<&Authorization> {
        self.authorization.as_ref()
    }

    /// Returns the retry table.
    #[must_use]
    pub const fn retry(&self) -> &RetrySection {
        &self.retry
    }

    /// Sends a `method` request to `url`, shaped by `prepare`, with the
    /// authorization, and tries it again as the retry table allows.
    ///
    /// A try that could not reach the integration, timed out, or was
    /// answered `5xx` is tried again after the next of
    /// [`RetrySection::delays`], so `prepare` builds a request that is safe
    /// to repeat. The last answer is returned whatever its status: a `5xx`
    /// after the last try included. A token the integration refuses is
    /// renewed once, as [`TokenSource::send`] does, with a `DPoP` proof for
    /// a bound token. A product's [`Authorizer`] gives the headers of every
    /// try and is told of every answer, and a `401` is sent once more with
    /// new headers.
    ///
    /// # Errors
    ///
    /// [`SendError::Transport`] when the last try got no answer,
    /// [`SendError::Token`] when no token could be obtained or a refused one
    /// renewed, and [`SendError::Authorization`] when the product's
    /// [`Authorizer`] gave no headers.
    pub async fn send<F>(
        &self,
        method: &Method,
        url: &Url,
        prepare: F,
    ) -> Result<reqwest::Response, SendError>
    where
        F: Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    {
        let mut delays = self.retry.delays();
        loop {
            let outcome = self.try_once(method, url, &prepare).await;
            let again = match &outcome {
                Ok(response) => response.status().is_server_error(),
                Err(SendError::Transport(_)) => true,
                Err(SendError::Token(_) | SendError::Authorization(_)) => false,
            };
            match delays.next() {
                Some(delay) if again => {
                    tracing::warn!(
                        delay_ms = delay.as_millis(),
                        "retrying a call to an outbound integration"
                    );
                    tokio::time::sleep(delay).await;
                }
                _ => return outcome,
            }
        }
    }

    /// Sends one try.
    async fn try_once<F>(
        &self,
        method: &Method,
        url: &Url,
        prepare: &F,
    ) -> Result<reqwest::Response, SendError>
    where
        F: Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    {
        self.presented.clear(url).await;
        let request = || prepare(self.http.request(method.clone(), url.clone()));
        match &self.authorization {
            None => request().send().await.map_err(SendError::Transport),
            Some(Authorization::Basic(credential)) => request()
                .header(http::header::AUTHORIZATION, credential.header_value())
                .send()
                .await
                .map_err(SendError::Transport),
            Some(Authorization::Bearer(source)) => source
                .send(method, url, |attempt| {
                    let mut call =
                        request().header(http::header::AUTHORIZATION, attempt.authorization());
                    if let Some(proof) = attempt.proof() {
                        call = call.header(dpop::HEADER, proof);
                    }
                    call.send()
                })
                .await
                .map_err(|error| match error {
                    CallError::Call { source } => SendError::Transport(source),
                    other => SendError::Token(other),
                }),
            Some(Authorization::Product(authorizer)) => {
                let first = Self::authorized(authorizer.as_ref(), method, url, &request).await?;
                if first.status() != StatusCode::UNAUTHORIZED {
                    return Ok(first);
                }
                tracing::debug!(
                    "the integration refused the product's credential; renewing it once"
                );
                Self::authorized(authorizer.as_ref(), method, url, &request).await
            }
        }
    }

    /// Sends the request `request` builds with the headers `authorizer`
    /// gives, and tells it of the answer.
    async fn authorized(
        authorizer: &dyn Authorizer,
        method: &Method,
        url: &Url,
        request: &impl Fn() -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, SendError> {
        let headers = authorizer
            .headers(method, url)
            .await
            .map_err(SendError::Authorization)?;
        let answer = request()
            .headers(headers)
            .send()
            .await
            .map_err(SendError::Transport)?;
        authorizer.answered(url, answer.status(), answer.headers());
        Ok(answer)
    }
}

/// Returns whether `grant` binds its tokens to nothing, to a `DPoP` key, or
/// to the certificate `connection` presents.
fn binding_agrees(grant: &ClientCredentials, connection: &PresentedTls) -> bool {
    // NOTE: RFC 8705 §3, resource requests "MUST be made over a mutually
    // authenticated TLS connection using the same certificate" as the token endpoint.
    match grant.token_binding {
        Some(TokenBinding::Certificate) => {
            let granted = grant
                .tls
                .presented
                .as_ref()
                .and_then(PresentedTls::certificate);
            granted.is_some() && granted == connection.certificate()
        }
        _ => true,
    }
}
