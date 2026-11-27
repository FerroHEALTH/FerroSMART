// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The authorization server metadata (RFC 8414 §2) and how it is found.
//!
//! The RFC 8414 §3 location is read first; a `404` there moves on to the
//! `OpenID` Connect Discovery 1.0 §4 location, and any other answer is final.
//! The document must name the configured issuer itself, compared as exact
//! text (RFC 8414 §3.3 and §4), and an object in it that repeats a member
//! name refuses it (RFC 8259 §4). A product that sends only to its issuer's
//! origin opts into [`ServerMetadata::check_origin`], and one that compares
//! the issuer only in its canonical form reads it with [`canonical_issuer`].
//! The resource server reads it for `jwks_uri` and the endpoints its SMART
//! discovery document republishes; the token client reads it for
//! `token_endpoint`.

use std::collections::BTreeSet;
use std::fmt;
#[cfg(feature = "fetch")]
use std::time::Duration;

use http::StatusCode;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::de::MapAccess;
use serde::de::SeqAccess;
use serde::de::Visitor;
use url::Url;

use crate::json::JsonError;

/// The RFC 8414 §3 well-known suffix.
pub const OAUTH_METADATA: &str = "/.well-known/oauth-authorization-server";

/// The `OpenID` Connect Discovery 1.0 §4 well-known suffix.
pub const OPENID_CONFIGURATION: &str = "/.well-known/openid-configuration";

/// The most bytes a metadata or key set document may carry.
///
/// No specification governs the ceiling: our own design, so a misdirected
/// issuer URL cannot have the process read a file of any size.
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// The members of an authorization server metadata document a resource
/// server or a token client reads or republishes (RFC 8414 §2).
///
/// Every member but `issuer` is optional on the wire, so each is an
/// `Option`; a member the document does not carry is `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerMetadata {
    /// The issuer identifier the document describes.
    pub issuer: String,
    /// The key set URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// The authorization endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,
    /// The token endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    /// The client authentication methods of the token endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// The grant types the server supports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<String>>,
    /// The dynamic client registration endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    /// The scopes the server supports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    /// The response types the server supports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_types_supported: Option<Vec<String>>,
    /// The token introspection endpoint (RFC 7662).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
    /// The token revocation endpoint (RFC 7009).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    /// The end-session endpoint a relying party signs the operator out at
    /// (OpenID Connect RP-Initiated Logout 1.0 §2.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_session_endpoint: Option<String>,
    /// The UserInfo Endpoint (OpenID Connect Discovery 1.0 §3, OpenID
    /// Connect Core 1.0 §5.3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,
    /// The PKCE challenge methods the server supports (RFC 7636).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
    /// The endpoints a client doing mutual TLS uses in place of the
    /// conventional ones (RFC 8705 §5).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtls_endpoint_aliases: Option<MtlsEndpointAliases>,
    /// The algorithms the token endpoint takes a client assertion in (RFC
    /// 8414 §2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// The algorithms the server takes a `DPoP` proof in (RFC 9449 §5.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
    /// The authorization details types the server supports (RFC 9396 §10).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details_types_supported: Option<Vec<String>>,
    /// Whether the server issues certificate-bound access tokens (RFC 8705
    /// §3.3); absent means it does not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_certificate_bound_access_tokens: Option<bool>,
}

/// The `mtls_endpoint_aliases` member (RFC 8705 §5): the endpoints a
/// client doing mutual TLS uses in preference to the conventional ones.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub struct MtlsEndpointAliases {
    /// The token endpoint alias.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
}

impl ServerMetadata {
    /// Returns the grant types the server supports, the RFC 8414 §2 default
    /// `authorization_code` and `implicit` when the document names none.
    #[must_use]
    pub fn grant_types(&self) -> Vec<String> {
        self.grant_types_supported
            .clone()
            .unwrap_or_else(|| vec![String::from("authorization_code"), String::from("implicit")])
    }

    /// Returns the client authentication methods of the token endpoint, the
    /// RFC 8414 §2 default `client_secret_basic` when the document names
    /// none.
    #[must_use]
    pub fn token_endpoint_auth_methods(&self) -> Vec<String> {
        self.token_endpoint_auth_methods_supported
            .clone()
            .unwrap_or_else(|| vec![String::from("client_secret_basic")])
    }

    /// Returns each endpoint member the document carries, by member name:
    /// `jwks_uri`, the authorization, token, registration, introspection and
    /// revocation endpoints, and the `mtls_endpoint_aliases` token endpoint.
    #[must_use]
    pub fn endpoints(&self) -> Vec<(&'static str, &str)> {
        let alias = self
            .mtls_endpoint_aliases
            .as_ref()
            .and_then(|aliases| aliases.token_endpoint.as_deref());
        [
            ("jwks_uri", self.jwks_uri.as_deref()),
            (
                "authorization_endpoint",
                self.authorization_endpoint.as_deref(),
            ),
            ("token_endpoint", self.token_endpoint.as_deref()),
            (
                "registration_endpoint",
                self.registration_endpoint.as_deref(),
            ),
            (
                "introspection_endpoint",
                self.introspection_endpoint.as_deref(),
            ),
            ("revocation_endpoint", self.revocation_endpoint.as_deref()),
            ("mtls_endpoint_aliases.token_endpoint", alias),
        ]
        .into_iter()
        .filter_map(|(member, location)| location.map(|location| (member, location)))
        .collect()
    }

    /// Checks that every endpoint the document names sits on the origin of
    /// `issuer`: the same scheme, host and port (RFC 6454 §4, §5).
    ///
    /// The check is a product's opt-in policy, for a product that sends a
    /// credential only to its issuer's own origin: RFC 8414 §2 places no
    /// endpoint, and an authorization server may publish its key set or a
    /// mutual-TLS alias on another host (no specification governs this: our
    /// own design). The member names are those of [`Self::endpoints`].
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::EndpointUrl`] for an endpoint that is no
    /// URL and [`DiscoveryError::OtherOrigin`] for one on another origin,
    /// each naming the first member that breaks the rule.
    pub fn check_origin(&self, issuer: &Url) -> Result<(), DiscoveryError> {
        for (member, location) in self.endpoints() {
            same_origin(issuer, member, location)?;
        }
        Ok(())
    }
}

/// A failure to reach or read the authorization server's metadata.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// The HTTP engine could not be built.
    #[cfg(feature = "fetch")]
    #[error("the HTTP engine of the authorization server client could not be built")]
    Build {
        /// What `reqwest` reported.
        #[source]
        source: reqwest::Error,
    },
    /// The trust roots or the client certificate are not PEM `reqwest`
    /// reads.
    #[cfg(feature = "fetch")]
    #[error("{what} could not be read as PEM")]
    Tls {
        /// What was refused: the trust roots or the client certificate.
        what: &'static str,
        /// What `reqwest` reported.
        #[source]
        source: reqwest::Error,
    },
    /// A PEM file of trust roots carries no certificate.
    #[cfg(feature = "fetch")]
    #[error("the trust roots carry no PEM certificate")]
    NoRootCertificate,
    /// The TLS material names PEM trust roots or a PEM identity beside a
    /// TLS configuration the product built, which carries its own.
    #[cfg(feature = "fetch")]
    #[error("the TLS material names PEM roots or a PEM identity beside a built TLS configuration")]
    PresentedTlsTwice,
    /// The configured issuer is not a URL.
    #[error("the configured issuer is not a URL")]
    IssuerUrl {
        /// What the URL parser reported.
        #[source]
        source: url::ParseError,
    },
    /// The issuer, or a location the metadata names, is not an `https` URL
    /// without a query or a fragment (RFC 8414 §2, `OpenID` Connect
    /// Discovery 1.0 §3), on a host that is no loopback.
    #[error("{what} is not an https URL without a query or fragment: {url}")]
    Insecure {
        /// What the URL is: the issuer or the metadata member.
        what: &'static str,
        /// The URL.
        url: String,
    },
    /// A request to the authorization server never completed, its timeout
    /// included.
    #[cfg(feature = "fetch")]
    #[error("the request to {url} could not be completed")]
    Transport {
        /// The URL that was called.
        url: Url,
        /// What `reqwest` reported.
        #[source]
        source: reqwest::Error,
    },
    /// The answer of the authorization server is larger than
    /// [`MAX_DOCUMENT_BYTES`].
    #[error("the answer of {url} is larger than {MAX_DOCUMENT_BYTES} bytes")]
    TooLarge {
        /// The URL that was called.
        url: Url,
    },
    /// No metadata document answered at either discovery location.
    #[error("the authorization server metadata at {url} answered {status}")]
    Status {
        /// The last location tried.
        url: Url,
        /// The status it answered.
        status: StatusCode,
        /// Always empty: RFC 8414 §3.2 defines no error body, and nothing of
        /// the answer is kept, so no rendering of the error carries it.
        body: String,
    },
    /// The metadata is not the JSON object RFC 8414 §3.2 describes.
    #[error("the authorization server metadata at {url} is not a metadata document")]
    Metadata {
        /// The location that answered it.
        url: Url,
        /// What the JSON reader reported.
        #[source]
        source: JsonError,
    },
    /// An object of the metadata repeats a member name, whose meaning
    /// RFC 8259 §4 leaves to each parser.
    #[error("the authorization server metadata at {url} repeats a member name")]
    RepeatedName {
        /// The location that answered it.
        url: Url,
        /// What the JSON reader reported, with the position.
        #[source]
        source: JsonError,
    },
    /// The metadata names another issuer, which RFC 8414 §3.3 requires a
    /// client to refuse.
    #[error("the authorization server metadata names issuer {found:?}, not {expected:?}")]
    IssuerMismatch {
        /// The configured issuer.
        expected: String,
        /// The issuer the metadata named.
        found: String,
    },
    /// The issuer is not written in the canonical form the URL parser
    /// gives it, or carries userinfo.
    #[error("the issuer {issuer:?} is not in its canonical form {canonical:?}")]
    NonCanonicalIssuer {
        /// The issuer as written.
        issuer: String,
        /// The form the URL parser writes it in.
        canonical: String,
    },
    /// An endpoint of the metadata is not a URL.
    #[error("the metadata member {member} is not a URL")]
    EndpointUrl {
        /// The member name.
        member: &'static str,
        /// What the URL parser reported.
        #[source]
        source: url::ParseError,
    },
    /// An endpoint of the metadata is not on the issuer's origin.
    #[error("the metadata member {member} is not on the issuer's origin: {url}")]
    OtherOrigin {
        /// The member name.
        member: &'static str,
        /// The endpoint.
        url: String,
    },
}

/// Checks that `found`, the `issuer` a metadata document names, is
/// `expected`, the issuer identifier its location was built from.
///
/// RFC 8414 §3.3 and `OpenID` Connect Discovery 1.0 §4.3 require the two to
/// be identical, and RFC 8414 §4 compares them code point by code point
/// after the JSON escaping is removed, with no normalization: a different
/// case, a default port written out or a terminating `/` is another issuer.
///
/// # Errors
///
/// Returns [`DiscoveryError::IssuerMismatch`] when the two texts differ.
pub fn check_issuer(expected: &str, found: &str) -> Result<(), DiscoveryError> {
    if expected == found {
        return Ok(());
    }
    Err(DiscoveryError::IssuerMismatch {
        expected: expected.to_owned(),
        found: found.to_owned(),
    })
}

/// Returns `issuer` as [`issuer_url`] does, refusing a text that is not the
/// canonical form the URL parser writes, or that carries userinfo.
///
/// An issuer is compared as text (RFC 8414 §3.3) and fetched as a URL, so a
/// product that holds the text to one meaning for both takes only a text
/// the parser leaves unchanged: a lower-case host, no default port, and the
/// parser's serialization or that serialization less the `/` it gives an
/// empty path (no specification governs this: our own design).
///
/// # Errors
///
/// Returns the errors of [`issuer_url`], and
/// [`DiscoveryError::NonCanonicalIssuer`] for a text the parser writes
/// otherwise or one with userinfo.
pub fn canonical_issuer(issuer: &str) -> Result<Url, DiscoveryError> {
    let url = issuer_url(issuer)?;
    let canonical = issuer == url.as_str()
        || (url.path() == "/" && url.as_str().strip_suffix('/') == Some(issuer));
    if !canonical || !url.username().is_empty() || url.password().is_some() {
        return Err(DiscoveryError::NonCanonicalIssuer {
            issuer: issuer.to_owned(),
            canonical: url.to_string(),
        });
    }
    Ok(url)
}

/// Returns `location`, the endpoint the metadata member `member` names, when
/// it sits on the origin of `issuer`: the same scheme, host and port
/// (RFC 6454 §4, §5).
///
/// # Errors
///
/// Returns [`DiscoveryError::EndpointUrl`] for a location that is no URL and
/// [`DiscoveryError::OtherOrigin`] for one on another origin.
pub fn same_origin(
    issuer: &Url,
    member: &'static str,
    location: &str,
) -> Result<Url, DiscoveryError> {
    let url =
        Url::parse(location).map_err(|source| DiscoveryError::EndpointUrl { member, source })?;
    if url.origin() != issuer.origin() {
        return Err(DiscoveryError::OtherOrigin {
            member,
            url: url.to_string(),
        });
    }
    Ok(url)
}

/// Proves that no object of the JSON text `body` repeats a member name, at
/// any depth.
///
/// RFC 8259 §4 has the names within an object unique only as a SHOULD and
/// leaves the meaning of a repeated one to each parser, so two readers of
/// one document could take different values from it: an `issuer` or a
/// `jwks_uri` one checks and another one uses. A document that repeats a
/// name is refused instead (no specification governs the refusal: our own
/// design).
///
/// # Errors
///
/// Returns a [`JsonError`] for a text that is no JSON, and a data error
/// ([`serde_json::error::Category::Data`]) at the position of the first
/// repeated name, neither of which renders any part of the text.
pub fn repeats_no_name(body: &[u8]) -> Result<(), JsonError> {
    serde_json::from_slice::<Unique>(body)
        .map(|Unique| ())
        .map_err(JsonError::from)
}

/// A JSON value read only to prove that no object in it repeats a name.
struct Unique;

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueVisitor)
    }
}

/// The visitor of [`Unique`].
struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Unique;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value whose objects repeat no name")
    }

    fn visit_bool<E: serde::de::Error>(self, _value: bool) -> Result<Unique, E> {
        Ok(Unique)
    }

    fn visit_i64<E: serde::de::Error>(self, _value: i64) -> Result<Unique, E> {
        Ok(Unique)
    }

    fn visit_u64<E: serde::de::Error>(self, _value: u64) -> Result<Unique, E> {
        Ok(Unique)
    }

    fn visit_f64<E: serde::de::Error>(self, _value: f64) -> Result<Unique, E> {
        Ok(Unique)
    }

    fn visit_str<E: serde::de::Error>(self, _value: &str) -> Result<Unique, E> {
        Ok(Unique)
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Unique, E> {
        Ok(Unique)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Unique, A::Error> {
        while seq.next_element::<Unique>()?.is_some() {}
        Ok(Unique)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
        let mut names = BTreeSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if !names.insert(name) {
                return Err(serde::de::Error::custom("an object repeats a member name"));
            }
            map.next_value::<Unique>()?;
        }
        Ok(Unique)
    }
}

/// Returns the metadata document `body`, which `url` answered, refusing one
/// that repeats a member name (RFC 8259 §4) or is no metadata document
/// (RFC 8414 §3.2).
///
/// # Errors
///
/// Returns [`DiscoveryError::RepeatedName`] for a document that repeats a
/// name and [`DiscoveryError::Metadata`] for a body that is no metadata
/// document.
pub fn parse_metadata(url: &Url, body: &str) -> Result<ServerMetadata, DiscoveryError> {
    if let Err(source) = repeats_no_name(body.as_bytes()) {
        // NOTE: RFC 8259 §4, only the repeated-name refusal reads as a data
        // error, so any other failure is a body that is no JSON at all.
        if source.category() == serde_json::error::Category::Data {
            return Err(DiscoveryError::RepeatedName {
                url: url.clone(),
                source,
            });
        }
        return Err(DiscoveryError::Metadata {
            url: url.clone(),
            source,
        });
    }
    serde_json::from_str(body).map_err(|source| DiscoveryError::Metadata {
        url: url.clone(),
        source: source.into(),
    })
}

/// Returns `issuer` as the URL RFC 8414 §2 describes: `https`, no query, no
/// fragment.
///
/// A loopback host (`localhost`, `127.0.0.1`, `::1`) may be plain `http`,
/// because a test issuer is one and its transport cannot be observed (no
/// specification governs the exception: our own design).
///
/// # Errors
///
/// Returns [`DiscoveryError::IssuerUrl`] for text that is no URL and
/// [`DiscoveryError::Insecure`] for a URL outside the rule.
pub fn issuer_url(issuer: &str) -> Result<Url, DiscoveryError> {
    let url: Url = issuer
        .parse()
        .map_err(|source| DiscoveryError::IssuerUrl { source })?;
    secure(&url, "the issuer")?;
    Ok(url)
}

/// Checks that `url` is `https` without a query or a fragment, or plain
/// `http` on a loopback host.
///
/// # Errors
///
/// Returns [`DiscoveryError::Insecure`] naming `what` otherwise.
pub fn secure(url: &Url, what: &'static str) -> Result<(), DiscoveryError> {
    let loopback = matches!(
        url.host(),
        Some(
            url::Host::Domain("localhost")
                | url::Host::Ipv4(std::net::Ipv4Addr::LOCALHOST)
                | url::Host::Ipv6(std::net::Ipv6Addr::LOCALHOST)
        )
    );
    let scheme_ok = url.scheme() == "https" || (loopback && url.scheme() == "http");
    if !scheme_ok || url.query().is_some() || url.fragment().is_some() {
        return Err(DiscoveryError::Insecure {
            what,
            url: url.to_string(),
        });
    }
    Ok(())
}

/// Returns the two metadata locations of `issuer`, the RFC 8414 one first.
///
/// RFC 8414 §3.1 inserts the suffix between the host and the path, after
/// removing a terminating `/`; `OpenID` Connect Discovery 1.0 §4 appends it to
/// the issuer, after removing a terminating `/`.
#[must_use]
pub fn locations(issuer: &Url) -> [Url; 2] {
    let path = issuer.path().trim_end_matches('/');
    let mut oauth = issuer.clone();
    oauth.set_path(&format!("{OAUTH_METADATA}{path}"));
    let mut openid = issuer.clone();
    openid.set_path(&format!("{path}{OPENID_CONFIGURATION}"));
    [oauth, openid]
}

/// The HTTP engine the authorization server is called through, behind the
/// `fetch` feature.
///
/// It follows no redirect: a metadata document, a key set or a token request
/// answered with a redirect is refused as the status it is, so a credential
/// never travels to a host the configuration did not name (no specification
/// governs this: our own design).
#[cfg(feature = "fetch")]
#[derive(Debug, Clone)]
pub struct Http {
    /// The engine.
    client: reqwest::Client,
}

#[cfg(feature = "fetch")]
impl Http {
    /// Returns an engine whose calls each take at most `timeout`.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::Build`] when the engine cannot be built.
    pub fn new(timeout: Duration) -> Result<Self, DiscoveryError> {
        Self::with_tls(timeout, &crate::client::Tls::default())
    }

    /// Returns an engine whose calls each take at most `timeout`, trusting
    /// the roots of `tls` beside the built-in ones and presenting its
    /// client certificate (RFC 8705 §2) when the server asks for one.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::Tls`] for roots or a client certificate
    /// that are no PEM `reqwest` reads, [`DiscoveryError::NoRootCertificate`]
    /// for roots that hold no certificate,
    /// [`DiscoveryError::PresentedTlsTwice`] for PEM material beside a
    /// built configuration, and [`DiscoveryError::Build`] when the engine
    /// cannot be built.
    pub fn with_tls(timeout: Duration, tls: &crate::client::Tls) -> Result<Self, DiscoveryError> {
        Self::reaching(timeout, tls, &crate::client::Reach::default())
    }

    /// Returns an engine as [`Self::with_tls`] does, negotiating no TLS
    /// version below the one `reach` names and reaching each host `reach`
    /// overrides at its address. A configuration the product built
    /// (`tls.presented`) keeps its own protocol versions.
    ///
    /// # Errors
    ///
    /// As [`Self::with_tls`].
    pub fn reaching(
        timeout: Duration,
        tls: &crate::client::Tls,
        reach: &crate::client::Reach,
    ) -> Result<Self, DiscoveryError> {
        use ferrohealth_config::tls::TlsVersion;
        let min_version = match reach.min_tls_version().max(tls.min_version) {
            TlsVersion::Tls12 => reqwest::tls::Version::TLS_1_2,
            TlsVersion::Tls13 => reqwest::tls::Version::TLS_1_3,
        };
        let mut builder = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .tls_version_min(min_version);
        for (host, address) in reach.resolve() {
            builder = builder.resolve(host, *address);
        }
        if let Some(presented) = &tls.presented {
            // NOTE: RFC 8705 §2, the connection presents the identity the
            // product's configuration carries, with its roots and versions.
            builder =
                builder.tls_backend_preconfigured(rustls::ClientConfig::clone(presented.config()));
        }
        let client = builder
            .build()
            .map_err(|source| DiscoveryError::Build { source })?;
        Ok(Self { client })
    }

    /// Returns an engine over `client`, a product's own, used as built.
    ///
    /// The crate's engines follow no redirect; this one keeps whatever
    /// redirect policy, timeout and TLS material the product gave it.
    #[must_use]
    pub const fn from_client(client: reqwest::Client) -> Self {
        Self { client }
    }

    /// Returns the underlying engine, for the token request.
    pub(crate) const fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Returns the metadata of `issuer`.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::IssuerUrl`] or [`DiscoveryError::Insecure`]
    /// for an issuer outside the URL rule, [`DiscoveryError::Transport`]
    /// when neither location answers, [`DiscoveryError::Status`] when the
    /// last location tried answers anything but `200`,
    /// [`DiscoveryError::RepeatedName`] for a document that repeats a member
    /// name, [`DiscoveryError::Metadata`] for a body that is no metadata
    /// document, and [`DiscoveryError::IssuerMismatch`] when the document
    /// names another issuer.
    pub async fn discover(&self, issuer: &str) -> Result<ServerMetadata, DiscoveryError> {
        self.discover_document(issuer)
            .await
            .map(|(metadata, _media_type)| metadata)
    }

    /// Returns the metadata of `issuer`, as [`Http::discover`] does, with the
    /// media type it was answered as.
    pub(crate) async fn discover_document(
        &self,
        issuer: &str,
    ) -> Result<(ServerMetadata, Option<String>), DiscoveryError> {
        let parsed = issuer_url(issuer)?;
        let [oauth, openid] = locations(&parsed);
        let (url, status, body, media_type) = match self.read(oauth).await? {
            (url, status, _, _) if status == StatusCode::NOT_FOUND => {
                tracing::debug!(%url, "no RFC 8414 metadata; reading the OpenID Connect location");
                self.read(openid).await?
            }
            answered => answered,
        };
        if status != StatusCode::OK {
            return Err(DiscoveryError::Status {
                url,
                status,
                body: String::new(),
            });
        }
        let metadata = parse_metadata(&url, &body)?;
        check_issuer(issuer, &metadata.issuer)?;
        Ok((metadata, media_type))
    }

    /// Returns the status and body `url` answers a `GET` with, the body
    /// capped at [`MAX_DOCUMENT_BYTES`].
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::Transport`] when the call never completes
    /// and [`DiscoveryError::TooLarge`] when the body passes the cap.
    pub async fn get(&self, url: Url) -> Result<(Url, StatusCode, String), DiscoveryError> {
        let (url, status, body, _media_type) = self.read(url).await?;
        Ok((url, status, body))
    }

    /// Returns what [`Http::get`] returns, with the media type the answer
    /// names.
    async fn read(
        &self,
        url: Url,
    ) -> Result<(Url, StatusCode, String, Option<String>), DiscoveryError> {
        let mut response = self
            .client
            .get(url.clone())
            .header(http::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|source| DiscoveryError::Transport {
                url: url.clone(),
                source,
            })?;
        let status = response.status();
        // NOTE: RFC 9110 §8.3, a Content-Type that is no visible ASCII is
        // legitimately unreadable, and the answer is read as one with none.
        let media_type = response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = capped_body(&mut response, &url).await?;
        Ok((url, status, body, media_type))
    }
}

/// Returns the body of `response`, the answer of `url`, read up to
/// [`MAX_DOCUMENT_BYTES`].
///
/// No specification governs the ceiling: our own design, so a misdirected
/// or hostile server cannot make the process buffer a body of any size.
#[cfg(feature = "fetch")]
pub(crate) async fn capped_body(
    response: &mut reqwest::Response,
    url: &Url,
) -> Result<String, DiscoveryError> {
    let mut bytes = Vec::new();
    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|source| DiscoveryError::Transport {
                url: url.clone(),
                source,
            })?;
        let Some(chunk) = chunk else { break };
        if bytes.len().saturating_add(chunk.len()) > MAX_DOCUMENT_BYTES {
            return Err(DiscoveryError::TooLarge { url: url.clone() });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        DiscoveryError, MtlsEndpointAliases, ServerMetadata, canonical_issuer, check_issuer,
        issuer_url, locations, parse_metadata, repeats_no_name, same_origin,
    };
    use url::Url;

    const ISSUER: &str = "https://as.example.org/oauth2/hospital";

    /// Moves one endpoint member of a metadata document to a location.
    type Move = fn(&mut ServerMetadata, String);

    #[test]
    fn an_issuer_is_identical_only_as_exact_text() {
        assert!(check_issuer(ISSUER, ISSUER).is_ok());
        for named in [
            "https://as.example.org/oauth2/other",
            "https://AS.example.org/oauth2/hospital",
            "https://as.example.org:443/oauth2/hospital",
            "https://as.example.org/oauth2/hospital/",
            "https://as.example.org/oauth2/Hospital",
            "",
        ] {
            assert!(
                matches!(
                    check_issuer(ISSUER, named),
                    Err(DiscoveryError::IssuerMismatch { ref found, .. }) if found == named
                ),
                "{named}"
            );
        }
    }

    #[test]
    fn a_canonical_issuer_is_the_text_the_url_parser_writes() {
        for text in [
            ISSUER,
            "https://as.example.org",
            "https://as.example.org/",
            "https://as.example.org/tenant/",
            "http://127.0.0.1:8080/oauth2",
        ] {
            assert!(canonical_issuer(text).is_ok(), "{text}");
        }
        for text in [
            "https://AS.example.org/tenant",
            "https://as.example.org:443/tenant",
            "https://user@as.example.org",
            "https://user:pass@as.example.org/tenant",
            "https://as.example.org/a/../tenant",
        ] {
            assert!(
                matches!(
                    canonical_issuer(text),
                    Err(DiscoveryError::NonCanonicalIssuer { ref issuer, .. }) if issuer == text
                ),
                "{text}"
            );
        }
        assert!(matches!(
            canonical_issuer("http://as.example.org"),
            Err(DiscoveryError::Insecure { .. })
        ));
        assert!(matches!(
            canonical_issuer("not a url"),
            Err(DiscoveryError::IssuerUrl { .. })
        ));
    }

    #[test]
    fn an_endpoint_is_on_the_issuers_origin_by_scheme_host_and_port() {
        let issuer: Url = ISSUER.parse().expect("a valid URL");
        let url = same_origin(&issuer, "token_endpoint", "https://as.example.org/token")
            .expect("the same origin");
        assert_eq!("https://as.example.org/token", url.as_str());
        assert!(same_origin(&issuer, "token_endpoint", "https://as.example.org:443/t").is_ok());
        for other in [
            "http://as.example.org/token",
            "https://elsewhere.example.org/token",
            "https://as.example.org:8443/token",
            "https://as.example.org.evil.example/token",
            "https://sub.as.example.org/token",
        ] {
            assert!(
                matches!(
                    same_origin(&issuer, "token_endpoint", other),
                    Err(DiscoveryError::OtherOrigin {
                        member: "token_endpoint",
                        ..
                    })
                ),
                "{other}"
            );
        }
        assert!(matches!(
            same_origin(&issuer, "jwks_uri", "/jwks"),
            Err(DiscoveryError::EndpointUrl {
                member: "jwks_uri",
                ..
            })
        ));
    }

    #[test]
    fn the_origin_check_reads_every_endpoint_member() {
        let issuer: Url = ISSUER.parse().expect("a valid URL");
        let on = |path: &str| Some(format!("https://as.example.org{path}"));
        let metadata = ServerMetadata {
            issuer: ISSUER.to_owned(),
            jwks_uri: on("/jwks"),
            authorization_endpoint: on("/authorize"),
            token_endpoint: on("/token"),
            registration_endpoint: on("/register"),
            introspection_endpoint: on("/introspect"),
            revocation_endpoint: on("/revoke"),
            mtls_endpoint_aliases: Some(MtlsEndpointAliases {
                token_endpoint: on("/mtls/token"),
            }),
            ..ServerMetadata::default()
        };
        assert!(metadata.check_origin(&issuer).is_ok());
        assert_eq!(7, metadata.endpoints().len());
        let off = String::from("https://elsewhere.example.org/x");
        let cases: [(&str, Move); 7] = [
            ("jwks_uri", |m, v| m.jwks_uri = Some(v)),
            ("authorization_endpoint", |m, v| {
                m.authorization_endpoint = Some(v);
            }),
            ("token_endpoint", |m, v| m.token_endpoint = Some(v)),
            ("registration_endpoint", |m, v| {
                m.registration_endpoint = Some(v);
            }),
            ("introspection_endpoint", |m, v| {
                m.introspection_endpoint = Some(v);
            }),
            ("revocation_endpoint", |m, v| {
                m.revocation_endpoint = Some(v);
            }),
            ("mtls_endpoint_aliases.token_endpoint", |m, v| {
                m.mtls_endpoint_aliases = Some(MtlsEndpointAliases {
                    token_endpoint: Some(v),
                });
            }),
        ];
        for (name, set) in cases {
            let mut moved = metadata.clone();
            set(&mut moved, off.clone());
            assert!(
                matches!(
                    moved.check_origin(&issuer),
                    Err(DiscoveryError::OtherOrigin { member, .. }) if member == name
                ),
                "{name}"
            );
        }
        let bare = ServerMetadata {
            issuer: ISSUER.to_owned(),
            ..ServerMetadata::default()
        };
        assert!(bare.check_origin(&issuer).is_ok());
    }

    #[test]
    fn a_repeated_name_at_any_depth_is_refused() {
        assert!(repeats_no_name(br#"{"a": 1, "b": {"c": [1, {"d": 2}]}, "e": null}"#).is_ok());
        assert!(repeats_no_name(br#"{"a": {"c": 1}, "b": {"c": 1}}"#).is_ok());
        for body in [
            &br#"{"a": 1, "a": 2}"#[..],
            br#"{"a": 1, "a": 1}"#,
            br#"{"a": {"b": 1, "b": 1}}"#,
            br#"[{"b": 1, "b": 1}]"#,
            br#"{"a": 1, "a": 2}"#,
        ] {
            let error = repeats_no_name(body).expect_err("a repeated name");
            assert_eq!(
                serde_json::error::Category::Data,
                error.category(),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn a_metadata_body_is_refused_for_a_repeated_name_or_for_being_no_document() {
        let url: Url = "https://as.example.org/.well-known/oauth-authorization-server"
            .parse()
            .expect("a valid URL");
        let read = parse_metadata(&url, r#"{"issuer": "https://as.example.org"}"#)
            .expect("a metadata document");
        assert_eq!("https://as.example.org", read.issuer);
        assert!(matches!(
            parse_metadata(
                &url,
                r#"{"issuer": "https://as.example.org", "issuer": "https://attacker.invalid"}"#
            ),
            Err(DiscoveryError::RepeatedName { .. })
        ));
        for body in ["", "{", "[1, 2]", r#"{"issuer": 7}"#] {
            assert!(
                matches!(
                    parse_metadata(&url, body),
                    Err(DiscoveryError::Metadata { .. })
                ),
                "{body}"
            );
        }
    }

    #[test]
    fn rfc_8414_inserts_the_suffix_and_openid_connect_appends_it() {
        let issuer: Url = "https://as.example.org/realms/ferro/"
            .parse()
            .expect("a valid URL");
        let [oauth, openid] = locations(&issuer);
        assert_eq!(
            "https://as.example.org/.well-known/oauth-authorization-server/realms/ferro",
            oauth.as_str()
        );
        assert_eq!(
            "https://as.example.org/realms/ferro/.well-known/openid-configuration",
            openid.as_str()
        );
    }

    #[test]
    fn an_issuer_without_a_path_reads_the_bare_suffixes() {
        let issuer: Url = "https://as.example.org".parse().expect("a valid URL");
        let [oauth, openid] = locations(&issuer);
        assert_eq!(
            "https://as.example.org/.well-known/oauth-authorization-server",
            oauth.as_str()
        );
        assert_eq!(
            "https://as.example.org/.well-known/openid-configuration",
            openid.as_str()
        );
    }

    #[test]
    fn an_issuer_is_https_without_query_or_fragment_and_loopback_may_be_http() {
        assert!(issuer_url("https://as.example.org/realms/ferro").is_ok());
        assert!(issuer_url("http://localhost:8080/realm").is_ok());
        assert!(issuer_url("http://127.0.0.1:8080").is_ok());
        assert!(issuer_url("http://[::1]:8080").is_ok());
        for bad in [
            "http://as.example.org",
            "https://as.example.org/?x=1",
            "https://as.example.org/#frag",
        ] {
            assert!(
                matches!(issuer_url(bad), Err(DiscoveryError::Insecure { .. })),
                "{bad}"
            );
        }
        assert!(matches!(
            issuer_url("not a url"),
            Err(DiscoveryError::IssuerUrl { .. })
        ));
    }
}
