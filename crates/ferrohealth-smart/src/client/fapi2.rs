// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The FAPI 2.0 Security Profile on a client grant: the rules the profile
//! sets a client, checked when the grant is built and when its
//! authorization server's metadata is read.
//!
//! When the grant is built ([`ClientCredentials::validate`]):
//!
//! - the token endpoint is discovered from the issuer, since the client
//!   "shall only use authorization server metadata ... retrieved from the
//!   metadata document" (FAPI 2.0 §5.3.3.1);
//! - the client authenticates with `private_key_jwt` or mutual TLS
//!   (§5.3.3.1), an assertion naming the issuer as its one-string `aud`
//!   (§5.3.3.1), every key of its ring and its `DPoP` key signing `PS256`,
//!   `ES256` or `EdDSA` (§5.4.1);
//! - every token is sender-constrained, by `DPoP` or the certificate
//!   (§5.3.2.1, §5.3.3.1);
//! - the grant asks for a `scope` or `authorization_details`, so the
//!   authorization server never chooses what the token may do (no
//!   specification governs this: our own design);
//! - alias hosts are named only by a grant that uses mutual TLS, the only
//!   one that reads `mtls_endpoint_aliases` (RFC 8705 §5).
//!
//! When the metadata is read, before anything reaches the token endpoint:
//! an `application/json` document (RFC 8414 §3.2), a token endpoint on the
//! issuer's origin or, for a mutual-TLS alias, on a host the grant names
//! (RFC 8705 §5; the hosts are our own design), the client's method in
//! `token_endpoint_auth_methods_supported`, its algorithm in
//! `token_endpoint_auth_signing_alg_values_supported` (RFC 8414 §2),
//! `tls_client_certificate_bound_access_tokens` true for a certificate-bound
//! grant (RFC 8705 §3.3), every grant type it sends in
//! `grant_types_supported` (RFC 8414 §2), and its proof algorithm in a
//! listed `dpop_signing_alg_values_supported` (RFC 9449 §5.1).
//!
//! What the profile asks of an authorization-endpoint flow (pushed
//! authorization requests, PKCE, §5.3.2.2) needs a user agent, and no grant
//! of this client has one.

use crate::jws::algorithm::Algorithm;
use url::Url;

use crate::client::ClientAuth;
use crate::client::ClientCredentials;
use crate::client::Endpoint;
use crate::client::binding::TokenBinding;
#[cfg(feature = "fetch")]
use crate::metadata::ServerMetadata;

/// The JWS algorithms FAPI 2.0 §5.4.1 admits.
pub const ALGORITHMS: [Algorithm; 3] = [Algorithm::Ps256, Algorithm::Es256, Algorithm::EdDsa];

/// The security profile a client grant is held to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecurityProfile {
    /// OAuth 2.0 as each RFC the grant uses sets it.
    #[default]
    OAuth2,
    /// The FAPI 2.0 Security Profile.
    Fapi2(Fapi2),
}

/// The security profile a `[<lane>.credentials.oauth]` table names.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ProfileKind {
    /// OAuth 2.0, the default.
    #[default]
    OAuth2,
    /// The FAPI 2.0 Security Profile.
    Fapi2,
}

/// What a FAPI 2.0 grant names beyond its credentials: the hosts beside the
/// issuer's origin a mutual-TLS endpoint alias may be on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fapi2 {
    /// The hosts, each as its `https` origin.
    alias_hosts: Vec<AliasHost>,
}

impl Fapi2 {
    /// Returns the profile taking a mutual-TLS alias on the issuer's origin
    /// alone.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            alias_hosts: Vec::new(),
        }
    }

    /// Returns this profile taking a mutual-TLS alias on `host` as well.
    #[must_use]
    pub fn with_alias_host(mut self, host: AliasHost) -> Self {
        self.alias_hosts.push(host);
        self
    }

    /// Returns the hosts beside the issuer's origin an alias may be on.
    #[must_use]
    pub fn alias_hosts(&self) -> &[AliasHost] {
        &self.alias_hosts
    }
}

/// A host a client sends a mutual-TLS endpoint alias to beside its issuer's
/// origin (RFC 8705 §5): a host name, or a host name and a port, read as an
/// `https` origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasHost {
    /// The host, as written.
    text: String,
    /// Its `https` origin.
    origin: url::Origin,
}

/// A host that cannot be an [`AliasHost`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "the alias host is not a host name, or a host name and a port, in the canonical form the URL parser gives it"
)]
pub struct InvalidAliasHost;

impl AliasHost {
    /// Reads `text`, such as `mtls.example.com` or `mtls.example.com:8443`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAliasHost`] for text that is no host, carries a
    /// scheme, userinfo, a path, a query or a fragment, or is not written in
    /// the canonical form the URL parser gives it.
    pub fn parse(text: &str) -> Result<Self, InvalidAliasHost> {
        let written = format!("https://{text}/");
        let url = Url::parse(&written).map_err(|_unparsable| InvalidAliasHost)?;
        if text.is_empty()
            || url.as_str() != written
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(InvalidAliasHost);
        }
        Ok(Self {
            text: text.to_owned(),
            origin: url.origin(),
        })
    }

    /// Returns the host, as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

/// A rule of the FAPI 2.0 Security Profile a grant or its authorization
/// server breaks.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Fapi2Error {
    /// The grant names its token endpoint outright (FAPI 2.0 §5.3.3.1).
    #[error("a FAPI 2.0 grant discovers its token endpoint from the issuer (FAPI 2.0 §5.3.3.1)")]
    NoIssuer,
    /// The grant authenticates with a client secret (FAPI 2.0 §5.3.3.1).
    #[error(
        "a FAPI 2.0 grant authenticates with private_key_jwt or mutual TLS (FAPI 2.0 §5.3.3.1)"
    )]
    ClientAuthentication,
    /// A key signs an algorithm the profile does not admit (§5.4.1).
    #[error("the {role} key signs {algorithm}, which FAPI 2.0 §5.4.1 does not admit")]
    Algorithm {
        /// Which key.
        role: &'static str,
        /// The algorithm.
        algorithm: Algorithm,
    },
    /// The grant's tokens are not sender-constrained (§5.3.3.1).
    #[error("a FAPI 2.0 grant binds its tokens with DPoP or its certificate (FAPI 2.0 §5.3.3.1)")]
    Unbound,
    /// The grant asks for neither a scope nor `authorization_details`.
    #[error("a FAPI 2.0 grant asks for a scope or authorization_details")]
    Unrequested,
    /// Alias hosts are named by a grant that does not use mutual TLS.
    #[error("alias hosts are named and the grant does not use mutual TLS (RFC 8705 §5)")]
    AliasHostsUnused,
    /// The metadata is not `application/json` (RFC 8414 §3.2).
    #[error("the authorization server metadata is not application/json (RFC 8414 §3.2)")]
    MediaType,
    /// The token endpoint is not on the issuer's origin, or a mutual-TLS
    /// alias on no host the grant names.
    #[error("the metadata's {member} is not on the issuer's origin or a named alias host")]
    Endpoint {
        /// The member.
        member: &'static str,
    },
    /// The token endpoint does not list the client's authentication method.
    #[error("the token endpoint does not list the client authentication {method} (RFC 8414 §2)")]
    AuthenticationMethod {
        /// The method.
        method: &'static str,
    },
    /// The token endpoint does not list the assertion's algorithm.
    #[error("the token endpoint does not list {algorithm} for client assertions (RFC 8414 §2)")]
    SigningAlgorithm {
        /// The algorithm.
        algorithm: Algorithm,
    },
    /// The server does not state it issues certificate-bound tokens.
    #[error(
        "the authorization server does not state tls_client_certificate_bound_access_tokens (RFC 8705 §3.3)"
    )]
    CertificateBinding,
    /// The server does not list a grant type the grant sends.
    #[error("the authorization server does not list the grant type {grant_type} (RFC 8414 §2)")]
    GrantType {
        /// The grant type.
        grant_type: &'static str,
    },
    /// The server lists `DPoP` algorithms without the proof's.
    #[error("the metadata's dpop_signing_alg_values_supported does not list {algorithm}")]
    ProofAlgorithm {
        /// The algorithm.
        algorithm: Algorithm,
    },
}

/// Checks `config`, a grant under `profile`, against the build-time rules.
pub(crate) fn check_grant(config: &ClientCredentials, profile: &Fapi2) -> Result<(), Fapi2Error> {
    if !matches!(config.endpoint, Endpoint::Issuer(_)) {
        return Err(Fapi2Error::NoIssuer);
    }
    match config.client_auth {
        ClientAuth::PrivateKeyJwt
        | ClientAuth::TlsClientAuth
        | ClientAuth::SelfSignedTlsClientAuth => {}
        ClientAuth::ClientSecretBasic | ClientAuth::ClientSecretPost => {
            return Err(Fapi2Error::ClientAuthentication);
        }
    }
    if let Some(ring) = &config.assertion_keys {
        let keys = [
            ("assertion", Some(ring.current())),
            ("previous assertion", ring.retiring()),
            ("next assertion", ring.next()),
        ];
        for (role, key) in keys {
            if let Some(key) = key
                && !ALGORITHMS.contains(&key.algorithm())
            {
                return Err(Fapi2Error::Algorithm {
                    role,
                    algorithm: key.algorithm(),
                });
            }
        }
    }
    match &config.token_binding {
        None => return Err(Fapi2Error::Unbound),
        Some(TokenBinding::Dpop(key)) if !ALGORITHMS.contains(&key.algorithm()) => {
            return Err(Fapi2Error::Algorithm {
                role: "DPoP",
                algorithm: key.algorithm(),
            });
        }
        Some(_) => {}
    }
    if config.scope.is_none() && config.authorization_details.is_none() {
        return Err(Fapi2Error::Unrequested);
    }
    if !profile.alias_hosts.is_empty() && !uses_mutual_tls(config) {
        return Err(Fapi2Error::AliasHostsUnused);
    }
    Ok(())
}

/// Returns whether `config` uses mutual TLS at the token endpoint: to
/// authenticate, to bind its tokens, or both (RFC 8705 §5).
fn uses_mutual_tls(config: &ClientCredentials) -> bool {
    config.client_auth.is_mutual_tls()
        || matches!(config.token_binding, Some(TokenBinding::Certificate))
}

/// Checks `metadata`, read as `media_type`, against what `config` under
/// `profile` sends with `grant_types`, and returns the token endpoint.
#[cfg(feature = "fetch")]
pub(crate) fn check_metadata(
    config: &ClientCredentials,
    profile: &Fapi2,
    (metadata, media_type): (&ServerMetadata, Option<&str>),
    grant_types: &[&'static str],
) -> Result<Url, Fapi2Error> {
    let json = media_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"));
    if !json {
        return Err(Fapi2Error::MediaType);
    }
    let issuer = Url::parse(&metadata.issuer)
        .map_err(|_unparsable| Fapi2Error::Endpoint { member: "issuer" })?;
    let token_endpoint = token_endpoint(config, profile, metadata, &issuer)?;
    let lists = |list: Option<&Vec<String>>, value: &str| {
        list.is_some_and(|list| list.iter().any(|item| item == value))
    };
    let method = match config.client_auth {
        ClientAuth::TlsClientAuth => "tls_client_auth",
        ClientAuth::SelfSignedTlsClientAuth => "self_signed_tls_client_auth",
        ClientAuth::PrivateKeyJwt
        | ClientAuth::ClientSecretBasic
        | ClientAuth::ClientSecretPost => "private_key_jwt",
    };
    if !lists(
        metadata.token_endpoint_auth_methods_supported.as_ref(),
        method,
    ) {
        return Err(Fapi2Error::AuthenticationMethod { method });
    }
    if config.client_auth == ClientAuth::PrivateKeyJwt
        && let Some(ring) = &config.assertion_keys
        && !names_algorithm(
            metadata
                .token_endpoint_auth_signing_alg_values_supported
                .as_ref(),
            ring.current().algorithm(),
        )
    {
        return Err(Fapi2Error::SigningAlgorithm {
            algorithm: ring.current().algorithm(),
        });
    }
    if matches!(config.token_binding, Some(TokenBinding::Certificate))
        && metadata.tls_client_certificate_bound_access_tokens != Some(true)
    {
        return Err(Fapi2Error::CertificateBinding);
    }
    if let Some(grant_type) = grant_types
        .iter()
        .copied()
        .find(|grant_type| !lists(metadata.grant_types_supported.as_ref(), grant_type))
    {
        return Err(Fapi2Error::GrantType { grant_type });
    }
    if let Some(TokenBinding::Dpop(key)) = &config.token_binding
        && metadata
            .dpop_signing_alg_values_supported
            .as_ref()
            .is_some_and(|listed| !names_algorithm(Some(listed), key.algorithm()))
    {
        return Err(Fapi2Error::ProofAlgorithm {
            algorithm: key.algorithm(),
        });
    }
    Ok(token_endpoint)
}

/// Returns the token endpoint `metadata` names for `config`: the mutual-TLS
/// alias in preference for a grant that uses mutual TLS (RFC 8705 §5), on
/// the issuer's origin or a host `profile` names, or the token endpoint on
/// the issuer's origin.
#[cfg(feature = "fetch")]
fn token_endpoint(
    config: &ClientCredentials,
    profile: &Fapi2,
    metadata: &ServerMetadata,
    issuer: &Url,
) -> Result<Url, Fapi2Error> {
    let alias = metadata
        .mtls_endpoint_aliases
        .as_ref()
        .and_then(|aliases| aliases.token_endpoint.as_deref())
        .filter(|_alias| uses_mutual_tls(config));
    let (member, text) = match alias {
        Some(alias) => ("mtls_endpoint_aliases.token_endpoint", alias),
        None => (
            "token_endpoint",
            metadata
                .token_endpoint
                .as_deref()
                .ok_or(Fapi2Error::Endpoint {
                    member: "token_endpoint",
                })?,
        ),
    };
    let url = Url::parse(text).map_err(|_unparsable| Fapi2Error::Endpoint { member })?;
    let on_issuer = url.origin() == issuer.origin();
    let on_named = alias.is_some()
        && profile
            .alias_hosts
            .iter()
            .any(|host| host.origin == url.origin());
    // NOTE: no specification governs this: our own design; RFC 8414 places no
    // endpoint, and a credential goes to the issuer's origin or a named host alone.
    if !(on_issuer || on_named)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Fapi2Error::Endpoint { member });
    }
    Ok(url)
}

/// Returns whether `listed`, a metadata list of algorithm names, names
/// `algorithm` as RFC 7518 §3.1 writes it.
#[cfg(feature = "fetch")]
fn names_algorithm(listed: Option<&Vec<String>>, algorithm: Algorithm) -> bool {
    listed.is_some_and(|listed| listed.iter().any(|item| item == algorithm.name()))
}

#[cfg(test)]
mod tests {
    use super::AliasHost;
    #[cfg(feature = "fetch")]
    use super::{Fapi2, Fapi2Error, token_endpoint};
    #[cfg(feature = "fetch")]
    use crate::client::{ClientCredentials, Endpoint};
    #[cfg(feature = "fetch")]
    use crate::metadata::{MtlsEndpointAliases, ServerMetadata};

    #[cfg(feature = "fetch")]
    #[test]
    fn a_mutual_tls_alias_is_taken_on_the_issuer_or_a_named_host() {
        let issuer: url::Url = "https://as.example.org".parse().expect("a URL");
        let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("the default versions")
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let grant = ClientCredentials::with_presented_tls(
            Endpoint::Issuer(issuer.to_string()),
            String::from("gateway"),
            crate::client::PresentedTls::new(
                std::sync::Arc::new(config),
                Some(rustls::pki_types::CertificateDer::from(Vec::new())),
            ),
            false,
        );
        let metadata = |alias: &str| ServerMetadata {
            issuer: issuer.to_string(),
            token_endpoint: Some(String::from("https://as.example.org/token")),
            mtls_endpoint_aliases: Some(MtlsEndpointAliases {
                token_endpoint: Some(alias.to_owned()),
            }),
            ..ServerMetadata::default()
        };
        let named =
            Fapi2::new().with_alias_host(AliasHost::parse("mtls.example.org").expect("a host"));
        let taken = token_endpoint(
            &grant,
            &named,
            &metadata("https://mtls.example.org/token"),
            &issuer,
        )
        .expect("a named host is taken");
        assert_eq!("https://mtls.example.org/token", taken.as_str());
        assert!(
            token_endpoint(
                &grant,
                &Fapi2::new(),
                &metadata("https://as.example.org/mtls"),
                &issuer
            )
            .is_ok()
        );
        assert_eq!(
            Err(Fapi2Error::Endpoint {
                member: "mtls_endpoint_aliases.token_endpoint"
            }),
            token_endpoint(
                &grant,
                &named,
                &metadata("https://other.example.org/token"),
                &issuer
            )
        );
    }

    #[test]
    fn an_alias_host_is_a_canonical_host_and_port() {
        assert!(AliasHost::parse("mtls.example.com").is_ok());
        assert!(AliasHost::parse("mtls.example.com:8443").is_ok());
        for text in [
            "",
            "https://mtls.example.com",
            "MTLS.example.com",
            "mtls.example.com:443",
            "mtls.example.com/path",
            "user@mtls.example.com",
            "mtls.example.com?q",
        ] {
            assert!(AliasHost::parse(text).is_err(), "{text}");
        }
    }
}
