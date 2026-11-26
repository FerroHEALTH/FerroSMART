// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `[oidc]` and `[session]` sections every console embeds in its
//! configuration.
//!
//! Both are read with `deny_unknown_fields`, every default lives in the
//! section's `Default`, and every secret is a
//! `ferrohealth_secret::secret::Secret` read inline or from the file its
//! `<key>_file` sibling names. [`OidcSection::check`] and
//! [`SessionSection::check`] refuse a section the console cannot run with,
//! naming the key and never the secret.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use ferrohealth_config::tls::TlsClientSection;
use ferrohealth_config::units::Duration as ConfigDuration;
use ferrohealth_secret::file::{SecretError, read_secret};
use ferrohealth_secret::secret::Secret;
use ferrohealth_secret::secret_url::SecretUrl;
use ferrohealth_smart::client::{PresentedTls, Reach, Tls};
use ferrohealth_smart::config::TlsBuilder;
use ferrohealth_smart::metadata::{DiscoveryError, Http, ServerMetadata};
use ferrohealth_smart::oidc::{OFFLINE_ACCESS, OPENID, OidcError, Provider, RelyingParty};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::lifetime::Lifetimes;

/// Why a section was refused, or the provider could not be reached.
///
/// No variant carries a secret.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A secret could not be read.
    #[error(transparent)]
    Secret(#[from] SecretError),
    /// A required key is empty.
    #[error("{key} is not set")]
    Missing {
        /// The key.
        key: &'static str,
    },
    /// A key is not a URL.
    #[error("{key} is not a URL")]
    Url {
        /// The key.
        key: &'static str,
        /// What the parser said.
        #[source]
        source: url::ParseError,
    },
    /// A URL is not one its key admits: a provider URL that is not `https`
    /// off loopback, or a redirection endpoint with userinfo or a fragment.
    #[error("{key} {reason}")]
    UrlShape {
        /// The key.
        key: &'static str,
        /// What the key requires.
        reason: &'static str,
    },
    /// `scopes` lacks `openid` (OpenID Connect Core 1.0 §3.1.2.1).
    #[error("oidc.scopes must hold openid")]
    NoOpenId,
    /// `scopes` lists `offline_access`, which `offline_access = true` asks
    /// for (OpenID Connect Core 1.0 §11).
    #[error("oidc.scopes must not list offline_access; set oidc.offline_access = true")]
    OfflineAccessScope,
    /// A lifetime or a bound is zero.
    #[error("{key} must be greater than zero")]
    Zero {
        /// The key.
        key: &'static str,
    },
    /// The absolute lifetime is shorter than the idle one.
    #[error("session.absolute_timeout must be at least session.idle_timeout")]
    AbsoluteBeforeIdle,
    /// `oidc.tls` names TLS material and the section was checked without
    /// the console's TLS builder, the one reader of TLS material.
    #[error("oidc.tls names TLS material; check the section with the console's TLS builder")]
    TlsNotBuilt,
    /// The console's TLS builder refused `oidc.tls`.
    #[error("oidc.tls is refused")]
    TlsBuild(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// An `oidc.resolve` entry is not `host=ip:port`.
    #[error("oidc.resolve entry {index} must be host=ip:port")]
    Resolve {
        /// The entry's position, from zero.
        index: usize,
    },
    /// The HTTP engine could not be built.
    #[error("the OpenID Provider's client could not be built")]
    Http(#[source] DiscoveryError),
    /// The provider's metadata could not be read or names no endpoint the
    /// sign-in needs.
    #[error("the OpenID Provider could not be read")]
    Provider(#[source] OidcError),
}

/// `[oidc]`: the console's client at its OpenID Provider.
///
/// With `issuer` alone, the endpoints are discovered (RFC 8414 §3, OpenID
/// Connect Discovery 1.0 §4); each endpoint given here takes the place of
/// the discovered one. The issuer, the endpoints and the two redirection
/// URIs render with their userinfo and their query masked, as [`SecretUrl`]
/// renders itself, in `Debug` and when serialized.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct OidcSection {
    /// The provider's issuer identifier, which an ID Token's `iss` must
    /// equal exactly (OpenID Connect Core 1.0 §3.1.3.7).
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub issuer: SecretUrl,
    /// The authorization endpoint (RFC 6749 §3.1).
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub authorization_endpoint: Option<SecretUrl>,
    /// The token endpoint (RFC 6749 §3.2).
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub token_endpoint: Option<SecretUrl>,
    /// The JWK Set of the keys that sign the ID Tokens.
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub jwks_uri: Option<SecretUrl>,
    /// The end-session endpoint (OpenID Connect RP-Initiated Logout 1.0 §2).
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub end_session_endpoint: Option<SecretUrl>,
    /// The revocation endpoint (RFC 7009 §2).
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub revocation_endpoint: Option<SecretUrl>,
    /// The console's client identifier (RFC 6749 §2.2).
    pub client_id: String,
    /// The console's client secret, inline, for a confidential client.
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub client_secret: Option<Secret>,
    /// A file holding the console's client secret.
    pub client_secret_file: Option<PathBuf>,
    /// The redirection endpoint, the console's `/auth/callback`
    /// (RFC 6749 §3.1.2).
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub redirect_uri: SecretUrl,
    /// Where the provider sends the operator after a sign-out.
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub post_logout_redirect_uri: Option<SecretUrl>,
    /// The scopes requested, `openid` among them.
    pub scopes: Vec<String>,
    /// Whether the sign-in asks for `offline_access` (OpenID Connect Core
    /// 1.0 §11), so the provider issues a refresh token.
    pub offline_access: bool,
    /// Provider hosts reached at a fixed address in place of resolving
    /// their names, each `host=ip:port`, for a provider whose name resolves
    /// only inside a private network. The URL's port and the certificate
    /// check against the host name stay as the URL names them.
    pub resolve: Vec<String>,
    /// `[oidc.tls]`: the trust roots, the client certificate (RFC 8705 §2)
    /// and the TLS floor of the provider connection, built by the console's
    /// [`TlsBuilder`]; the crate reads no TLS file.
    pub tls: TlsClientSection,
    /// How long one call to the provider may take; never zero.
    pub timeout: ConfigDuration,
}

impl Default for OidcSection {
    fn default() -> Self {
        Self {
            issuer: SecretUrl::default(),
            authorization_endpoint: None,
            token_endpoint: None,
            jwks_uri: None,
            end_session_endpoint: None,
            revocation_endpoint: None,
            client_id: String::new(),
            client_secret: None,
            client_secret_file: None,
            redirect_uri: SecretUrl::default(),
            post_logout_redirect_uri: None,
            scopes: vec![String::from(OPENID)],
            offline_access: false,
            resolve: Vec::new(),
            tls: TlsClientSection::default(),
            timeout: ConfigDuration::from_secs(10),
        }
    }
}

/// The checked `[oidc]`.
#[derive(Clone)]
pub struct OidcSettings {
    issuer: String,
    endpoints: ServerMetadata,
    client_id: String,
    client_secret: Option<Secret>,
    redirect_uri: Url,
    post_logout_redirect_uri: Option<Url>,
    scopes: Vec<String>,
    offline_access: bool,
    tls: Tls,
    reach: Reach,
    timeout: Duration,
}

impl fmt::Debug for OidcSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcSettings")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri.as_str())
            .field("scopes", &self.scopes)
            .field("offline_access", &self.offline_access)
            .finish_non_exhaustive()
    }
}

impl OidcSection {
    /// Checks the section and reads its client secret.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Missing`] for an empty `issuer`, `client_id`
    /// or `redirect_uri`, [`ConfigError::Url`] for a value that is not a
    /// URL, [`ConfigError::UrlShape`] for a provider URL that is not `https`
    /// off loopback or a redirection endpoint that is no `http` or `https`
    /// URL with a host, no userinfo and no fragment,
    /// [`ConfigError::NoOpenId`] and [`ConfigError::OfflineAccessScope`] for
    /// `scopes` without `openid` or with `offline_access`,
    /// [`ConfigError::Zero`] for a zero `timeout`,
    /// [`ConfigError::Resolve`] for a `resolve` entry that is not
    /// `host=ip:port`, [`ConfigError::TlsNotBuilt`] when `tls` names TLS
    /// material, and the errors of reading `client_secret`.
    pub fn check(&self) -> Result<OidcSettings, ConfigError> {
        if self.tls.names_material() {
            return Err(ConfigError::TlsNotBuilt);
        }
        self.check_over(None)
    }

    /// Checks the section as [`Self::check`] does, `oidc.tls` built by
    /// `tls`, the console's reader of TLS material.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::check`], and [`ConfigError::TlsBuild`] when
    /// `tls` refuses `oidc.tls`.
    pub fn check_with_tls(&self, tls: &dyn TlsBuilder) -> Result<OidcSettings, ConfigError> {
        let presented = tls
            .build("oidc.tls", &self.tls)
            .map_err(ConfigError::TlsBuild)?;
        self.check_over(Some(presented))
    }

    /// Checks the section, over the configuration the console built.
    fn check_over(&self, presented: Option<PresentedTls>) -> Result<OidcSettings, ConfigError> {
        let issuer = required("oidc.issuer", self.issuer.expose())?;
        provider_url("oidc.issuer", issuer)?;
        let client_id = required("oidc.client_id", &self.client_id)?;
        let redirect_uri = web_url(
            "oidc.redirect_uri",
            required("oidc.redirect_uri", self.redirect_uri.expose())?,
        )?;
        // NOTE: RFC 6749 §3.1.2: the redirection endpoint URI MUST NOT include a fragment
        // component.
        if redirect_uri.fragment().is_some() {
            return Err(ConfigError::UrlShape {
                key: "oidc.redirect_uri",
                reason: "must not carry a fragment",
            });
        }
        // NOTE: OpenID Connect Core 1.0 §3.1.2.1: an OpenID Connect request MUST carry the
        // `openid` scope value.
        if !self.scopes.iter().any(|scope| scope == OPENID) {
            return Err(ConfigError::NoOpenId);
        }
        // NOTE: OpenID Connect Core 1.0 §11: `offline_access` goes with `prompt=consent`,
        // which the relying party sends only for `offline_access = true`.
        if self.scopes.iter().any(|scope| scope == OFFLINE_ACCESS) {
            return Err(ConfigError::OfflineAccessScope);
        }
        let endpoints = ServerMetadata {
            issuer: issuer.to_owned(),
            authorization_endpoint: endpoint(
                "oidc.authorization_endpoint",
                self.authorization_endpoint.as_ref().map(SecretUrl::expose),
            )?,
            token_endpoint: endpoint(
                "oidc.token_endpoint",
                self.token_endpoint.as_ref().map(SecretUrl::expose),
            )?,
            jwks_uri: endpoint(
                "oidc.jwks_uri",
                self.jwks_uri.as_ref().map(SecretUrl::expose),
            )?,
            end_session_endpoint: endpoint(
                "oidc.end_session_endpoint",
                self.end_session_endpoint.as_ref().map(SecretUrl::expose),
            )?,
            revocation_endpoint: endpoint(
                "oidc.revocation_endpoint",
                self.revocation_endpoint.as_ref().map(SecretUrl::expose),
            )?,
            ..ServerMetadata::default()
        };
        let post_logout_redirect_uri = self
            .post_logout_redirect_uri
            .as_ref()
            .map(SecretUrl::expose)
            .map(|value| web_url("oidc.post_logout_redirect_uri", value))
            .transpose()?;
        if self.timeout.is_zero() {
            return Err(ConfigError::Zero {
                key: "oidc.timeout",
            });
        }
        let client_secret = read_secret(
            "oidc.client_secret",
            self.client_secret.clone(),
            self.client_secret_file.as_deref(),
        )?;
        let tls = Tls {
            presented,
            min_version: self.tls.min_version,
        };
        let mut reach = Reach::default();
        for (index, entry) in self.resolve.iter().enumerate() {
            let (host, address) = resolve_entry(entry).ok_or(ConfigError::Resolve { index })?;
            reach = reach.with_resolve(host, address);
        }
        Ok(OidcSettings {
            issuer: issuer.to_owned(),
            endpoints,
            client_id: client_id.to_owned(),
            client_secret,
            redirect_uri,
            post_logout_redirect_uri,
            scopes: self.scopes.clone(),
            offline_access: self.offline_access,
            tls,
            reach,
            timeout: self.timeout.get(),
        })
    }
}

impl OidcSettings {
    /// Whether the sign-in asks for a refresh token.
    #[must_use]
    pub const fn offline_access(&self) -> bool {
        self.offline_access
    }

    /// The console's relying party at the provider, its endpoints discovered
    /// unless the section names the three the sign-in needs.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Http`] when the client cannot be built and
    /// [`ConfigError::Provider`] when discovery fails or the metadata names
    /// no authorization, token or key-set endpoint.
    pub async fn relying_party(&self) -> Result<RelyingParty, ConfigError> {
        let http =
            Http::reaching(self.timeout, &self.tls, &self.reach).map_err(ConfigError::Http)?;
        let given = &self.endpoints;
        let complete = given.authorization_endpoint.is_some()
            && given.token_endpoint.is_some()
            && given.jwks_uri.is_some();
        let metadata = if complete {
            given.clone()
        } else {
            let found = http
                .discover(&self.issuer)
                .await
                .map_err(|error| ConfigError::Provider(OidcError::Discovery(error)))?;
            ServerMetadata {
                authorization_endpoint: given
                    .authorization_endpoint
                    .clone()
                    .or(found.authorization_endpoint.clone()),
                token_endpoint: given
                    .token_endpoint
                    .clone()
                    .or(found.token_endpoint.clone()),
                jwks_uri: given.jwks_uri.clone().or(found.jwks_uri.clone()),
                end_session_endpoint: given
                    .end_session_endpoint
                    .clone()
                    .or(found.end_session_endpoint.clone()),
                revocation_endpoint: given
                    .revocation_endpoint
                    .clone()
                    .or(found.revocation_endpoint.clone()),
                ..found
            }
        };
        let provider = Provider::from_metadata(&metadata).map_err(ConfigError::Provider)?;
        let mut party = RelyingParty::new(
            http,
            provider,
            self.client_id.clone(),
            self.redirect_uri.clone(),
        )
        .with_scopes(self.scopes.iter().cloned());
        if let Some(secret) = &self.client_secret {
            party = party.with_client_secret(secret.to_secret_string());
        }
        if self.offline_access {
            party = party.with_offline_access();
        }
        if let Some(redirect) = &self.post_logout_redirect_uri {
            party = party.with_post_logout_redirect_uri(redirect.clone());
        }
        Ok(party)
    }
}

/// Where a console keeps its sessions.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StoreKind {
    /// In the console's process, bounded; the cookie carries an opaque id.
    #[default]
    Memory,
}

/// `[session]`: the store and the lifetimes of the console's sessions.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionSection {
    /// Where the sessions are kept.
    pub store: StoreKind,
    /// Whether the cookies carry `Secure`, and with it the `__Host-` prefix.
    pub secure_cookie: bool,
    /// How long a pending sign-in waits for the provider's redirect back.
    pub sign_in_timeout: ConfigDuration,
    /// How many pending sign-ins a `memory` store holds; past it the oldest
    /// is dropped.
    pub max_sign_ins: usize,
    /// How long a session lives with no request that counts as activity.
    pub idle_timeout: ConfigDuration,
    /// How long a session lives from its sign-in, whatever the activity.
    pub absolute_timeout: ConfigDuration,
    /// How many sessions a `memory` store holds; past it a new one is
    /// refused.
    pub max_sessions: usize,
}

impl Default for SessionSection {
    fn default() -> Self {
        Self {
            store: StoreKind::Memory,
            secure_cookie: true,
            sign_in_timeout: ConfigDuration::from_mins(5),
            max_sign_ins: 1000,
            idle_timeout: ConfigDuration::from_mins(30),
            absolute_timeout: ConfigDuration::from_hours(12),
            max_sessions: 10_000,
        }
    }
}

/// The checked `[session]`.
#[derive(Clone)]
pub struct SessionSettings {
    pub(crate) max_sign_ins: usize,
    pub(crate) max_sessions: usize,
    pub(crate) secure_cookie: bool,
    pub(crate) sign_in_timeout: Duration,
    pub(crate) lifetimes: Lifetimes,
}

impl fmt::Debug for SessionSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionSettings")
            .field("max_sign_ins", &self.max_sign_ins)
            .field("max_sessions", &self.max_sessions)
            .field("secure_cookie", &self.secure_cookie)
            .field("sign_in_timeout", &self.sign_in_timeout)
            .field("lifetimes", &self.lifetimes)
            .finish_non_exhaustive()
    }
}

impl SessionSettings {
    /// The lifetimes of every session.
    #[must_use]
    pub const fn lifetimes(&self) -> Lifetimes {
        self.lifetimes
    }

    /// Whether the cookies carry `Secure` and the `__Host-` prefix.
    #[must_use]
    pub const fn secure_cookie(&self) -> bool {
        self.secure_cookie
    }
}

impl SessionSection {
    /// Checks the section.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Zero`] for a zero lifetime or bound, and
    /// [`ConfigError::AbsoluteBeforeIdle`] for an absolute lifetime shorter
    /// than the idle one.
    pub fn check(&self) -> Result<SessionSettings, ConfigError> {
        for (key, value) in [
            ("session.sign_in_timeout", self.sign_in_timeout),
            ("session.idle_timeout", self.idle_timeout),
            ("session.absolute_timeout", self.absolute_timeout),
        ] {
            if value.is_zero() {
                return Err(ConfigError::Zero { key });
            }
        }
        if self.absolute_timeout < self.idle_timeout {
            return Err(ConfigError::AbsoluteBeforeIdle);
        }
        for (key, value) in [
            ("session.max_sign_ins", self.max_sign_ins),
            ("session.max_sessions", self.max_sessions),
        ] {
            if value == 0 {
                return Err(ConfigError::Zero { key });
            }
        }
        Ok(SessionSettings {
            max_sign_ins: self.max_sign_ins,
            max_sessions: self.max_sessions,
            secure_cookie: self.secure_cookie,
            sign_in_timeout: self.sign_in_timeout.get(),
            lifetimes: Lifetimes {
                idle: self.idle_timeout.get(),
                absolute: self.absolute_timeout.get(),
            },
        })
    }
}

/// `value` of `key`, refused when empty.
fn required<'a>(key: &'static str, value: &'a str) -> Result<&'a str, ConfigError> {
    let value = value.trim();
    if value.is_empty() {
        Err(ConfigError::Missing { key })
    } else {
        Ok(value)
    }
}

/// `value` of `key` as a URL.
fn url(key: &'static str, value: &str) -> Result<Url, ConfigError> {
    Url::parse(value).map_err(|source| ConfigError::Url { key, source })
}

/// An optional provider endpoint, checked as [`provider_url`] and kept as
/// written.
fn endpoint(key: &'static str, value: Option<&str>) -> Result<Option<String>, ConfigError> {
    value
        .map(|text| provider_url(key, text).map(|_| text.to_owned()))
        .transpose()
}

/// `value` of `key` as an `http` or `https` URL with a host and no userinfo.
fn web_url(key: &'static str, value: &str) -> Result<Url, ConfigError> {
    let parsed = url(key, value)?;
    let shape = |reason| Err(ConfigError::UrlShape { key, reason });
    if !matches!(parsed.scheme(), "http" | "https") {
        return shape("must be an http or https URL");
    }
    if parsed.host().is_none() {
        return shape("must name a host");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return shape("must not carry userinfo");
    }
    Ok(parsed)
}

/// `value` of `key` as a provider URL: `https`, or `http` on a loopback host.
fn provider_url(key: &'static str, value: &str) -> Result<Url, ConfigError> {
    let parsed = web_url(key, value)?;
    // NOTE: RFC 6749 §3.1: the authorization server MUST require TLS at its authorization
    // endpoint, so plain `http` is admitted only on loopback.
    if parsed.scheme() == "https" || is_loopback(&parsed) {
        Ok(parsed)
    } else {
        Err(ConfigError::UrlShape {
            key,
            reason: "must be an https URL unless its host is loopback",
        })
    }
}

/// Whether `url` names a loopback host: `localhost`, `127.0.0.0/8` or `::1`.
fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(name)) => name == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// The host and the address of one `resolve` entry, `host=ip:port`.
fn resolve_entry(entry: &str) -> Option<(String, SocketAddr)> {
    let (host, address) = entry.split_once('=')?;
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    let address = address.trim().parse().ok()?;
    Some((host.to_ascii_lowercase(), address))
}

#[cfg(test)]
mod tests {
    use ferrohealth_secret::secret::Secret;
    use ferrohealth_secret::secret_url::SecretUrl;

    use ferrohealth_smart::oidc::{OFFLINE_ACCESS, OPENID};

    use super::{ConfigError, OidcSection, SessionSection};

    #[test]
    fn the_sections_refuse_an_unknown_key() {
        let refused = toml::from_str::<SessionSection>("idle_minutes = 5");
        assert!(refused.is_err(), "deny_unknown_fields");
        let refused = toml::from_str::<OidcSection>("issuer = \"x\"\nclient = \"y\"");
        assert!(refused.is_err(), "deny_unknown_fields");
    }

    // NOTE: RFC 3986 §3.2.1: a password in a URI's userinfo is not rendered in clear text.
    #[test]
    fn every_endpoint_masks_its_userinfo_in_every_rendering() {
        let section: OidcSection = toml::from_str(
            r#"
issuer = "https://idp.example.org"
client_id = "console"
redirect_uri = "https://console.example.org/auth/callback"
authorization_endpoint = "https://u:AUTHORIZE_PW@idp.example.org/authorize"
token_endpoint = "https://u:TOKEN_PW@idp.example.org/token"
jwks_uri = "https://u:JWKS_PW@idp.example.org/jwks"
end_session_endpoint = "https://u:LOGOUT_PW@idp.example.org/logout"
revocation_endpoint = "https://u:REVOKE_PW@idp.example.org/revoke"
"#,
        )
        .expect("the section parses");
        let renderings = [
            toml::to_string(&section).expect("renders"),
            serde_json::to_string(&section).expect("renders"),
            format!("{section:?}"),
        ];
        for shown in &renderings {
            for password in [
                "AUTHORIZE_PW",
                "TOKEN_PW",
                "JWKS_PW",
                "LOGOUT_PW",
                "REVOKE_PW",
            ] {
                assert!(!shown.contains(password), "{password}: {shown}");
            }
            for kept in [
                "idp.example.org/authorize",
                "idp.example.org/token",
                "idp.example.org/jwks",
                "idp.example.org/logout",
                "idp.example.org/revoke",
            ] {
                assert!(shown.contains(kept), "{kept}: {shown}");
            }
        }
    }

    // NOTE: RFC 3986 §3.2.1: a password in a URI's userinfo is not rendered in clear text.
    #[test]
    fn the_issuer_and_the_redirection_uris_mask_their_userinfo_in_every_rendering() {
        let section: OidcSection = toml::from_str(
            r#"
issuer = "https://u:ISSUER_PW@idp.example.org/realms/r"
client_id = "console"
redirect_uri = "https://u:REDIRECT_PW@console.example.org/auth/callback"
post_logout_redirect_uri = "https://u:LOGOUT_REDIRECT_PW@console.example.org/"
"#,
        )
        .expect("the section parses");
        let renderings = [
            toml::to_string(&section).expect("renders"),
            serde_json::to_string(&section).expect("renders"),
            format!("{section:?}"),
        ];
        for (index, shown) in renderings.iter().enumerate() {
            for (key, sentinel) in [
                ("issuer", "ISSUER_PW"),
                ("redirect_uri", "REDIRECT_PW"),
                ("post_logout_redirect_uri", "LOGOUT_REDIRECT_PW"),
            ] {
                assert!(!shown.contains(sentinel), "rendering {index}: {key}");
            }
            for kept in [
                "idp.example.org/realms/r",
                "console.example.org/auth/callback",
                "console.example.org/",
            ] {
                assert!(shown.contains(kept), "rendering {index}: {kept}");
            }
        }
        assert_eq!(
            "https://u:ISSUER_PW@idp.example.org/realms/r",
            section.issuer.expose(),
            "the identifier itself is held as written"
        );
        let refused = section.check();
        assert!(
            matches!(
                refused,
                Err(ConfigError::UrlShape {
                    key: "oidc.issuer",
                    ..
                })
            ),
            "the issuer's userinfo is still refused"
        );
        let shown = refused.err().map(|error| format!("{error} {error:?}"));
        assert!(
            shown.is_some_and(|shown| !shown.contains("ISSUER_PW")),
            "the refusal names no password"
        );
    }

    #[test]
    fn the_defaults_are_a_memory_store_with_secure_cookies() {
        let section: SessionSection = toml::from_str("").expect("all defaults");
        let settings = section.check().expect("valid");
        assert!(settings.secure_cookie(), "Secure by default");
        assert_eq!(1800, settings.lifetimes().idle.as_secs(), "idle");
        assert_eq!(43_200, settings.lifetimes().absolute.as_secs(), "absolute");
    }

    #[test]
    fn an_absolute_lifetime_shorter_than_the_idle_one_is_refused() {
        let section = SessionSection {
            absolute_timeout: ferrohealth_config::units::Duration::from_secs(10),
            idle_timeout: ferrohealth_config::units::Duration::from_secs(20),
            ..SessionSection::default()
        };
        assert!(matches!(
            section.check(),
            Err(ConfigError::AbsoluteBeforeIdle)
        ));
    }

    #[test]
    fn the_sealed_store_and_its_keys_are_unknown() {
        for text in [
            "store = \"sealed\"",
            "key = \"a-sealing-key\"",
            "key_file = \"/run/secrets/session-key\"",
        ] {
            assert!(
                toml::from_str::<SessionSection>(text).is_err(),
                "{text} reads"
            );
        }
    }

    #[test]
    fn a_memory_store_refuses_a_zero_bound() {
        for (key, section) in [
            (
                "session.max_sign_ins",
                SessionSection {
                    max_sign_ins: 0,
                    ..SessionSection::default()
                },
            ),
            (
                "session.max_sessions",
                SessionSection {
                    max_sessions: 0,
                    ..SessionSection::default()
                },
            ),
        ] {
            let refused = section.check();
            assert!(
                matches!(refused, Err(ConfigError::Zero { key: named }) if named == key),
                "{key}: {refused:?}"
            );
        }
    }

    #[test]
    fn no_secret_reaches_a_debug_rendering_or_an_error() {
        let oidc = OidcSection {
            issuer: SecretUrl::new("https://idp.example.org"),
            client_id: String::from("console"),
            client_secret: Some(Secret::new("synthetic-client-secret")),
            redirect_uri: SecretUrl::new("https://console.example.org/auth/callback"),
            ..OidcSection::default()
        };
        let shown = format!("{oidc:?} {:?}", oidc.check().expect("valid"));
        assert!(!shown.contains("synthetic-client-secret"), "{shown}");
    }

    fn oidc() -> OidcSection {
        OidcSection {
            issuer: SecretUrl::new("https://idp.example.org"),
            client_id: String::from("console"),
            redirect_uri: SecretUrl::new("https://console.example.org/auth/callback"),
            ..OidcSection::default()
        }
    }

    #[test]
    fn a_provider_url_off_loopback_must_be_https() {
        assert!(oidc().check().is_ok(), "https");
        for (key, section) in [
            (
                "oidc.issuer",
                OidcSection {
                    issuer: SecretUrl::new("http://idp.example.org"),
                    ..oidc()
                },
            ),
            (
                "oidc.token_endpoint",
                OidcSection {
                    token_endpoint: Some(SecretUrl::new(String::from(
                        "http://idp.example.org/token",
                    ))),
                    ..oidc()
                },
            ),
            (
                "oidc.revocation_endpoint",
                OidcSection {
                    revocation_endpoint: Some(SecretUrl::new(String::from(
                        "http://idp.example.org/revoke",
                    ))),
                    ..oidc()
                },
            ),
        ] {
            let refused = section.check();
            assert!(
                matches!(refused, Err(ConfigError::UrlShape { key: named, .. }) if named == key),
                "{key}: {refused:?}"
            );
        }
        let loopback = OidcSection {
            issuer: SecretUrl::new("http://127.0.0.1:8081/realm"),
            jwks_uri: Some(SecretUrl::new(String::from("http://localhost:8081/jwks"))),
            ..oidc()
        };
        assert!(loopback.check().is_ok(), "plain http on loopback");
    }

    #[test]
    fn a_redirect_with_a_fragment_or_userinfo_is_refused() {
        for redirect in [
            "https://console.example.org/auth/callback#x",
            "https://u:p@console.example.org/auth/callback",
            "ftp://console.example.org/auth/callback",
        ] {
            let refused = OidcSection {
                redirect_uri: SecretUrl::new(redirect),
                ..oidc()
            }
            .check();
            assert!(
                matches!(
                    refused,
                    Err(ConfigError::UrlShape {
                        key: "oidc.redirect_uri",
                        ..
                    })
                ),
                "{redirect}: {refused:?}"
            );
        }
    }

    #[test]
    fn the_scopes_hold_openid_and_never_offline_access() {
        let refused = OidcSection {
            scopes: vec![String::from("profile")],
            ..oidc()
        }
        .check();
        assert!(matches!(refused, Err(ConfigError::NoOpenId)), "{refused:?}");
        let refused = OidcSection {
            scopes: vec![String::from(OPENID), String::from(OFFLINE_ACCESS)],
            ..oidc()
        }
        .check();
        assert!(
            matches!(refused, Err(ConfigError::OfflineAccessScope)),
            "{refused:?}"
        );
        let asked = OidcSection {
            offline_access: true,
            ..oidc()
        };
        assert!(asked.check().is_ok(), "offline_access = true asks for it");
    }

    #[test]
    fn an_oidc_section_needs_an_issuer_a_client_and_a_redirect() {
        let refused = OidcSection::default().check();
        assert!(
            matches!(refused, Err(ConfigError::Missing { key: "oidc.issuer" })),
            "{refused:?}"
        );
        let refused = OidcSection {
            issuer: SecretUrl::new("https://idp.example.org"),
            client_id: String::from("console"),
            redirect_uri: SecretUrl::new("not a url"),
            ..OidcSection::default()
        }
        .check();
        assert!(
            matches!(
                refused,
                Err(ConfigError::Url {
                    key: "oidc.redirect_uri",
                    ..
                })
            ),
            "{refused:?}"
        );
    }

    #[test]
    fn resolve_entries_name_a_host_and_its_address() {
        let section: OidcSection = toml::from_str(
            "issuer = \"https://keycloak:8443/realms/console\"\n\
             client_id = \"console\"\n\
             redirect_uri = \"https://console.example.org/auth/callback\"\n\
             resolve = [\"Keycloak = 127.0.0.1:8443\"]\n\
             [tls]\nmin_version = \"1.3\"\n",
        )
        .expect("the section reads");
        let settings = section.check().expect("valid");
        assert_eq!(
            settings.reach.resolve(),
            [(
                String::from("keycloak"),
                "127.0.0.1:8443".parse().expect("an address")
            )]
        );
        assert_eq!(
            settings.tls.min_version,
            ferrohealth_config::tls::TlsVersion::Tls13
        );
        assert!(
            toml::from_str::<OidcSection>("[tls]\nmin_version = \"1.1\"").is_err(),
            "no floor below TLS 1.2"
        );
        for (index, entry) in [
            "keycloak",
            "=127.0.0.1:8443",
            "keycloak=localhost:8443",
            "keycloak=127.0.0.1",
        ]
        .into_iter()
        .enumerate()
        {
            let refused = OidcSection {
                resolve: vec![String::from("idp.example.org=127.0.0.1:443"); index]
                    .into_iter()
                    .chain([entry.to_owned()])
                    .collect(),
                ..oidc()
            }
            .check();
            assert!(
                matches!(refused, Err(ConfigError::Resolve { index: found }) if found == index),
                "{entry}: {refused:?}"
            );
        }
    }

    /// A console's TLS builder in the tests: a configuration over no roots,
    /// or a refusal when `refuse`.
    struct Builder {
        refuse: bool,
    }

    impl ferrohealth_smart::config::TlsBuilder for Builder {
        fn build(
            &self,
            _key: &str,
            _section: &ferrohealth_config::tls::TlsClientSection,
        ) -> Result<ferrohealth_smart::client::PresentedTls, Box<dyn std::error::Error + Send + Sync>>
        {
            if self.refuse {
                return Err("the identity file could not be read".into());
            }
            let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
            Ok(ferrohealth_smart::client::PresentedTls::new(
                std::sync::Arc::new(config),
                None,
            ))
        }
    }

    #[test]
    fn the_tls_table_is_built_by_the_console_s_builder() {
        let with_identity = OidcSection {
            tls: ferrohealth_config::tls::TlsClientSection {
                client_identity: Some(Secret::new("synthetic-client-identity")),
                ..ferrohealth_config::tls::TlsClientSection::default()
            },
            ..oidc()
        };
        assert!(matches!(
            with_identity.check(),
            Err(ConfigError::TlsNotBuilt)
        ));
        let settings = with_identity
            .check_with_tls(&Builder { refuse: false })
            .expect("valid");
        assert!(settings.tls.presented.is_some(), "the built TLS is held");
        let shown = format!("{with_identity:?} {settings:?}");
        assert!(!shown.contains("synthetic-client-identity"), "{shown}");
        assert!(matches!(
            with_identity.check_with_tls(&Builder { refuse: true }),
            Err(ConfigError::TlsBuild(_))
        ));
    }

    #[test]
    fn the_retired_keys_are_unknown_keys() {
        for retired in [
            "ca_file = \"/run/ca.pem\"",
            "timeout_s = 10",
            "[tls]\nclient_certificate = \"/run/cert.pem\"",
            "[tls]\nclient_key = \"inline-private-key\"",
            "[tls]\nclient_key_file = \"/run/key.pem\"",
        ] {
            assert!(
                toml::from_str::<OidcSection>(retired).is_err(),
                "{retired} is no key of [oidc]"
            );
        }
        for retired in [
            "sign_in_timeout_s = 60",
            "idle_timeout_s = 60",
            "absolute_timeout_s = 600",
        ] {
            assert!(
                toml::from_str::<SessionSection>(retired).is_err(),
                "{retired} is no key of [session]"
            );
        }
        assert!(toml::from_str::<SessionSection>("idle_timeout = 60").is_err());
    }

    #[test]
    fn the_tls_table_still_refuses_an_unknown_key_and_reads_its_own() {
        assert!(toml::from_str::<OidcSection>("[tls]\nca_file = \"/run/ca.pem\"\n").is_err());
        let oidc: OidcSection = toml::from_str(
            "[tls]\ntrust_roots_file = \"/run/ca.pem\"\nclient_identity_file = \"/run/id.pem\"\nmin_version = \"1.2\"\n",
        )
        .expect("the shared table reads");
        assert_eq!(
            oidc.tls.trust_roots_file.as_deref(),
            Some(std::path::Path::new("/run/ca.pem"))
        );
        assert_eq!(
            oidc.tls.min_version,
            ferrohealth_config::tls::TlsVersion::Tls12
        );
    }
}
