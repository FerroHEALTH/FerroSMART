// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The resolution of the `[<lane>.credentials]` tables: HTTP Basic or the
//! client credentials grant, every rule checked and every secret read.

use std::path::Path;
use std::path::PathBuf;

use crate::jws::algorithm::Algorithm;
use ferrohealth_config::tls::TlsClientSection;
use ferrohealth_config::units::Duration;
use ferrohealth_secret::secret_url::SecretUrl;
use secrecy::SecretString;
use serde::Deserialize;
use serde::Serialize;

use crate::basic::Credential;
use crate::client::ClientAuth;
use crate::client::ClientCredentials;
use crate::client::Endpoint;
use crate::client::PresentedTls;
use crate::client::Tls;
use crate::client::assertion::AssertionKey;
use crate::client::authorization_details::AuthorizationDetails;
use crate::client::dpop::DpopKey;
use crate::client::fapi2::AliasHost;
use crate::client::fapi2::Fapi2;
use crate::client::fapi2::ProfileKind;
use crate::client::fapi2::SecurityProfile;
use crate::client::keys::KeyRing;
use crate::config::ConfigError;
use crate::config::REDACTED;
use crate::config::TlsBuilder;
use crate::config::build_tls;
use crate::config::onward;
use crate::config::read::parse_url;
use crate::config::read::secret;
use crate::config::shapes;
use crate::scope::is_scope_token;

mod problems;

/// The `[<lane>.credentials]` table: HTTP Basic with `user` and `password`,
/// or the client credentials grant under `oauth`; the two exclude each
/// other.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CredentialsSection {
    /// The Basic user-id.
    pub user: String,
    /// The Basic password, rendered redacted.
    #[serde(
        serialize_with = "shapes::redact",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub password: Option<SecretString>,
    /// The file holding the Basic password.
    pub password_file: Option<PathBuf>,
    /// The client credentials grant.
    pub oauth: Option<OauthSection>,
    /// The onward target the lane reaches on a caller's behalf, authenticating
    /// with `oauth`.
    pub onward: Option<onward::OnwardSection>,
}

/// The `[<lane>.credentials.oauth]` table.
///
/// Its rendering, serialized or `Debug`, shows `issuer` and
/// `token_endpoint` as their [`SecretUrl`] renders itself and the secrets
/// redacted, so a product can render its running configuration.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct OauthSection {
    /// The issuer whose metadata names the token endpoint; exclusive with
    /// `token_endpoint`. It renders with any userinfo masked, as
    /// [`SecretUrl`] renders itself.
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub issuer: SecretUrl,
    /// The token endpoint itself; exclusive with `issuer`. It renders with
    /// its userinfo and its query masked.
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub token_endpoint: SecretUrl,
    /// The client identifier.
    pub client_id: String,
    /// How the client authenticates.
    pub client_auth: ClientAuth,
    /// The client secret, rendered redacted.
    #[serde(
        serialize_with = "shapes::redact",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub client_secret: Option<SecretString>,
    /// The file holding the client secret.
    pub client_secret_file: Option<PathBuf>,
    /// The PEM file holding the private key of the client assertion under
    /// `private_key_jwt`, and of the actor assertion of an onward exchange
    /// (`credentials.onward.actor_assertion`) whatever the client
    /// authentication.
    pub private_key_file: Option<PathBuf>,
    /// The `kid` the assertion names; the RFC 7638 thumbprint when empty.
    pub kid: String,
    /// The algorithm the assertion is signed with; when unset, by key type,
    /// an EC key by its curve (P-256 ES256, P-384 ES384).
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub assertion_alg: Option<Algorithm>,
    /// The `scope` request parameter; empty for none.
    pub scope: String,
    /// The RFC 8707 resource indicator; empty for none.
    pub resource: String,
    /// The `audience` request parameter; empty for none.
    pub audience: String,
    /// How long before the token expires a new one is fetched.
    pub refresh_margin: Duration,
    /// How long one call to the authorization server may take.
    pub timeout: Duration,
    /// The TLS of the token endpoint connection: trust roots beside the
    /// platform's, the client identity presented over mutual TLS (RFC 8705
    /// §2) and the minimum version. The crate reads none of it: a table that
    /// names material resolves through the product's
    /// [`TlsBuilder`].
    pub tls: TlsClientSection,
    /// The PEM file of the `DPoP` key the tokens are bound to (RFC 9449).
    pub dpop_key_file: Option<PathBuf>,
    /// Whether the tokens are bound to the client certificate (RFC 8705 §3).
    pub certificate_bound: bool,
    /// The security profile: `oauth2` (the default) or `fapi2`.
    pub security_profile: ProfileKind,
    /// The hosts a FAPI 2.0 mutual-TLS alias may be on (RFC 8705 §5).
    pub mtls_alias_hosts: Vec<String>,
    /// The PEM file of the previous assertion key, published, never signing.
    pub previous_private_key_file: Option<PathBuf>,
    /// How long the previous key stays published; `0s` for as long as it
    /// is set.
    pub previous_key_overlap: Duration,
    /// The PEM file of the next assertion key, published and never signing.
    pub next_private_key_file: Option<PathBuf>,
    /// The RFC 9396 `authorization_details` JSON text; empty for none.
    pub authorization_details: String,
}

/// The outbound credential a `[<lane>.credentials]` table resolves to.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Outbound {
    /// HTTP Basic.
    Basic(Credential),
    /// The client credentials grant.
    Oauth(Box<ClientCredentials>),
}

impl CredentialsSection {
    /// Resolves the table: `None` when it names no credential.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when `user` and `oauth` are both set, a
    /// secret is set twice or not at all, neither or both of `issuer` and
    /// `token_endpoint` are set, the issuer breaks the RFC 8414 §2 URL rule,
    /// the key file cannot be read, a URL does not parse, or `resource`
    /// carries a fragment (RFC 8707 §2), and as [`OauthSection::resolve`]
    /// does for the `oauth` table.
    pub fn resolve(&self) -> Result<Option<Outbound>, ConfigError> {
        match (&self.user, &self.oauth) {
            (user, Some(_)) if !user.is_empty() => Err(ConfigError::Exclusive {
                left: "credentials.user",
                right: "credentials.oauth",
            }),
            (user, None) if user.is_empty() => {
                if self.password.is_some() || self.password_file.is_some() {
                    return Err(ConfigError::Missing {
                        key: "credentials.user",
                    });
                }
                Ok(None)
            }
            (user, None) => {
                let password = secret(
                    self.password.as_ref(),
                    self.password_file.as_deref(),
                    "credentials.password",
                )?;
                let credential = Credential::new(user.clone(), password)
                    .map_err(|source| ConfigError::Basic { source })?;
                Ok(Some(Outbound::Basic(credential)))
            }
            (_, Some(oauth)) => {
                self.check_actor_key(oauth)?;
                oauth
                    .resolve()
                    .map(|grant| Some(Outbound::Oauth(Box::new(grant))))
            }
        }
    }

    /// Resolves the table as [`CredentialsSection::resolve`] does, the
    /// `oauth` table's TLS built by `tls`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] as [`CredentialsSection::resolve`] does, and
    /// [`ConfigError::TlsBuild`] when `tls` refuses the `oauth` table's TLS.
    pub fn resolve_with_tls(&self, tls: &dyn TlsBuilder) -> Result<Option<Outbound>, ConfigError> {
        match &self.oauth {
            Some(oauth) if self.user.is_empty() => {
                self.check_actor_key(oauth)?;
                oauth
                    .resolve_with_tls(tls)
                    .map(|grant| Some(Outbound::Oauth(Box::new(grant))))
            }
            _ => self.resolve(),
        }
    }

    /// Resolves the table as [`CredentialsSection::resolve_with_tls`] does,
    /// except that an `oauth` table whose `tls` names no material presents
    /// `connection`, the configuration the product built for the connection
    /// the grant serves, as [`OauthSection::resolve_sharing_tls`] does.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] as [`CredentialsSection::resolve_with_tls`]
    /// does, and [`ConfigError::Missing`] for a mutual-TLS `client_auth` or
    /// `certificate_bound` when the configuration the grant presents carries
    /// no certificate.
    pub fn resolve_sharing_tls(
        &self,
        tls: &dyn TlsBuilder,
        connection: &PresentedTls,
    ) -> Result<Option<Outbound>, ConfigError> {
        match &self.oauth {
            Some(oauth) if self.user.is_empty() => {
                self.check_actor_key(oauth)?;
                oauth
                    .resolve_sharing_tls(tls, connection)
                    .map(|grant| Some(Outbound::Oauth(Box::new(grant))))
            }
            _ => self.resolve(),
        }
    }

    /// Refuses a `private_key_file` that signs nothing: neither the client
    /// assertion of `private_key_jwt` nor the actor assertion the onward
    /// table asks for.
    pub(crate) fn check_actor_key(&self, oauth: &OauthSection) -> Result<(), ConfigError> {
        let actor = self
            .onward
            .as_ref()
            .is_some_and(|onward| onward.actor_assertion);
        if oauth.private_key_file.is_some()
            && oauth.client_auth != ClientAuth::PrivateKeyJwt
            && !actor
        {
            return Err(ConfigError::Unused {
                key: "credentials.oauth.private_key_file",
                needs: "client_auth = \"private_key_jwt\" or credentials.onward.actor_assertion = true",
            });
        }
        Ok(())
    }
}

impl OauthSection {
    /// Resolves the grant.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] as [`CredentialsSection::resolve`] does, and
    /// for a client certificate file without its key file or the reverse,
    /// a mutual-TLS `client_auth` without a client certificate, TLS
    /// and material that is no PEM (with the `fetch` feature).
    pub fn resolve(&self) -> Result<ClientCredentials, ConfigError> {
        if self.tls.names_material() {
            return Err(ConfigError::TlsNotBuilt {
                key: "credentials.oauth.tls",
            });
        }
        self.resolve_presenting(None)
    }

    /// Resolves the grant over the TLS configuration `tls` builds from the
    /// table's `tls` keys, such as with `ferrohealth-server`'s `TlsClient`,
    /// so the token endpoint connection presents its client certificate (RFC
    /// 8705 §2), a `certificate_bound` grant binds its tokens to it (RFC 8705
    /// §3), and the minimum version holds.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] as [`OauthSection::resolve`] does,
    /// [`ConfigError::TlsBuild`] when `tls` refuses the table, and
    /// [`ConfigError::Missing`] for a mutual-TLS `client_auth` or
    /// `certificate_bound` when the built configuration presents no
    /// certificate.
    pub fn resolve_with_tls(&self, tls: &dyn TlsBuilder) -> Result<ClientCredentials, ConfigError> {
        let presented = build_tls(tls, "credentials.oauth.tls", &self.tls)?;
        self.resolve_presenting(Some(presented))
    }

    /// Resolves the grant over the TLS configuration of the connection it
    /// serves: when the table's `tls` names no material, the token endpoint
    /// connection presents `connection`, the configuration the product built
    /// for that connection, with its trust roots and its client certificate;
    /// when the table's `tls` names material, it resolves as
    /// [`OauthSection::resolve_with_tls`] does.
    ///
    /// A mutual-TLS `client_auth` then authenticates with the connection's
    /// certificate (RFC 8705 §2), and a `certificate_bound` grant binds its
    /// tokens to the certificate the connection presents to the resource
    /// server (RFC 8705 §3).
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] as [`OauthSection::resolve_with_tls`] does,
    /// with [`ConfigError::Missing`] for a mutual-TLS `client_auth` or
    /// `certificate_bound` when `connection` presents no certificate.
    pub fn resolve_sharing_tls(
        &self,
        tls: &dyn TlsBuilder,
        connection: &PresentedTls,
    ) -> Result<ClientCredentials, ConfigError> {
        if self.tls.names_material() {
            return self.resolve_with_tls(tls);
        }
        // NOTE: RFC 8705 §3, a bound token is used over the connection whose
        // certificate was presented at the token endpoint, so the grant presents it.
        self.resolve_presenting(Some(connection.clone()))
    }

    /// Resolves the grant, over the product's built TLS configuration when
    /// `presented` carries one.
    fn resolve_presenting(
        &self,
        presented: Option<PresentedTls>,
    ) -> Result<ClientCredentials, ConfigError> {
        let endpoint = match (self.issuer.is_empty(), self.token_endpoint.is_empty()) {
            (false, false) => {
                return Err(ConfigError::Exclusive {
                    left: "credentials.oauth.issuer",
                    right: "credentials.oauth.token_endpoint",
                });
            }
            (true, true) => {
                return Err(ConfigError::Missing {
                    key: "credentials.oauth.issuer or credentials.oauth.token_endpoint",
                });
            }
            (false, true) => {
                crate::metadata::issuer_url(self.issuer.expose())
                    .map_err(|source| ConfigError::OauthIssuer { source })?;
                Endpoint::Issuer(self.issuer.expose().to_owned())
            }
            (true, false) => {
                let url = parse_url(
                    self.token_endpoint.expose(),
                    "credentials.oauth.token_endpoint",
                )?;
                if let Some(part) = crate::client::forbidden_part(&url) {
                    return Err(ConfigError::TokenEndpoint {
                        key: "credentials.oauth.token_endpoint",
                        part,
                    });
                }
                Endpoint::Token(url)
            }
        };
        if self.client_id.is_empty() {
            return Err(ConfigError::Missing {
                key: "credentials.oauth.client_id",
            });
        }
        let tls = Tls {
            presented,
            min_version: self.tls.min_version,
        };
        let mut grant = match self.client_auth {
            ClientAuth::ClientSecretBasic | ClientAuth::ClientSecretPost => {
                let client_secret = secret(
                    self.client_secret.as_ref(),
                    self.client_secret_file.as_deref(),
                    "credentials.oauth.client_secret",
                )?;
                let mut grant =
                    ClientCredentials::new(endpoint, self.client_id.clone(), client_secret);
                grant.client_auth = self.client_auth;
                grant
            }
            ClientAuth::PrivateKeyJwt => self.private_key_jwt(endpoint)?,
            ClientAuth::TlsClientAuth | ClientAuth::SelfSignedTlsClientAuth => {
                self.mutual_tls_grant(endpoint, &tls)?
            }
        };
        // NOTE: RFC 8693 §2.1, the actor token is independent of the client
        // authentication, so the key that signs it is read whatever the method.
        if self.client_auth != ClientAuth::PrivateKeyJwt {
            grant.assertion_keys = self.assertion_ring()?;
        }
        grant.tls = tls;
        if !self.scope.is_empty() {
            if let Some(bad) = self.scope.split(' ').find(|token| !is_scope_token(token)) {
                return Err(ConfigError::Scope {
                    scope: bad.to_owned(),
                });
            }
            grant.scope = Some(self.scope.clone());
        }
        if !self.resource.is_empty() {
            let resource = parse_url(&self.resource, "credentials.oauth.resource")?;
            // NOTE: RFC 8707 §2, the resource "MUST NOT include a fragment
            // component"; an absolute URI is what `Url` parses at all.
            if resource.fragment().is_some() {
                return Err(ConfigError::Fragment {
                    key: "credentials.oauth.resource",
                });
            }
            grant.resource = Some(resource);
        }
        if !self.audience.is_empty() {
            grant.audience = Some(self.audience.clone());
        }
        grant.refresh_margin = self.refresh_margin.get();
        grant.timeout = self.timeout.get();
        self.finish(self.bind(grant)?)
    }

    /// Returns the `private_key_jwt` grant at `endpoint`, signing with the
    /// key ring of `private_key_file` and its previous and next keys.
    fn private_key_jwt(&self, endpoint: Endpoint) -> Result<ClientCredentials, ConfigError> {
        let ring = self.assertion_ring()?.ok_or(ConfigError::Missing {
            key: "credentials.oauth.private_key_file",
        })?;
        Ok(ClientCredentials::with_key_ring(
            endpoint,
            self.client_id.clone(),
            ring,
        ))
    }

    /// Returns the key ring of `private_key_file` with its previous and next
    /// keys, or `None` when the table names no `private_key_file`.
    fn assertion_ring(&self) -> Result<Option<std::sync::Arc<KeyRing>>, ConfigError> {
        let Some(path) = self.private_key_file.as_deref() else {
            return Ok(None);
        };
        let pem = std::fs::read(path).map_err(|source| ConfigError::SecretFile {
            path: path.to_path_buf(),
            source,
        })?;
        let kid = (!self.kid.is_empty()).then(|| self.kid.clone());
        let key = AssertionKey::from_pem(&pem, self.assertion_alg, kid)
            .map_err(|source| ConfigError::Key { source })?;
        Ok(Some(std::sync::Arc::new(self.ring(key)?)))
    }

    /// Returns `grant` with the table's `authorization_details` and security
    /// profile, checked as [`ClientCredentials::validate`] checks it.
    fn finish(&self, mut grant: ClientCredentials) -> Result<ClientCredentials, ConfigError> {
        if !self.authorization_details.is_empty() {
            grant.authorization_details = Some(
                AuthorizationDetails::parse(&self.authorization_details)
                    .map_err(|source| ConfigError::AuthorizationDetails { source })?,
            );
        }
        grant.profile = self.profile()?;
        grant.validate().map_err(|source| ConfigError::Grant {
            source: Box::new(source),
        })?;
        Ok(grant)
    }

    /// Returns the key ring `current` signs in, with the previous and next
    /// keys the table names published beside it.
    fn ring(&self, current: AssertionKey) -> Result<KeyRing, ConfigError> {
        let read = |path: &Path| -> Result<AssertionKey, ConfigError> {
            let pem = std::fs::read(path).map_err(|source| ConfigError::SecretFile {
                path: path.to_path_buf(),
                source,
            })?;
            AssertionKey::from_pem(&pem, self.assertion_alg, None)
                .map_err(|source| ConfigError::Key { source })
        };
        let mut ring = KeyRing::new(current);
        if let Some(path) = &self.previous_private_key_file {
            let previous = read(path)?;
            ring = if self.previous_key_overlap.is_zero() {
                ring.with_previous_until_removed(previous)
            } else {
                ring.with_previous_for(previous, self.previous_key_overlap.get())
            }
            .map_err(|source| ConfigError::KeyRing { source })?;
        }
        if let Some(path) = &self.next_private_key_file {
            ring = ring
                .with_next(read(path)?)
                .map_err(|source| ConfigError::KeyRing { source })?;
        }
        Ok(ring)
    }

    /// Returns the security profile the table names, with its alias hosts.
    fn profile(&self) -> Result<SecurityProfile, ConfigError> {
        match self.security_profile {
            ProfileKind::OAuth2 if self.mtls_alias_hosts.is_empty() => Ok(SecurityProfile::OAuth2),
            ProfileKind::OAuth2 => Err(ConfigError::Missing {
                key: "credentials.oauth.security_profile = \"fapi2\", which mtls_alias_hosts needs",
            }),
            ProfileKind::Fapi2 => {
                let mut profile = Fapi2::new();
                for host in &self.mtls_alias_hosts {
                    let host = AliasHost::parse(host)
                        .map_err(|_invalid| ConfigError::AliasHost { host: host.clone() })?;
                    profile = profile.with_alias_host(host);
                }
                Ok(SecurityProfile::Fapi2(profile))
            }
        }
    }

    /// Returns `grant` with the token binding the table names: a `DPoP` key
    /// (RFC 9449) or the client certificate (RFC 8705 §3), never both.
    fn bind(&self, grant: ClientCredentials) -> Result<ClientCredentials, ConfigError> {
        match (&self.dpop_key_file, self.certificate_bound) {
            (Some(_), true) => Err(ConfigError::Exclusive {
                left: "credentials.oauth.dpop_key_file",
                right: "credentials.oauth.certificate_bound",
            }),
            (Some(path), false) => {
                let pem = std::fs::read(path).map_err(|source| ConfigError::SecretFile {
                    path: path.clone(),
                    source,
                })?;
                let key =
                    DpopKey::from_pem(&pem).map_err(|source| ConfigError::DpopKey { source })?;
                Ok(grant.with_dpop(std::sync::Arc::new(key)))
            }
            (None, true) if !grant.tls.presents_identity() => Err(ConfigError::Missing {
                key: "the client certificate of the TLS configuration built from credentials.oauth.tls, which certificate_bound names",
            }),
            (None, true) => Ok(grant.with_certificate_binding()),
            (None, false) => Ok(grant),
        }
    }

    /// Returns the grant of a mutual-TLS `client_auth` (RFC 8705 §2) over
    /// the client certificate `tls` presents.
    fn mutual_tls_grant(
        &self,
        endpoint: Endpoint,
        tls: &Tls,
    ) -> Result<ClientCredentials, ConfigError> {
        let self_signed = self.client_auth == ClientAuth::SelfSignedTlsClientAuth;
        match &tls.presented {
            Some(presented) if presented.certificate().is_some() => {
                Ok(ClientCredentials::with_presented_tls(
                    endpoint,
                    self.client_id.clone(),
                    presented.clone(),
                    self_signed,
                ))
            }
            _ => Err(ConfigError::Missing {
                key: "the client certificate of the TLS configuration built from credentials.oauth.tls",
            }),
        }
    }
}

impl Default for OauthSection {
    fn default() -> Self {
        Self {
            issuer: SecretUrl::default(),
            token_endpoint: SecretUrl::default(),
            client_id: String::new(),
            client_auth: ClientAuth::ClientSecretBasic,
            client_secret: None,
            client_secret_file: None,
            private_key_file: None,
            kid: String::new(),
            assertion_alg: None,
            scope: String::new(),
            resource: String::new(),
            audience: String::new(),
            refresh_margin: Duration::from_secs(30),
            timeout: Duration::from_secs(10),
            tls: TlsClientSection::default(),
            dpop_key_file: None,
            certificate_bound: false,
            security_profile: ProfileKind::OAuth2,
            mtls_alias_hosts: Vec::new(),
            previous_private_key_file: None,
            previous_key_overlap: Duration::ZERO,
            next_private_key_file: None,
            authorization_details: String::new(),
        }
    }
}

impl std::fmt::Debug for OauthSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OauthSection")
            .field("issuer", &self.issuer)
            .field("token_endpoint", &self.token_endpoint)
            .field("client_id", &self.client_id)
            .field("client_auth", &self.client_auth)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_set| REDACTED),
            )
            .field("client_secret_file", &self.client_secret_file)
            .field("private_key_file", &self.private_key_file)
            .field("kid", &self.kid)
            .field("scope", &self.scope)
            .field("resource", &self.resource)
            .field("audience", &self.audience)
            .field("tls", &self.tls)
            .field("dpop_key_file", &self.dpop_key_file)
            .field("certificate_bound", &self.certificate_bound)
            .field("security_profile", &self.security_profile)
            .field("mtls_alias_hosts", &self.mtls_alias_hosts)
            .field("previous_private_key_file", &self.previous_private_key_file)
            .field("next_private_key_file", &self.next_private_key_file)
            .finish_non_exhaustive()
    }
}

// The exhaustive pattern makes a new field a compile error here until it is compared.
impl PartialEq for CredentialsSection {
    fn eq(&self, other: &Self) -> bool {
        let Self {
            user,
            password,
            password_file,
            oauth,
            onward,
        } = self;
        shapes::same_secret(password.as_ref(), other.password.as_ref())
            && *user == other.user
            && *password_file == other.password_file
            && *oauth == other.oauth
            && *onward == other.onward
    }
}

impl Eq for CredentialsSection {}

// The exhaustive pattern makes a new field a compile error here until it is compared.
impl PartialEq for OauthSection {
    fn eq(&self, other: &Self) -> bool {
        let Self {
            issuer,
            token_endpoint,
            client_id,
            client_auth,
            client_secret,
            client_secret_file,
            private_key_file,
            kid,
            assertion_alg,
            scope,
            resource,
            audience,
            refresh_margin,
            timeout,
            tls,
            dpop_key_file,
            certificate_bound,
            security_profile,
            mtls_alias_hosts,
            previous_private_key_file,
            previous_key_overlap,
            next_private_key_file,
            authorization_details,
        } = self;
        shapes::same_secret(client_secret.as_ref(), other.client_secret.as_ref())
            && *issuer == other.issuer
            && *token_endpoint == other.token_endpoint
            && *client_id == other.client_id
            && *client_auth == other.client_auth
            && *client_secret_file == other.client_secret_file
            && *private_key_file == other.private_key_file
            && *kid == other.kid
            && *assertion_alg == other.assertion_alg
            && *scope == other.scope
            && *resource == other.resource
            && *audience == other.audience
            && *refresh_margin == other.refresh_margin
            && *timeout == other.timeout
            && *tls == other.tls
            && *dpop_key_file == other.dpop_key_file
            && *certificate_bound == other.certificate_bound
            && *security_profile == other.security_profile
            && *mtls_alias_hosts == other.mtls_alias_hosts
            && *previous_private_key_file == other.previous_private_key_file
            && *previous_key_overlap == other.previous_key_overlap
            && *next_private_key_file == other.next_private_key_file
            && *authorization_details == other.authorization_details
    }
}

impl Eq for OauthSection {}
