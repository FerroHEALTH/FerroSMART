// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The upstream identity providers a person logs in at, for login only.
//!
//! Each is a named `[[ferrosmart.upstream]]` entry with the table of its
//! protocol, `oidc`, `saml` or `openid4vp`, whichever is present
//! (`docs/architecture.md` §13.10). OpenID Connect is reached through
//! `ferrohealth-smart`'s relying party, SAML 2.0 through [`saml`] and the
//! EUDI Wallet through [`wallet`]; each protocol is a [`Protocol`]
//! variant and a table of its own, with no change to the entry or to the
//! login flow. An OpenID Connect entry may name a [`preset::Preset`], whose
//! data file fills the keys its table leaves out.
//!
//! What FerroSMART takes from a provider's login is configured per entry
//! too: the claim that holds the user's `fhirUser` and the claims that hold
//! the user's roles. The user's FerroSMART `sub` is pairwise per upstream
//! issuer (13.6 item 9).

pub mod preset;
pub mod registration;
pub mod saml;
pub mod wallet;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use ferrohealth_smart::client::assertion::AssertionKey;
use ferrohealth_smart::metadata::Http;
use ferrohealth_smart::oidc::{OidcError, Provider, RelyingParty};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use url::Url;

/// How long one call to the upstream provider may take. No specification
/// governs the value: our own design.
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(10);

/// One `[[ferrosmart.upstream]]` entry: a provider by name, with the table
/// of its protocol.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamSection {
    /// The provider's name, which a client's `upstreams` list names; letters,
    /// digits and `-`.
    pub name: String,
    /// The words the chooser page shows for the provider; its name when
    /// empty.
    pub label: String,
    /// The vendor whose tested setup fills the keys the `oidc` table leaves
    /// out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<preset::Preset>,
    /// `[ferrosmart.upstream.oidc]`: the OpenID Connect settings; the
    /// provider speaks OpenID Connect when it is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc: Option<OidcSection>,
    /// `[ferrosmart.upstream.saml]`: the SAML 2.0 settings; the provider
    /// speaks SAML 2.0 when it is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saml: Option<saml::SamlSection>,
    /// `[ferrosmart.upstream.openid4vp]`: the EUDI Wallet verifier; a person
    /// logs in by presenting their PID when it is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openid4vp: Option<wallet::WalletSection>,
    /// `[ferrosmart.upstream.assurance]`: the eIDAS level each of the
    /// provider's values stands for, and its minimum.
    pub assurance: crate::assurance::AssuranceSection,
}

impl UpstreamSection {
    /// Returns the defaults of the entry's preset, none when it names
    /// none.
    ///
    /// # Errors
    /// Returns [`preset::PresetError`] when the preset's file does not
    /// read, which the tests rule out.
    pub fn defaults(&self) -> Result<preset::Defaults, preset::PresetError> {
        self.preset
            .map_or_else(|| Ok(preset::Defaults::default()), preset::Preset::defaults)
    }

    /// Returns the issuer a person's pairwise `sub` is derived under, exactly
    /// as configured: the OpenID Provider's issuer identifier, the SAML
    /// identity provider's entity ID, or the wallet's first credential type;
    /// none unless the entry has exactly one protocol table.
    #[must_use]
    pub fn issuer(&self) -> Option<&str> {
        match (&self.oidc, &self.saml, &self.openid4vp) {
            (Some(oidc), None, None) => Some(&oidc.issuer),
            (None, Some(saml), None) => Some(&saml.entity_id),
            (None, None, Some(wallet)) => wallet.issuer(),
            _ => None,
        }
    }
}

/// `[ferrosmart.upstream.oidc]`. A key left unset takes the entry's preset,
/// then the built-in default ([`OidcSection::effective`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct OidcSection {
    /// The provider's issuer identifier, whose discovery document names its
    /// endpoints (OpenID Connect Discovery 1.0 §4).
    pub issuer: String,
    /// The client FerroSMART is registered as at the provider.
    pub client_id: String,
    /// The scopes FerroSMART asks the provider for, `openid` among them;
    /// `["openid"]` by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    /// The dotted claim of the ID Token that holds the user's `fhirUser`
    /// URL; empty when the provider carries none, and FerroSMART then
    /// offers no `fhirUser` scope. Empty by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fhir_user_claim: Option<String>,
    /// The dotted claims of the ID Token that hold the user's roles; the
    /// claims RFC 9068 §2.2.3.1 names by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_claims: Option<Vec<String>>,
    /// The audiences an ID Token may name beside FerroSMART's client id, which
    /// FerroSMART trusts (OpenID Connect Core 1.0 §3.1.3.7 item 3), such as
    /// the project a provider adds; none by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_audiences: Option<Vec<String>>,
    /// `[ferrosmart.upstream.oidc.private_key_jwt]`: FerroSMART authenticates
    /// with a JWT the current key of its own assertion ring signs (OpenID
    /// Connect Core 1.0 §9), the method taken when no table names one;
    /// exclusive with `client_secret_basic`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_jwt: Option<PrivateKeyJwtSection>,
    /// `[ferrosmart.upstream.oidc.client_secret_basic]`: FerroSMART
    /// authenticates with a client secret as HTTP Basic (RFC 6749 §2.3.1,
    /// OpenID Connect Core 1.0 §9), for a provider that offers no
    /// `private_key_jwt`; exclusive with `private_key_jwt`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_basic: Option<ClientSecretBasicSection>,
}

/// The algorithm of `private_key_jwt` when neither the entry nor its preset
/// names one (RFC 7518 §3.1).
pub const DEFAULT_ALGORITHM: &str = "RS256";

/// The values an OpenID Connect entry runs on, once its preset and the
/// built-in defaults filled what its table leaves out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    /// The scopes asked for.
    pub scopes: Vec<String>,
    /// The claim of `fhirUser`; empty for none.
    pub fhir_user_claim: String,
    /// The claims of the roles.
    pub role_claims: Vec<String>,
    /// The audiences trusted beside the client id.
    pub trusted_audiences: Vec<String>,
    /// The algorithm of `private_key_jwt`.
    pub algorithm: String,
}

impl OidcSection {
    /// Returns the values the entry runs on: each key the table sets, else
    /// the one `defaults` sets, else the built-in default.
    #[must_use]
    pub fn effective(&self, defaults: &preset::Defaults) -> Effective {
        let pick = |own: &Option<Vec<String>>, preset: &Option<Vec<String>>| {
            own.as_ref().or(preset.as_ref()).cloned()
        };
        Effective {
            scopes: pick(&self.scopes, &defaults.scopes)
                .unwrap_or_else(|| vec![String::from(ferrohealth_smart::oidc::OPENID)]),
            fhir_user_claim: self
                .fhir_user_claim
                .as_ref()
                .or(defaults.fhir_user_claim.as_ref())
                .cloned()
                .unwrap_or_default(),
            role_claims: pick(&self.role_claims, &defaults.role_claims)
                .unwrap_or_else(ferrohealth_smart::roles::default_claims),
            trusted_audiences: pick(&self.trusted_audiences, &defaults.trusted_audiences)
                .unwrap_or_default(),
            algorithm: self
                .private_key_jwt
                .as_ref()
                .and_then(|jwt| jwt.algorithm.as_ref())
                .or(defaults.private_key_jwt.algorithm.as_ref())
                .cloned()
                .unwrap_or_else(|| String::from(DEFAULT_ALGORITHM)),
        }
    }
}

/// `[ferrosmart.upstream.oidc.client_secret_basic]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientSecretBasicSection {
    /// The client secret the provider issued; exclusive with `secret_file`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<ferrohealth_secret::secret::Secret>,
    /// The file holding the client secret.
    pub secret_file: Option<PathBuf>,
}

/// `[ferrosmart.upstream.oidc.private_key_jwt]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivateKeyJwtSection {
    /// The algorithm the provider's registration names, one the assertion
    /// keys sign with (RFC 7518 §3.1); the preset's, else `RS256`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    /// `[ferrosmart.upstream.oidc.private_key_jwt.keys]`: the ring of assertion
    /// keys, read as `[ferrosmart.keys]` is and never one of its keys, so a
    /// key that signs assertions never signs a token (RFC 8725 §3.12).
    pub keys: crate::config::KeysSection,
    /// The PEM X.509 certificate of the current key, for a provider that
    /// knows the key by its certificate; each assertion then names it by
    /// `x5t#S256` (RFC 7515 §4.1.8).
    pub certificate_file: Option<PathBuf>,
}

/// How FerroSMART authenticates at the provider's token and revocation
/// endpoints (OpenID Connect Core 1.0 §9).
#[derive(Debug, Clone)]
pub enum Authentication {
    /// A JWT the assertion ring's current key signs (`private_key_jwt`),
    /// the ring published at [`crate::discovery::UPSTREAM_JWKS_ROUTE`].
    PrivateKeyJwt(AssertionKeys),
    /// A client secret sent as HTTP Basic (`client_secret_basic`, RFC 6749
    /// §2.3.1), which redacts itself.
    ClientSecretBasic(SecretString),
}

impl Authentication {
    /// Returns the method's name as provider metadata lists it
    /// (`token_endpoint_auth_methods_supported`, RFC 8414 §2).
    #[must_use]
    pub const fn method(&self) -> &'static str {
        match self {
            Self::PrivateKeyJwt(_) => "private_key_jwt",
            Self::ClientSecretBasic(_) => "client_secret_basic",
        }
    }
}

/// The assertion keys of `private_key_jwt`.
#[derive(Debug, Clone)]
pub struct AssertionKeys {
    /// The current key, at the registration's algorithm and naming its
    /// certificate when one is configured.
    pub signer: Box<AssertionKey>,
    /// The ring the key is current in.
    pub ring: Arc<ferrohealth_smart::client::keys::KeyRing>,
}

/// Why a provider's login could not be set up.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// The provider's metadata could not be read or is not usable.
    #[error("the provider's metadata cannot be used")]
    Oidc(#[from] OidcError),
    /// The provider's token endpoint does not list the client
    /// authentication the entry names.
    #[error(
        "the provider's token endpoint does not list `{method}` among its client authentication methods"
    )]
    Method {
        /// The method the entry names.
        method: &'static str,
    },
    /// A SAML provider's metadata cannot be read or used.
    #[error("the SAML provider's metadata cannot be used")]
    Saml(#[from] saml::SamlError),
    /// A SAML provider is configured without `[ferrosmart.saml]`.
    #[error("a SAML provider needs `[ferrosmart.saml]`")]
    NoServiceProvider,
    /// The wallet verifier cannot be set up.
    #[error("the wallet verifier cannot be set up")]
    Wallet(#[from] wallet::WalletError),
}

/// An upstream provider, resolved.
#[derive(Debug, Clone)]
pub struct Upstream {
    /// Its name.
    pub name: String,
    /// The words the chooser page shows.
    pub label: String,
    /// The claim of `fhirUser`, if any.
    pub fhir_user_claim: Option<String>,
    /// The claims of the roles.
    pub role_claims: Vec<String>,
    /// The eIDAS level of each of its values, and the minimum a login at it
    /// reaches.
    pub assurance: crate::assurance::Assurance,
    /// The protocol, with its settings.
    pub protocol: Protocol,
}

/// The protocol of a resolved provider, with its settings: the seam a
/// second protocol joins at.
#[derive(Debug, Clone)]
pub enum Protocol {
    /// OpenID Connect.
    Oidc(OidcUpstream),
    /// SAML 2.0.
    Saml(saml::SamlUpstream),
    /// The EUDI Wallet, by OpenID4VP.
    Wallet(wallet::WalletUpstream),
}

impl Upstream {
    /// Returns the provider's issuer, which a person's pairwise `sub` is
    /// derived under: the OpenID Provider's issuer identifier, or the SAML
    /// identity provider's entity ID.
    #[must_use]
    pub fn issuer(&self) -> &str {
        match &self.protocol {
            Protocol::Oidc(oidc) => &oidc.issuer,
            Protocol::Saml(saml) => &saml.entity_id,
            Protocol::Wallet(wallet) => &wallet.issuer,
        }
    }

    /// Returns the JWK Set of the keys FerroSMART authenticates to the
    /// provider with, when it authenticates by a signed assertion.
    #[must_use]
    pub fn assertion_keys(&self) -> Option<serde_json::Value> {
        match &self.protocol {
            Protocol::Oidc(oidc) => match &oidc.authentication {
                Authentication::PrivateKeyJwt(keys) => Some(keys.ring.published()),
                Authentication::ClientSecretBasic(_) => None,
            },
            Protocol::Saml(_) | Protocol::Wallet(_) => None,
        }
    }
}

/// An OpenID Connect provider, resolved.
#[derive(Debug, Clone)]
pub struct OidcUpstream {
    /// The issuer identifier.
    pub issuer: String,
    /// The client id at the provider.
    pub client_id: String,
    /// How FerroSMART authenticates at the provider.
    pub authentication: Authentication,
    /// The scopes asked for.
    pub scopes: Vec<String>,
    /// The audiences trusted beside the client id.
    pub trusted_audiences: Vec<String>,
}

impl OidcUpstream {
    /// Discovers the provider and returns the relying party whose
    /// redirection endpoint is `callback`.
    ///
    /// # Errors
    /// Returns [`UpstreamError::Oidc`] when the provider's metadata cannot
    /// be read or names no usable endpoints, and [`UpstreamError::Method`]
    /// when its token endpoint does not list the entry's client
    /// authentication.
    pub async fn relying_party(&self, callback: Url) -> Result<RelyingParty, UpstreamError> {
        let http = Http::new(UPSTREAM_TIMEOUT).map_err(OidcError::from)?;
        let metadata = http.discover(&self.issuer).await.map_err(OidcError::from)?;
        // NOTE: RFC 8414 §2, token_endpoint_auth_methods_supported, client_secret_basic
        // when absent; a method the provider does not list is refused at start.
        let method = self.authentication.method();
        if !metadata
            .token_endpoint_auth_methods()
            .iter()
            .any(|listed| listed == method)
        {
            return Err(UpstreamError::Method { method });
        }
        let provider = Provider::from_metadata(&metadata)?;
        let party = RelyingParty::new(http, provider, self.client_id.clone(), callback)
            .with_scopes(self.scopes.iter().map(String::as_str))
            .with_trusted_audiences(self.trusted_audiences.iter().cloned());
        Ok(match &self.authentication {
            Authentication::PrivateKeyJwt(keys) => {
                party.with_private_key_jwt((*keys.signer).clone())
            }
            Authentication::ClientSecretBasic(secret) => party.with_client_secret(secret.clone()),
        })
    }
}

/// What a provider's login says about the person, whatever its protocol:
/// what the steps after the login read.
#[derive(Clone, Serialize, Deserialize)]
pub struct Identity {
    /// The provider's issuer identifier or entity ID.
    pub issuer: String,
    /// The person's identifier at the provider.
    pub subject: String,
    /// Their full name, when the provider gives one.
    pub name: Option<String>,
    /// The name they go by at the provider, when it gives one.
    pub preferred_username: Option<String>,
    /// The name a page greets them by: `name`, else `preferred_username`,
    /// each trimmed and skipped when empty.
    pub display_name: Option<String>,
    /// Every claim the login yields, by name: an ID Token's, or those a
    /// SAML provider's `claims` table maps from its attributes.
    pub claims: serde_json::Map<String, serde_json::Value>,
    /// The provider's session `sid`, which its logout names; none for a
    /// SAML login, whose Single Logout FerroSMART does not take.
    pub session: Option<String>,
    /// When the person authenticated, in seconds since the epoch, when the
    /// provider says.
    pub auth_time: Option<i64>,
    /// How they authenticated, in the provider's words: an ID Token's
    /// `acr`, a SAML assertion's `AuthnContextClassRef`.
    pub acr: Option<String>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// Returns what the ID Token `claims` say.
    #[must_use]
    pub fn from_id_token(claims: &ferrohealth_smart::oidc::IdTokenClaims) -> Self {
        Self {
            issuer: claims.issuer.clone(),
            subject: claims.subject.clone(),
            name: claims.name.clone(),
            preferred_username: claims.preferred_username.clone(),
            display_name: claims.display_name().map(str::to_owned),
            claims: claims.other.clone(),
            session: claims
                .other
                .get("sid")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            auth_time: claims
                .other
                .get("auth_time")
                .and_then(serde_json::Value::as_i64),
            acr: claims
                .other
                .get("acr")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        }
    }
}

/// Returns the FerroSMART `sub` of the user `subject` of the provider
/// `issuer`.
///
/// It is the SHA-256 of the two, base64url, so two providers never
/// collide and the upstream identifier never reaches a resource server
/// (`docs/architecture.md` §13.6 item 9, our own design; OpenID Connect
/// Core 1.0 §8.1 describes pairwise identifiers).
#[must_use]
pub fn pairwise(issuer: &str, subject: &str) -> String {
    let mut context = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    context.update(issuer.as_bytes());
    context.update(&[0]);
    context.update(subject.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(context.finish().as_ref())
}

/// How a person logs in at one provider: the protocol's own client.
#[derive(Debug)]
pub enum Login {
    /// The OpenID Connect relying party.
    Oidc(Box<RelyingParty>),
    /// The SAML 2.0 service provider's login at one identity provider.
    Saml(Box<saml::SamlLogin>),
    /// The wallet verifier.
    Wallet(Box<wallet::WalletLogin>),
}

/// A provider people log in at: its settings and its login.
#[derive(Debug)]
pub struct LoginProvider {
    /// The settings.
    upstream: Upstream,
    /// The login.
    login: Login,
}

impl LoginProvider {
    /// Returns the provider's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.upstream.name
    }

    /// Returns the provider's settings.
    #[must_use]
    pub const fn upstream(&self) -> &Upstream {
        &self.upstream
    }

    /// Returns the OpenID Connect relying party, when the provider speaks
    /// OpenID Connect.
    #[must_use]
    pub fn oidc(&self) -> Option<&RelyingParty> {
        match &self.login {
            Login::Oidc(party) => Some(party),
            Login::Saml(_) | Login::Wallet(_) => None,
        }
    }

    /// Returns the SAML login, when the provider speaks SAML 2.0.
    #[must_use]
    pub fn saml(&self) -> Option<&saml::SamlLogin> {
        match &self.login {
            Login::Saml(login) => Some(login),
            Login::Oidc(_) | Login::Wallet(_) => None,
        }
    }

    /// Returns the wallet login, when the provider is the EUDI Wallet.
    #[must_use]
    pub fn wallet(&self) -> Option<&wallet::WalletLogin> {
        match &self.login {
            Login::Wallet(login) => Some(login),
            Login::Oidc(_) | Login::Saml(_) => None,
        }
    }

    /// Returns where the browser goes to log in: the OpenID Provider's
    /// authorization endpoint, or the SAML provider's single sign-on
    /// location.
    #[must_use]
    pub fn login_endpoint(&self) -> Option<Url> {
        match &self.login {
            Login::Oidc(party) => Some(party.provider().authorization_endpoint().clone()),
            Login::Saml(login) => login.single_sign_on(),
            Login::Wallet(login) => Some(login.endpoint().clone()),
        }
    }

    /// Returns the origins the provider's own pages are served from: its
    /// issuer's, and its end-session endpoint's or its single sign-on
    /// location's.
    #[must_use]
    pub fn origins(&self) -> Vec<String> {
        let issuer = Url::parse(self.upstream.issuer()).ok();
        let pages = match &self.login {
            Login::Oidc(party) => party.provider().end_session_endpoint().cloned(),
            Login::Saml(login) => login.single_sign_on(),
            Login::Wallet(_) => None,
        };
        origins_of(issuer.iter().chain(pages.iter()))
    }
}

/// Returns the origins of `urls`, each once, in their order, leaving out an
/// opaque one, as a page's `form-action` or `frame-ancestors` names them.
pub fn origins_of<'a>(urls: impl Iterator<Item = &'a Url>) -> Vec<String> {
    let mut origins: Vec<String> = Vec::new();
    for url in urls {
        let origin = url.origin();
        if origin.is_tuple() && !origins.contains(&origin.ascii_serialization()) {
            origins.push(origin.ascii_serialization());
        }
    }
    origins
}

/// The providers people log in at, in the order the configuration names
/// them.
#[derive(Debug, Default)]
pub struct Providers {
    /// The providers.
    providers: Vec<LoginProvider>,
}

impl Providers {
    /// Discovers every provider `upstreams` names and returns their logins,
    /// each OpenID Connect one sending the browser back to `callback` and,
    /// after its own logout, to `post_logout` (RP-Initiated Logout 1.0 §3),
    /// and each SAML one through FerroSMART's service provider `saml`.
    ///
    /// # Errors
    /// Returns the [`UpstreamError`] of the first provider whose login
    /// cannot be set up.
    pub async fn connect(
        upstreams: &[Upstream],
        callback: &Url,
        post_logout: &Url,
        saml: Option<&Arc<saml::ServiceProviderSettings>>,
    ) -> Result<Self, UpstreamError> {
        let mut providers = Vec::with_capacity(upstreams.len());
        for upstream in upstreams {
            let login = match &upstream.protocol {
                Protocol::Oidc(oidc) => Login::Oidc(Box::new(
                    oidc.relying_party(callback.clone())
                        .await?
                        .with_post_logout_redirect_uri(post_logout.clone()),
                )),
                Protocol::Saml(entry) => {
                    let sp = saml.ok_or(UpstreamError::NoServiceProvider)?;
                    Login::Saml(Box::new(
                        saml::SamlLogin::connect(entry, Arc::clone(sp)).await?,
                    ))
                }
                Protocol::Wallet(entry) => {
                    Login::Wallet(Box::new(wallet::WalletLogin::connect(entry)?))
                }
            };
            providers.push(LoginProvider {
                upstream: upstream.clone(),
                login,
            });
        }
        Ok(Self { providers })
    }

    /// Whether no provider is configured.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    /// Returns every provider, in configuration order.
    pub fn iter(&self) -> impl Iterator<Item = &LoginProvider> {
        self.providers.iter()
    }

    /// Returns the provider `name`.
    #[must_use]
    pub fn named(&self, name: &str) -> Option<&LoginProvider> {
        self.providers
            .iter()
            .find(|provider| provider.name() == name)
    }

    /// Returns the provider whose issuer is `issuer`.
    #[must_use]
    pub fn by_issuer(&self, issuer: &str) -> Option<&LoginProvider> {
        self.providers
            .iter()
            .find(|provider| provider.upstream.issuer() == issuer)
    }

    /// Returns the providers a person may log in at for the client that
    /// names `allowed`: those it names, or every provider when it names
    /// none.
    #[must_use]
    pub fn allowed(&self, allowed: &[String]) -> Vec<&LoginProvider> {
        self.providers
            .iter()
            .filter(|provider| {
                allowed.is_empty() || allowed.iter().any(|name| name == provider.name())
            })
            .collect()
    }
}
