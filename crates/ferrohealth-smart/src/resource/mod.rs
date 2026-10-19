// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The resource-server role: who calls, and what the caller's access token
//! permits.
//!
//! One [`ResourceServer`] validates the access tokens of one authorization
//! server. The issuer and the audiences are configured; the issuer's
//! metadata (RFC 8414 §3, with `OpenID` Connect Discovery 1.0 §4 as the
//! fallback location) names the key set (RFC 7517) every token signature is
//! checked against, or a key set file handed over out of band does. A token
//! is an RFC 7519 JWT, read under the RFC 9068 access token profile unless
//! the deployment says otherwise. A product that trusts several issuers
//! holds them in an [`IssuerSet`]; a product that checks a token another
//! way (RFC 7662 introspection, a signed edge assertion) implements
//! [`Verifier`] beside them. A product never forwards a caller's token
//! upstream: an access token names the resource server it is for (RFC 9068
//! §4), and an upstream is reached with the product's own credential
//! ([`crate::client`]).

pub mod configuration;
mod jwks;
mod token;

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use http::StatusCode;
use jsonwebtoken::Algorithm;
use serde::Deserialize;
use serde::Serialize;
use url::Url;

use crate::metadata::DiscoveryError;
use crate::metadata::Http;
use crate::metadata::ServerMetadata;
use crate::resource::jwks::KeySet;
use crate::resource::jwks::KeySource;
use crate::scope::Evaluator;
use crate::scope::Permission;
use crate::scope::Reach;
use crate::scope::Scopes;

/// The longest clock skew a deployment may configure: RFC 7519 §4.1.4
/// allows "some small leeway, usually no more than a few minutes".
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(300);

/// The claims a token must carry, by profile.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenProfile {
    /// The JWT access token profile of RFC 9068: `typ` is `at+jwt` and `iss`,
    /// `exp`, `aud`, `sub`, `client_id`, `iat` and `jti` are present (§2.1,
    /// §2.2, §4).
    #[default]
    Rfc9068,
    /// A JWT bearer token outside that profile: `typ` absent or `JWT`, and
    /// `iss`, `exp`, `aud` and `sub` present. For an authorization server
    /// that does not issue RFC 9068 tokens; no specification governs the
    /// choice: our own design.
    Jwt,
}

/// What one deployment configured its resource server with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// The issuer identifier every token's `iss` must equal (RFC 8414 §2).
    pub issuer: String,
    /// The audiences, of which every token's `aud` must contain one
    /// (RFC 9068 §4); at least one.
    pub audience: Vec<String>,
    /// The signature algorithms a token may use; asymmetric only (RFC 8725
    /// §3.1, §3.2), which [`Settings::validate`] checks.
    pub algorithms: Vec<Algorithm>,
    /// The claims a token must carry.
    pub profile: TokenProfile,
    /// The clock skew `exp`, `nbf` and `iat` are checked with, at most
    /// [`MAX_CLOCK_SKEW`].
    pub clock_skew: Duration,
    /// How long a held key set is used before it is read again.
    pub jwks_max_age: Duration,
    /// The shortest time between two reads of the key set an unknown `kid`
    /// or a failed read triggers.
    pub jwks_refresh_interval: Duration,
    /// A JWK Set file handed over out of band, read in place of the
    /// issuer's `jwks_uri`; the issuer's metadata is then not read.
    pub jwks_file: Option<PathBuf>,
    /// How long one call to the authorization server may take.
    pub timeout: Duration,
    /// The subjects a token with no clinical scope is granted system-wide
    /// access for (a product's allowlist; no specification governs it: our
    /// own design).
    pub scopeless_subjects: BTreeSet<String>,
}

impl Settings {
    /// Returns settings for tokens of `issuer` addressed to `audience`.
    ///
    /// RS256, RS384, PS256, PS384, ES256 and ES384 are accepted under the
    /// RFC 9068 profile, the clock skew is 60 seconds, the key set is used
    /// for 600 seconds and read again at most once a minute, a call to the
    /// authorization server may take 10 seconds, and no subject is granted
    /// scopeless access.
    #[must_use]
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: vec![audience.into()],
            algorithms: vec![
                Algorithm::RS256,
                Algorithm::RS384,
                Algorithm::PS256,
                Algorithm::PS384,
                Algorithm::ES256,
                Algorithm::ES384,
            ],
            profile: TokenProfile::Rfc9068,
            clock_skew: Duration::from_secs(60),
            jwks_max_age: Duration::from_secs(600),
            jwks_refresh_interval: Duration::from_secs(60),
            jwks_file: None,
            timeout: Duration::from_secs(10),
            scopeless_subjects: BTreeSet::new(),
        }
    }

    /// Checks the settings: the issuer URL rule, at least one audience, at
    /// least one algorithm and none symmetric, and the clock skew bound.
    ///
    /// # Errors
    ///
    /// Returns the [`ResourceError`] naming the first rule broken.
    pub fn validate(&self) -> Result<(), ResourceError> {
        crate::metadata::issuer_url(&self.issuer)?;
        if self.audience.iter().all(String::is_empty) {
            return Err(ResourceError::NoAudience);
        }
        if self.algorithms.is_empty() {
            return Err(ResourceError::NoAlgorithm);
        }
        if let Some(algorithm) = self.algorithms.iter().find(|algorithm| {
            matches!(
                algorithm,
                Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
            )
        }) {
            return Err(ResourceError::SymmetricAlgorithm {
                algorithm: *algorithm,
            });
        }
        if self.clock_skew > MAX_CLOCK_SKEW {
            return Err(ResourceError::ClockSkew {
                skew: self.clock_skew,
            });
        }
        Ok(())
    }
}

/// A failure to reach or read the authorization server, or settings that
/// break a rule.
///
/// No variant carries a token.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ResourceError {
    /// The metadata could not be read, or the issuer is outside the URL
    /// rule.
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
    /// The settings admit a symmetric algorithm, which RFC 8725 §3.1 and
    /// §3.2 have a verifier refuse: a key of the issuer's set would then
    /// sign a token.
    #[error("the settings admit the symmetric algorithm {algorithm:?}")]
    SymmetricAlgorithm {
        /// The algorithm admitted.
        algorithm: Algorithm,
    },
    /// The settings admit no algorithm at all.
    #[error("the settings admit no signature algorithm")]
    NoAlgorithm,
    /// The settings name no audience (RFC 8725 §3.9 has a token without a
    /// recognized audience refused, so one must be expected).
    #[error("the settings name no audience")]
    NoAudience,
    /// The clock skew is longer than [`MAX_CLOCK_SKEW`].
    #[error("the clock skew of {skew:?} is longer than {MAX_CLOCK_SKEW:?}")]
    ClockSkew {
        /// The skew configured.
        skew: Duration,
    },
    /// The metadata names no member the resource server needs.
    #[error("the authorization server metadata names no {member}")]
    MissingMember {
        /// The member it lacks.
        member: &'static str,
    },
    /// The metadata names a `jwks_uri` that is not a URL.
    #[error("the authorization server metadata names a jwks_uri that is not a URL")]
    JwksUrl {
        /// What the URL parser reported.
        #[source]
        source: url::ParseError,
    },
    /// The key set location answered anything other than `200`.
    #[error("the key set at {url} answered {status}")]
    KeySetStatus {
        /// The location.
        url: Url,
        /// The status it answered.
        status: StatusCode,
        /// The body it answered, as received.
        body: String,
    },
    /// The key set file could not be read.
    #[error("the key set file {} could not be read", path.display())]
    KeySetFile {
        /// The file.
        path: PathBuf,
        /// What the file system reported.
        #[source]
        source: std::io::Error,
    },
    /// The key set is not the JSON object RFC 7517 §5 describes.
    #[error("the key set at {origin} is not a JWK Set")]
    KeySet {
        /// Where it was read from.
        origin: KeySource,
        /// What the JSON reader reported.
        #[source]
        error: serde_json::Error,
    },
    /// The key set was not read again, because a read failed within the
    /// refresh interval.
    #[error("the key set at {origin} failed to read within the refresh interval")]
    KeySetBackoff {
        /// Where it is read from.
        origin: KeySource,
    },
}

/// The resource types a clinical scope may name, when a product holds a
/// table.
type ResourceTypes = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// The resource server: the configured authorization server, its metadata
/// and its key set.
pub struct ResourceServer {
    /// What the deployment configured.
    settings: Settings,
    /// The authorization server's metadata, read at boot; only the issuer
    /// when the key set comes from a file.
    metadata: ServerMetadata,
    /// The signing keys.
    keys: KeySet,
    /// The resource types a clinical scope may name, when the product holds
    /// a table; the lexical rule of [`Scopes::parse`] otherwise.
    resource_types: Option<ResourceTypes>,
}

impl std::fmt::Debug for ResourceServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceServer")
            .field("settings", &self.settings)
            .field("metadata", &self.metadata)
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

impl ResourceServer {
    /// Reads the metadata and the key set of the authorization server
    /// `settings` names.
    ///
    /// Both are read once here, so an authorization server that cannot be
    /// reached refuses the start rather than the first request. With a
    /// `jwks_file`, the file is read and the metadata is not.
    ///
    /// # Errors
    ///
    /// Returns every [`ResourceError`]: the settings break a rule, the
    /// metadata or the key set could not be read, or the metadata names
    /// another issuer, no `jwks_uri` or an insecure one.
    pub async fn discover(settings: Settings) -> Result<Self, ResourceError> {
        settings.validate()?;
        let http = Http::new(settings.timeout)?;
        let (metadata, source) = if let Some(path) = &settings.jwks_file {
            let metadata = ServerMetadata {
                issuer: settings.issuer.clone(),
                ..ServerMetadata::default()
            };
            (metadata, KeySource::File(path.clone()))
        } else {
            let metadata = http.discover(&settings.issuer).await?;
            let jwks_uri = metadata
                .jwks_uri
                .as_deref()
                .ok_or(ResourceError::MissingMember { member: "jwks_uri" })?
                .parse::<Url>()
                .map_err(|source| ResourceError::JwksUrl { source })?;
            crate::metadata::secure(&jwks_uri, "the jwks_uri")?;
            (metadata, KeySource::Uri(jwks_uri))
        };
        let keys = KeySet::load(
            http,
            source,
            settings.jwks_max_age,
            settings.jwks_refresh_interval,
        )
        .await?;
        tracing::info!(
            issuer = %settings.issuer,
            keys = keys.len().await,
            source = %keys.source(),
            "validating access tokens of this issuer"
        );
        Ok(Self {
            settings,
            metadata,
            keys,
            resource_types: None,
        })
    }

    /// Returns this resource server reading a clinical scope's resource type
    /// against `known`, in place of the lexical rule.
    #[must_use]
    pub fn with_resource_types(
        mut self,
        known: impl Fn(&str) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.resource_types = Some(Arc::new(known));
        self
    }

    /// Returns what the deployment configured.
    #[must_use]
    pub const fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Returns the authorization server's metadata as read at boot.
    #[must_use]
    pub const fn metadata(&self) -> &ServerMetadata {
        &self.metadata
    }

    /// Returns the caller `token` authenticates.
    ///
    /// # Errors
    ///
    /// Returns [`Rejection::Invalid`] for a token whose signature, issuer,
    /// audience, lifetime or claims do not hold, and
    /// [`Rejection::Unavailable`] when the key set could not be read again.
    pub async fn authenticate(&self, token: &str) -> Result<Caller, Rejection> {
        token::validate(self, token).await
    }

    /// Returns the SMART discovery document of this resource server under
    /// `options`.
    #[must_use]
    pub fn smart_configuration(&self, options: &configuration::SmartOptions) -> serde_json::Value {
        configuration::document(&self.metadata, options)
    }

    /// Returns the clinical scopes `scope` grants under this server's
    /// resource table.
    fn scopes(&self, scope: &str) -> Scopes {
        match &self.resource_types {
            Some(known) => Scopes::parse_known(scope, |name| known(name)),
            None => Scopes::parse(scope),
        }
    }
}

/// How a bearer token is checked.
///
/// [`ResourceServer`] checks a JWT against the issuer's key set; a product
/// that checks a token another way (RFC 7662 introspection for a token that
/// is no JWS, a signed assertion of a trusted edge) implements this beside
/// it, so the gate, the [`Access`] and the audit line are shared and only
/// the check differs.
pub trait Verifier: Send + Sync + 'static {
    /// Returns the caller `token` authenticates, or why it does not.
    fn verify<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Caller, Rejection>> + Send + 'a>>;
}

impl Verifier for ResourceServer {
    fn verify<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Caller, Rejection>> + Send + 'a>> {
        Box::pin(self.authenticate(token))
    }
}

/// The resource servers of several trusted issuers, each token routed to
/// the one its `iss` names.
///
/// The `iss` is read from the payload before the signature is checked, as
/// RFC 7519 §7.2 lets a recipient do to select the key; the server it
/// names then checks everything, the issuer included.
#[derive(Debug, Default)]
pub struct IssuerSet {
    /// The servers, by issuer identifier.
    servers: BTreeMap<String, Arc<ResourceServer>>,
}

impl IssuerSet {
    /// Returns an empty set, which admits no token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns this set trusting `server`'s issuer.
    #[must_use]
    pub fn with(mut self, server: Arc<ResourceServer>) -> Self {
        self.servers
            .insert(server.settings().issuer.clone(), server);
        self
    }

    /// Returns the server of `issuer`, when the set trusts it.
    #[must_use]
    pub fn server(&self, issuer: &str) -> Option<&Arc<ResourceServer>> {
        self.servers.get(issuer)
    }

    /// Returns how many issuers the set trusts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.servers.len()
    }

    /// Returns whether the set trusts no issuer.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }
}

impl Verifier for IssuerSet {
    fn verify<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Caller, Rejection>> + Send + 'a>> {
        Box::pin(async move {
            let issuer = unverified_issuer(token).ok_or(Rejection::Invalid {
                reason: "malformed",
            })?;
            let server = self.servers.get(&issuer).ok_or(Rejection::Invalid {
                reason: "issuer not trusted",
            })?;
            server.authenticate(token).await
        })
    }
}

/// Returns the `iss` claim of `token` without checking anything.
fn unverified_issuer(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&bytes).ok()?;
    claims
        .get("iss")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// Why a request carries no usable identity.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Rejection {
    /// No bearer token arrived.
    #[error("the request carries no bearer token")]
    Missing,
    /// The token does not hold.
    #[error("the access token is not valid: {reason}")]
    Invalid {
        /// What failed, for the debug log; never a claim value.
        reason: &'static str,
    },
    /// The key set could not be read to check the token.
    #[error("the authorization server's key set could not be read")]
    Unavailable {
        /// What failed.
        #[source]
        source: Arc<ResourceError>,
    },
}

/// What a product honours for a caller beyond a `user/` grant under the
/// SMART on openEHR grammar, read from its issuer or client lists.
///
/// No specification governs these: our own design, FerroFED's, over the
/// draft's own notes (`master08 §Resource Scopes` on `system/aql-*`,
/// `master07 §Context Selection` on the `ehrId`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Honoured {
    /// The caller is a backend client the product lists, so a
    /// `system/aql-*` grant counts.
    pub backend: bool,
    /// The caller's issuer is bound to the product's own EHR space, so a
    /// `patient/` grant counts on an EHR's data, confined to the `ehrId` of
    /// the launch context.
    pub patient: bool,
}

/// The scheme a credential arrived with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// A bearer token (RFC 6750).
    Bearer,
    /// A Basic credential (RFC 7617).
    Basic,
}

impl Via {
    /// Returns the name the audit line records.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bearer => "bearer",
            Self::Basic => "basic",
        }
    }
}

/// The identity one valid credential carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// The token's `sub`, or the Basic user-id.
    subject: String,
    /// The token's `client_id`, when it carries one.
    client_id: Option<String>,
    /// Every token of the `scope` claim, as granted.
    scope: Vec<String>,
    /// The clinical scopes among them.
    scopes: Scopes,
    /// The `patient` launch context the token carries.
    patient: Option<String>,
    /// Whether the subject is granted system-wide access without a clinical
    /// scope.
    scopeless: bool,
    /// The scheme the credential arrived with.
    via: Via,
    /// The issuer that signed the token, when one did.
    issuer: Option<String>,
    /// Every claim of the token, for the product's own reading.
    claims: serde_json::Map<String, serde_json::Value>,
}

impl Caller {
    /// Returns the caller of a token whose claims say so.
    ///
    /// `scope` is the space-delimited `scope` claim (RFC 6749 §3.3), and
    /// `scopeless` is whether the deployment grants the subject system-wide
    /// access when the token names no clinical scope.
    #[must_use]
    pub fn new(
        subject: String,
        client_id: Option<String>,
        scope: &str,
        patient: Option<String>,
        scopeless: bool,
    ) -> Self {
        Self {
            subject,
            client_id,
            scope: scope
                .split(' ')
                .filter(|token| !token.is_empty())
                .map(str::to_owned)
                .collect(),
            scopes: Scopes::parse(scope),
            patient,
            scopeless,
            via: Via::Bearer,
            issuer: None,
            claims: serde_json::Map::new(),
        }
    }

    /// Returns the caller a Basic credential authenticates: the user-id as
    /// the subject, no client, and the space-delimited `scope` its
    /// configuration grants it, so the same check serves a Basic caller and
    /// a bearer caller (no specification governs this: our own design).
    #[must_use]
    pub fn basic(username: String, scope: &str) -> Self {
        let mut caller = Self::new(username, None, scope, None, false);
        caller.via = Via::Basic;
        caller
    }

    /// Returns this caller with `scopes` as its clinical scopes, read under
    /// a product's resource table.
    #[must_use]
    pub fn with_scopes(mut self, scopes: Scopes) -> Self {
        self.scopes = scopes;
        self
    }

    /// Returns this caller signed by `issuer`.
    #[must_use]
    pub fn with_issuer(mut self, issuer: String) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// Returns this caller carrying `claims`.
    #[must_use]
    pub fn with_claims(mut self, claims: serde_json::Map<String, serde_json::Value>) -> Self {
        self.claims = claims;
        self
    }

    /// Returns the subject: the token's `sub` or the Basic user-id.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the token's client, when it names one.
    #[must_use]
    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    /// Returns the `patient` launch context, when the token carries one.
    #[must_use]
    pub fn patient(&self) -> Option<&str> {
        self.patient.as_deref()
    }

    /// Returns the `ehrId` of the SMART on openEHR launch context, when the
    /// token carries it as a claim.
    ///
    /// The draft places it in the token response (`master07 §Context
    /// Selection`); reading it from an `ehrId` claim is the same convention
    /// as `patient` (no specification governs it: our own design).
    #[must_use]
    pub fn ehr_id(&self) -> Option<&str> {
        self.claims.get("ehrId").and_then(serde_json::Value::as_str)
    }

    /// Returns every token of the `scope` claim read under the SMART on
    /// openEHR grammar, a token outside it as [`SmartScope::Other`].
    ///
    /// [`SmartScope::Other`]: openehr_sdt::smart_scopes::SmartScope::Other
    #[cfg(feature = "openehr")]
    #[must_use]
    pub fn openehr_scopes(&self) -> Vec<openehr_sdt::smart_scopes::SmartScope> {
        self.scope
            .iter()
            .map(|token| openehr_sdt::smart_scopes::SmartScope::parse(token))
            .collect()
    }

    /// Returns the scheme the credential arrived with.
    #[must_use]
    pub const fn via(&self) -> Via {
        self.via
    }

    /// Returns the issuer that signed the token, when one did.
    #[must_use]
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// Returns whether the `scope` claim names `scope`, compared verbatim.
    ///
    /// This is how a product reads its own scope (an operator or admin
    /// scope) that is no SMART clinical scope.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scope.iter().any(|granted| granted == scope)
    }

    /// Returns every token of the `scope` claim, as granted.
    #[must_use]
    pub fn scope(&self) -> &[String] {
        &self.scope
    }

    /// Returns the clinical scopes the token grants.
    #[must_use]
    pub const fn scopes(&self) -> &Scopes {
        &self.scopes
    }

    /// Returns every claim of the token, for the product's own reading.
    #[must_use]
    pub const fn claims(&self) -> &serde_json::Map<String, serde_json::Value> {
        &self.claims
    }

    /// Returns the claim `name`, when the token carries it.
    #[must_use]
    pub fn claim(&self, name: &str) -> Option<&serde_json::Value> {
        self.claims.get(name)
    }

    /// Returns which data `permission` on `resource_type` reaches, or `None`
    /// when the token does not grant it.
    ///
    /// A token with no clinical scope reaches everything when its subject is
    /// on the deployment's allowlist and nothing otherwise. A `patient/`
    /// scope reaches the patient in the `patient` claim, and nothing when the
    /// token carries no such claim. A granular scope grants nothing here;
    /// [`Caller::reach_with`] evaluates it.
    #[must_use]
    pub fn reach(&self, permission: Permission, resource_type: &str) -> Option<Compartment> {
        self.reach_with(permission, resource_type, &|_constraint| false)
    }

    /// Returns which data `permission` on `resource_type` reaches, a
    /// granular scope admitted when `evaluate` says the resource satisfies
    /// its constraint.
    #[must_use]
    pub fn reach_with(
        &self,
        permission: Permission,
        resource_type: &str,
        evaluate: Evaluator<'_>,
    ) -> Option<Compartment> {
        if self.scopes.is_empty() {
            return self.scopeless.then_some(Compartment::Any);
        }
        match self
            .scopes
            .reach_with(permission, resource_type, evaluate)?
        {
            Reach::Any => Some(Compartment::Any),
            Reach::Patient => self.patient.clone().map(Compartment::Patient),
        }
    }
}

/// Which resources one permission reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compartment {
    /// Every resource of the type.
    Any,
    /// Only the compartment of the patient with this id, the `patient`
    /// launch context of the token.
    Patient(String),
}

impl Compartment {
    /// Returns whether this compartment reaches the data of `patient`, the
    /// patient a resource belongs to, or `None` when the resource belongs to
    /// no patient.
    ///
    /// "If the app has any patient-level scopes, they will be scoped to
    /// Patient 123" (SMART App Launch 2.2.0, Scopes and Launch Context,
    /// §Launch context arrives with your `access_token`), so a patient
    /// compartment reaches only that patient's resources, and a resource of
    /// no patient is outside every patient's compartment.
    #[must_use]
    pub fn admits(&self, patient: Option<&str>) -> bool {
        match self {
            Self::Any => true,
            Self::Patient(launched) => patient == Some(launched.as_str()),
        }
    }
}

/// What a request may do, as the gate established it.
///
/// Every request through the gate carries one as an extension, so a handler
/// that finds none is outside the gate, which fails the request.
#[derive(Debug, Clone)]
pub enum Access {
    /// Inbound authentication is off: the surface is open.
    Open,
    /// A caller with a valid credential.
    Caller(Arc<Caller>),
}

impl Access {
    /// Returns the caller, or `None` on an open surface.
    #[must_use]
    pub fn caller(&self) -> Option<&Caller> {
        match self {
            Self::Open => None,
            Self::Caller(caller) => Some(caller),
        }
    }

    /// Returns whether the caller's `scope` claim names `scope`; an open
    /// surface has no caller and so no scope.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.caller().is_some_and(|caller| caller.has_scope(scope))
    }

    /// Returns the caller's claims, or `None` on an open surface.
    #[must_use]
    pub fn claims(&self) -> Option<&serde_json::Map<String, serde_json::Value>> {
        self.caller().map(Caller::claims)
    }

    /// Returns the `ehrId` of the caller's launch context, when the token
    /// carries one.
    #[must_use]
    pub fn ehr_id(&self) -> Option<&str> {
        self.caller().and_then(Caller::ehr_id)
    }

    /// Returns which data `permission` on `resource_type` reaches.
    #[must_use]
    pub fn reach(&self, permission: Permission, resource_type: &str) -> Option<Compartment> {
        match self {
            Self::Open => Some(Compartment::Any),
            Self::Caller(caller) => caller.reach(permission, resource_type),
        }
    }

    /// Returns which data `permission` on `resource_type` reaches, a
    /// granular scope evaluated by `evaluate`.
    #[must_use]
    pub fn reach_with(
        &self,
        permission: Permission,
        resource_type: &str,
        evaluate: Evaluator<'_>,
    ) -> Option<Compartment> {
        match self {
            Self::Open => Some(Compartment::Any),
            Self::Caller(caller) => caller.reach_with(permission, resource_type, evaluate),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Caller, Compartment, MAX_CLOCK_SKEW, ResourceError, Settings, Via};
    use crate::scope::Permission;
    use std::time::Duration;

    #[test]
    fn a_scopeless_token_reaches_everything_only_when_allowlisted() {
        let allowed = Caller::new(String::from("svc"), None, "openid", None, true);
        assert_eq!(
            Some(Compartment::Any),
            allowed.reach(Permission::Create, "Condition")
        );
        assert!(allowed.has_scope("openid"));
        assert!(!allowed.has_scope("open"));
        let other = Caller::new(String::from("svc"), None, "", None, false);
        assert_eq!(None, other.reach(Permission::Read, "Condition"));
        assert!(other.scope().is_empty());
    }

    #[test]
    fn an_allowlisted_subject_with_scopes_gets_only_its_scopes() {
        let caller = Caller::new(String::from("svc"), None, "system/Condition.r", None, true);
        assert_eq!(None, caller.reach(Permission::Create, "Condition"));
    }

    #[test]
    fn a_patient_scope_without_a_patient_claim_reaches_nothing() {
        let without = Caller::new(String::from("app"), None, "patient/*.rs", None, false);
        assert_eq!(None, without.reach(Permission::Read, "Condition"));
        let with = Caller::new(
            String::from("app"),
            None,
            "patient/*.rs",
            Some(String::from("123")),
            false,
        );
        assert_eq!(
            Some(Compartment::Patient(String::from("123"))),
            with.reach(Permission::Read, "Condition")
        );
    }

    #[test]
    fn a_patient_compartment_admits_its_patient_alone() {
        let compartment = Compartment::Patient(String::from("123"));
        assert!(compartment.admits(Some("123")));
        assert!(!compartment.admits(Some("124")));
        assert!(!compartment.admits(None));
        assert!(Compartment::Any.admits(None));
    }

    #[test]
    fn a_basic_caller_carries_its_configured_scope() {
        let caller = Caller::basic(String::from("alice"), "system/Condition.r");
        assert_eq!("alice", caller.subject());
        assert_eq!(None, caller.client_id());
        assert_eq!(Via::Basic, caller.via());
        assert_eq!(None, caller.issuer());
        assert_eq!(
            Some(Compartment::Any),
            caller.reach(Permission::Read, "Condition")
        );
        assert_eq!(None, caller.reach(Permission::Delete, "Condition"));
        let none = Caller::basic(String::from("bob"), "");
        assert_eq!(None, none.reach(Permission::Read, "Condition"));
    }

    #[test]
    fn the_settings_rules_refuse_the_start() {
        let mut settings = Settings::new("https://as.example.org", "aud");
        assert!(settings.validate().is_ok());
        settings.clock_skew = MAX_CLOCK_SKEW + Duration::from_secs(1);
        assert!(matches!(
            settings.validate(),
            Err(ResourceError::ClockSkew { .. })
        ));
        let mut settings = Settings::new("https://as.example.org", "");
        assert!(matches!(
            settings.validate(),
            Err(ResourceError::NoAudience)
        ));
        settings.audience = vec![String::from("aud")];
        settings.issuer = String::from("http://as.example.org");
        assert!(matches!(
            settings.validate(),
            Err(ResourceError::Discovery(_))
        ));
    }
}
