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
//! holds them in an [`IssuerSet`]. [`ResourceServer::lazy`] defers the
//! metadata and key set read to the first token, for a product that answers
//! an unreachable issuer with `503` rather than refusing to start. A product
//! that checks a token another
//! way (RFC 7662 introspection, a signed edge assertion) implements
//! [`Verifier`] beside them. A product never forwards a caller's token
//! upstream: an access token names the resource server it is for (RFC 9068
//! §4), and an upstream is reached with the product's own credential
//! ([`crate::client`]).

mod caller;
pub mod configuration;
pub mod described;
mod federated;
#[cfg(feature = "fetch")]
pub mod introspection;
mod jwks;
mod rules;
mod server;
mod set;
mod settings;
mod token;
mod verdict;

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use http::Extensions;
use http::StatusCode;
use jsonwebtoken::Algorithm;
use url::Url;

use crate::assurance::Assessment;
use crate::assurance::AssuranceError;
use crate::assurance::AssuranceSection;
use crate::federation::FederationError;
use crate::federation::FederationSection;
use crate::kind::CallerKind;
use crate::kind::IssuerKind;
use crate::kind::Unclassified;
use crate::metadata::DiscoveryError;
use crate::metadata::ServerMetadata;
use crate::profile::Profile;
use crate::profile::ProfileError;
use crate::refusal::Reason;
use crate::resource::jwks::KeySet;
use crate::resource::jwks::KeySource;
use crate::scope::Scopes;
use crate::sender::Binding;
use crate::sender::Check;
use crate::sender::SenderConstraint;

/// The longest clock skew a deployment may configure: RFC 7519 §4.1.4
/// allows "some small leeway, usually no more than a few minutes".
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(300);

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
    /// Whose tokens the issuer signs.
    pub kind: IssuerKind,
    /// What the issuer's tokens look like and how their callers are
    /// classified.
    pub profile: Profile,
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
    /// The claims a token's roles are read from, each a dotted path
    /// (RFC 9068 §2.2.3.1; [`crate::roles`]).
    pub role_claims: Vec<String>,
    /// The assurance level the issuer's tokens carry, when the deployment
    /// maps its authentication context values.
    pub assurance: Option<AssuranceSection>,
    /// What a `federation` issuer asserts and the bounds it is held to;
    /// required on a `federation` issuer and refused on any other.
    pub federation: Option<FederationSection>,
    /// What a `persons` issuer states about its professionals; refused on
    /// an issuer of any other kind.
    pub attributes: Option<crate::federation::person::AttributesSection>,
    /// Whether the issuer's tokens must be bound to a `DPoP` key or a client
    /// certificate ([`crate::sender`]).
    pub sender_constraint: SenderConstraint,
    /// The TLS of the discovery document and the key set: the configuration
    /// the product built from `auth.tls`, or the platform's roots at its
    /// minimum version.
    pub tls: crate::client::Tls,
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
    /// The issuer's profile breaks a rule.
    #[error(transparent)]
    Profile(#[from] ProfileError),
    /// The issuer's `[auth.issuer.<name>.federation]` table breaks a rule.
    #[error(transparent)]
    Federation(#[from] FederationError),
    /// The issuer's assurance mapping breaks a rule.
    #[error(transparent)]
    Assurance(#[from] AssuranceError),
    /// A `contact_point = true` issuer without `sender_constraint =
    /// "required"`.
    #[error("a contact_point = true issuer requires sender_constraint = \"required\"")]
    ContactPointSender,
    /// A `federation` issuer whose table declares
    /// `requires_sender_constraint = true` without `sender_constraint =
    /// "required"`.
    #[error(
        "the issuer's [auth.issuer.<name>.federation] table requires sender_constraint = \"required\""
    )]
    SenderConstraintRequired,
    /// A setting is refused on an issuer of this kind.
    #[error("{key} is refused on a {kind} issuer")]
    Kind {
        /// The setting.
        key: &'static str,
        /// The issuer's kind.
        kind: IssuerKind,
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
        /// Always empty: RFC 7517 defines no error body, and nothing of the
        /// answer is kept, so no rendering of the error carries it.
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
        error: crate::json::JsonError,
    },
    /// An object of the key set repeats a member name, whose meaning
    /// RFC 8259 §4 leaves to each parser.
    #[error("the key set at {origin} repeats a member name")]
    KeySetRepeatedName {
        /// Where it was read from.
        origin: KeySource,
        /// What the JSON reader reported, with the position.
        #[source]
        error: crate::json::JsonError,
    },
    /// The settings name no `jwks_file`, and the crate is built without the
    /// `fetch` feature that reads the issuer's metadata and its `jwks_uri`.
    #[error("the settings name no jwks_file, and this build reads no key set over HTTP")]
    KeySetFileRequired,
    /// The key set was not read again, because a read failed within the
    /// refresh interval.
    #[error("the key set at {origin} failed to read within the refresh interval")]
    KeySetBackoff {
        /// Where it is read from.
        origin: KeySource,
    },
    /// Operator-supplied metadata was offered to a resource server that read
    /// its metadata from the issuer, whose own document stands.
    #[error("the metadata of this issuer was read from the issuer and is not replaced")]
    MetadataFetched,
    /// Operator-supplied metadata names another issuer than the configured
    /// one (RFC 8414 §3.3).
    #[error("the supplied metadata names the issuer {found:?}, not the configured one")]
    MetadataIssuer {
        /// The issuer the metadata names.
        found: String,
    },
    /// Operator-supplied metadata names a location that is not a URL.
    #[error("the supplied metadata names a {member} that is not a URL")]
    MetadataUrl {
        /// The member.
        member: &'static str,
        /// What the URL parser reported.
        #[source]
        source: url::ParseError,
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
    /// Whether the operator supplied the metadata of a key set read from a
    /// file ([`ResourceServer::with_metadata`]).
    supplied: bool,
    /// The signing keys.
    keys: KeySet,
    /// The resource types a clinical scope may name, when the product holds
    /// a table; the lexical rule of [`Scopes::parse`] otherwise.
    resource_types: Option<ResourceTypes>,
    /// The product's values copied onto every caller this server admits.
    extensions: Extensions,
    /// How many token signatures this server has checked.
    signatures: std::sync::atomic::AtomicU64,
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

/// How a bearer token is checked.
///
/// [`ResourceServer`] checks a JWT against the issuer's key set; a product
/// that checks a token another way (RFC 7662 introspection for a token that
/// is no JWS, a signed assertion of a trusted edge) implements this beside
/// it, so the gate, the [`Access`] and the audit line are shared and only
/// the check differs.
pub trait Verifier: Send + Sync + 'static {
    /// Returns the caller `token`, presented as a plain bearer token,
    /// authenticates, or why it does not.
    fn verify<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Caller, Rejection>> + Send + 'a>>;

    /// Returns the caller `token` authenticates when the request proves
    /// what `binding` carries: the key of a verified `DPoP` proof, the client
    /// certificate of its connection, or neither ([`crate::sender`]).
    ///
    /// The default checks a request that proves no key with
    /// [`Verifier::verify`] and refuses a `DPoP` request as
    /// [`Check::Unsupported`], so a verifier that does not read `cnf` never
    /// admits one; the gate holds every caller's `cnf` to the binding after.
    fn verify_bound<'a>(
        &'a self,
        token: &'a str,
        binding: &'a Binding,
    ) -> Pin<Box<dyn Future<Output = Result<Caller, Rejection>> + Send + 'a>> {
        if binding.proven_key().is_some() {
            return Box::pin(std::future::ready(Err(Rejection::Invalid {
                reason: Reason::Sender(Check::Unsupported),
            })));
        }
        self.verify(token)
    }
}

/// A resource server whose metadata and key set are read when the first
/// token needs them ([`ResourceServer::lazy`]).
pub struct LazyResourceServer {
    /// What the deployment configured.
    settings: Settings,
    /// The resource types a clinical scope may name, when the product holds
    /// a table.
    resource_types: Option<ResourceTypes>,
    /// The product's values copied onto every caller this server admits.
    extensions: Extensions,
    /// The resource server, once a read succeeded.
    server: tokio::sync::OnceCell<Arc<ResourceServer>>,
    /// When the last read failed and why, so the next is not made inside
    /// the refresh interval.
    failed: Mutex<Option<(Instant, Arc<ResourceError>)>>,
}

impl std::fmt::Debug for LazyResourceServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyResourceServer")
            .field("settings", &self.settings)
            .field("server", &self.server.get())
            .finish_non_exhaustive()
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
    servers: BTreeMap<String, set::Trusted>,
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
        /// Which check failed, for the log; never a claim value.
        reason: Reason,
    },
    /// The token is valid and matches no step of the caller classification
    /// for its issuer's kind ([`crate::kind`]); answered as an invalid token.
    #[error("the access token names no caller this issuer may: {reason}")]
    Unclassified {
        /// Which step refused it, for the log; never a claim value.
        reason: Unclassified,
    },
    /// The key set could not be read to check the token.
    #[error("the authorization server's key set could not be read")]
    Unavailable {
        /// What failed.
        #[source]
        source: Arc<ResourceError>,
    },
    /// The issuer's metadata or key set has not been read yet, so its tokens
    /// cannot be checked; answered `503` until a read succeeds
    /// ([`LazyResourceServer`]).
    #[error("the issuer's metadata or key set has not been read yet")]
    Unread {
        /// Why the last read failed.
        #[source]
        source: Arc<ResourceError>,
    },
    /// An upstream a product's own [`Verifier`] calls (an RFC 7662
    /// introspection endpoint) could not be reached or read, so the token
    /// was not checked. It answers `503`, as [`Rejection::Unavailable`]
    /// does.
    #[error("the {upstream} could not be reached to check the access token")]
    Upstream {
        /// What could not be reached, for the log.
        upstream: &'static str,
        /// What failed, the product's own error.
        #[source]
        source: Arc<dyn std::error::Error + Send + Sync + 'static>,
    },
}

impl Rejection {
    /// Returns the rejection of a token a product's own verifier could not
    /// check, because `upstream` failed with `source`.
    #[must_use]
    pub fn upstream(
        upstream: &'static str,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Upstream {
            upstream,
            source: Arc::new(source),
        }
    }
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
///
/// Two callers are equal when everything but their extensions and their
/// party is. Its
/// `Debug` rendering names the subject, the client, the issuer, the kind and
/// the scheme alone, never another claim of the token.
#[derive(Clone)]
pub struct Caller {
    /// The token's `sub`, or the Basic user-id.
    subject: String,
    /// The client the issuer profile's client claims name, when the token
    /// names one.
    client_id: Option<String>,
    /// Who stands behind the credential.
    kind: CallerKind,
    /// The current RFC 8693 §4.1 actor the token names.
    actor: Option<crate::kind::Actor>,
    /// What the token says about the authentication behind it, under the
    /// issuer's assurance mapping.
    assurance: Assessment,
    /// Every token of the `scope` claim, as granted.
    scope: Vec<String>,
    /// The clinical scopes among them.
    scopes: Scopes,
    /// The `patient` launch context the token carries.
    patient: Option<String>,
    /// The scheme the credential arrived with.
    via: Via,
    /// The issuer that signed the token, when one did.
    issuer: Option<String>,
    /// Every claim of the token, for the product's own reading.
    claims: serde_json::Map<String, serde_json::Value>,
    /// The roles the token's claims or the Basic user's configuration grant.
    roles: Vec<String>,
    /// Whether a Basic credential was admitted from the verified-credential
    /// cache, without the key derivation.
    cached: bool,
    /// The product's own values, attached by its resource server or its
    /// verifier.
    extensions: Extensions,
    /// What the login resolved to, when a party binding looked it up.
    party: Option<crate::party::Outcome>,
    /// What a `persons` token states about the professional.
    attributes: Option<crate::federation::person::Attributes>,
}

impl PartialEq for Caller {
    fn eq(&self, other: &Self) -> bool {
        self.subject == other.subject
            && self.client_id == other.client_id
            && self.kind == other.kind
            && self.actor == other.actor
            && self.assurance == other.assurance
            && self.scope == other.scope
            && self.scopes == other.scopes
            && self.patient == other.patient
            && self.via == other.via
            && self.issuer == other.issuer
            && self.claims == other.claims
            && self.roles == other.roles
            && self.cached == other.cached
    }
}

impl Eq for Caller {}

impl std::fmt::Debug for Caller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Caller")
            .field("subject", &self.subject)
            .field("client_id", &self.client_id)
            .field("issuer", &self.issuer)
            .field("kind", &self.kind)
            .field("via", &self.via)
            .field("cached", &self.cached)
            .finish_non_exhaustive()
    }
}

/// Which resources one permission reaches.
///
/// The `Debug` rendering of a patient compartment leaves out the patient.
#[derive(Clone, PartialEq, Eq)]
pub enum Compartment {
    /// Every resource of the type.
    Any,
    /// Only the compartment of the patient with this id, the `patient`
    /// launch context of the token.
    Patient(String),
}

impl std::fmt::Debug for Compartment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => f.write_str("Any"),
            Self::Patient(_) => f.debug_tuple("Patient").finish_non_exhaustive(),
        }
    }
}

/// The patient a request of the person's own access is bound to, as its
/// token names it ([`Caller::person`]).
///
/// Each field is what one source names, `None` when the token carries no
/// such value; a product reads the one its own identifiers live in. The
/// `Debug` rendering carries none of them.
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PersonContext<'a> {
    /// The `patient` launch context (SMART App Launch 2.2.0, Scopes and
    /// Launch Context, §Launch context arrives with your `access_token`).
    pub patient: Option<&'a str>,
    /// The `ehrId` of the SMART on openEHR launch context (`master07
    /// §Context Selection`).
    pub ehr_id: Option<&'a str>,
    /// The value of the deployment's [`PatientClaim`].
    pub claim: Option<&'a str>,
}

impl std::fmt::Debug for PersonContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersonContext").finish_non_exhaustive()
    }
}

/// The claim a deployment names the patient of a person's own token in, a
/// dotted path such as `patient_id` or `person.patient_id`.
///
/// A product attaches it to its resource server with `with_extension`, so
/// every caller that server admits carries it, and
/// [`Caller::person`] reads it. No specification names such a
/// claim: our own design, FerroEHR's ABAC patient claim moved here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatientClaim(String);

/// A [`PatientClaim`] path that is blank, has an empty step, or carries
/// whitespace.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the patient claim path is blank, has an empty step or carries whitespace")]
pub struct PatientClaimError;

impl PatientClaim {
    /// Returns the claim at the dotted `path`.
    ///
    /// # Errors
    ///
    /// [`PatientClaimError`] when `path` is blank, has an empty step, or
    /// carries whitespace, which would name no claim.
    pub fn new(path: impl Into<String>) -> Result<Self, PatientClaimError> {
        let path = path.into();
        if !crate::roles::well_formed(&path) {
            return Err(PatientClaimError);
        }
        Ok(Self(path))
    }

    /// Returns the dotted path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.0
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
