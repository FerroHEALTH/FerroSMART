// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The configuration sections every product embeds: `[auth]` for the
//! surface it guards, and `[<lane>.credentials]` for each upstream it
//! calls.
//!
//! Both are read with `deny_unknown_fields`, every default lives in the
//! section's `Default`, and every secret has a `_file` sibling of which
//! exactly one is set. A product's loader applies its own environment
//! overrides over these types and resolves them at load, so a section that
//! breaks a rule refuses the start (no specification governs the model: our
//! own design).

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::jws::algorithm::Algorithm;
use ferrohealth_config::tls::TlsClientSection;
use ferrohealth_config::units::Duration;
use ferrohealth_secret::secret_url::RedactedUrl;
use secrecy::SecretString;
use serde::Deserialize;
use serde::Serialize;

use crate::assurance::AssuranceSection;
use crate::basic::PasswordStore;
use crate::basic::StoreError;
use crate::client::assertion::AssertionError;
use crate::config::credentials::OauthSection;
use crate::federation::FederationSection;
use crate::federation::person::AttributesSection;
use crate::kind::IssuerKind;
use crate::metadata::DiscoveryError;
use crate::party::config::PartyError;
use crate::party::config::PartySection;
use crate::profile::ProfileKeys;
use crate::resource::ResourceError;
use crate::resource::Settings;
use crate::sender::SenderConstraint;

mod auth;
pub mod credentials;
pub mod endpoint;
mod issuer;
pub mod onward;
mod read;
mod shapes;

/// A section that breaks a rule, named by its key.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The `[auth.dpop]` settings break a rule.
    #[error("auth.dpop is refused")]
    Dpop {
        /// The rule.
        #[source]
        source: crate::sender::proof::ProofSettingsError,
    },
    /// A token endpoint carries userinfo or a fragment (RFC 6749 §3.2, RFC
    /// 9110 §4.2.4); the URL is never quoted.
    #[error(
        "{key} carries {part}, which a token endpoint must not (RFC 6749 §3.2, RFC 9110 §4.2.4)"
    )]
    TokenEndpoint {
        /// The key.
        key: &'static str,
        /// What it carries: `userinfo` or a `fragment`.
        part: &'static str,
    },
    /// A key is set that nothing in the section uses.
    #[error("{key} is set, but signs nothing without {needs}")]
    Unused {
        /// The key.
        key: &'static str,
        /// What would use it.
        needs: &'static str,
    },
    /// A key the section needs is not set, or does not parse.
    #[error("{key} is not set or does not parse")]
    Missing {
        /// The key.
        key: &'static str,
    },
    /// Both a secret and its `_file` sibling are set, or neither.
    #[error("exactly one of {key} and {key}_file must be set")]
    Secret {
        /// The key of the secret.
        key: &'static str,
    },
    /// A secret file could not be read.
    #[error("the secret file {} could not be read", path.display())]
    SecretFile {
        /// The file.
        path: PathBuf,
        /// What the file system reported.
        #[source]
        source: std::io::Error,
    },
    /// Two keys that exclude each other are both set.
    #[error("{left} and {right} exclude each other")]
    Exclusive {
        /// The one key.
        left: &'static str,
        /// The other.
        right: &'static str,
    },
    /// An issuer entry breaks a resource-server rule.
    #[error("the issuer {issuer:?} is refused")]
    Issuer {
        /// The issuer.
        issuer: String,
        /// The rule.
        #[source]
        source: Box<ResourceError>,
    },
    /// An `[auth.issuer.<name>]` URL carries userinfo, which an issuer
    /// identifier never holds (OpenID Connect Core 1.0 §1.2), shown masked.
    #[error("auth.issuer {issuer} carries userinfo, which an issuer identifier never holds")]
    IssuerUserinfo {
        /// The issuer, its userinfo masked ([`mask_userinfo`]).
        issuer: String,
    },
    /// An issuer's `jwks_file` holds a symmetric key (`kty` `oct`), which
    /// a verifier of asymmetric signatures never holds (RFC 8725 §3.1).
    #[error(
        "the jwks_file of auth.issuer {issuer} holds a symmetric key at index {index} (kid {kid:?})"
    )]
    JwksSymmetricKey {
        /// The issuer whose file it is.
        issuer: String,
        /// The key's index in `keys`.
        index: usize,
        /// The key's `kid`, when it has one.
        kid: Option<String>,
    },
    /// An issuer's `jwks_file` holds private key material, which a verifier
    /// never needs (RFC 7517 Appendix A.2).
    #[error(
        "the jwks_file of auth.issuer {issuer} holds private key material ({member}) at index {index} (kid {kid:?})"
    )]
    JwksPrivateKey {
        /// The issuer whose file it is.
        issuer: String,
        /// The key's index in `keys`.
        index: usize,
        /// The key's `kid`, when it has one.
        kid: Option<String>,
        /// The first private member the key carries, never its value.
        member: &'static str,
    },
    /// A Basic user or credential breaks a rule.
    #[error("a Basic user or credential is refused")]
    Basic {
        /// The rule.
        #[source]
        source: StoreError,
    },
    /// A scope token is outside the RFC 6749 §3.3 character set.
    #[error("the scope token {scope:?} is outside the RFC 6749 scope character set")]
    Scope {
        /// The token.
        scope: String,
    },
    /// The product scope is in neither extension form of SMART App Launch
    /// 2.2.0, Scopes and Launch Context, §Extensibility.
    #[error("the product scope {scope:?} is neither a full URI nor a string starting with __")]
    ProductScope {
        /// The scope.
        scope: String,
    },
    /// A capability is in neither the SMART App Launch 2.2.0 list nor the
    /// SMART on openEHR list, and is no full URI.
    #[error("the capability {capability:?} is not a SMART capability and not a full URI")]
    Capability {
        /// The capability.
        capability: String,
    },
    /// The issuer of the client credentials grant breaks the RFC 8414 §2
    /// URL rule.
    #[error("credentials.oauth.issuer is refused")]
    OauthIssuer {
        /// The rule.
        #[source]
        source: DiscoveryError,
    },
    /// A resource indicator carries a fragment, which RFC 8707 §2 forbids.
    #[error("{key} carries a fragment, which a resource indicator must not")]
    Fragment {
        /// The key.
        key: &'static str,
    },
    /// The assertion key could not be loaded.
    #[error("the private key of the client assertion is refused")]
    Key {
        /// Why.
        #[source]
        source: AssertionError,
    },
    /// The `DPoP` key could not be loaded.
    #[error("the DPoP key is refused")]
    DpopKey {
        /// Why.
        #[source]
        source: crate::client::dpop::DpopKeyError,
    },
    /// The assertion keys form no ring.
    #[error("the assertion keys form no key ring")]
    KeyRing {
        /// Why.
        #[source]
        source: crate::client::keys::KeyRingError,
    },
    /// The `authorization_details` is not of RFC 9396 §2 shape.
    #[error("credentials.oauth.authorization_details is not of RFC 9396 §2 shape")]
    AuthorizationDetails {
        /// Why.
        #[source]
        source: crate::client::authorization_details::AuthorizationDetailsError,
    },
    /// A `mtls_alias_hosts` entry is no host.
    #[error("credentials.oauth.mtls_alias_hosts holds {host:?}, which is no host")]
    AliasHost {
        /// The entry.
        host: String,
    },
    /// The grant breaks a rule of its method or security profile.
    #[error("the credentials.oauth grant is refused")]
    Grant {
        /// Why.
        #[source]
        source: Box<crate::client::TokenError>,
    },
    /// An issuer with `mode = "introspection"` in a build without the `fetch` feature,
    /// which links no HTTP client to call the endpoint with.
    #[error("auth.issuer.mode = \"introspection\" needs the fetch feature")]
    IntrospectionUnavailable,
    /// The introspection settings break a rule.
    #[cfg(feature = "fetch")]
    #[error("the auth.issuer.introspection settings are refused")]
    Introspection {
        /// The rule.
        #[source]
        source: Box<crate::resource::introspection::IntrospectionError>,
    },
    /// An outbound endpoint table breaks a rule.
    #[error("the endpoint table is refused: {rule}")]
    Endpoint {
        /// The rule it breaks.
        rule: &'static str,
    },
    /// A `tls` table names TLS material and was resolved without the
    /// product's [`TlsBuilder`], the one reader of TLS material.
    #[error("{key} names TLS material; resolve it with the product's TLS builder")]
    TlsNotBuilt {
        /// The dotted key of the table.
        key: &'static str,
    },
    /// The product's [`TlsBuilder`] refused a `tls` table.
    #[error("{key} is refused")]
    TlsBuild {
        /// The dotted key of the table, such as `auth.tls` or, for an
        /// outbound endpoint table at `cdr`, `cdr.tls`.
        key: String,
        /// What the builder reported.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The `credentials.onward` table names an issuer or a target the onward
    /// client refuses.
    #[cfg(feature = "fetch")]
    #[error("credentials.onward is refused")]
    Onward {
        /// Why.
        #[source]
        source: Box<crate::client::onward::OnwardError>,
    },
    /// `credentials.onward.actor_assertion` is set on a lane that cannot
    /// sign an actor assertion: its `oauth` table holds no assertion key, or
    /// its issuer exchanges by the JWT bearer grant, which has no actor
    /// (RFC 7523 §2.1).
    #[cfg(feature = "fetch")]
    #[error("credentials.onward.actor_assertion is refused")]
    OnwardActor {
        /// Why.
        #[source]
        source: Box<crate::client::onward::OnwardError>,
    },
    /// A product role list names an issuer that is not a `persons` issuer.
    #[error("the {key} list names the issuer {name:?}, which is not a persons issuer")]
    RoleIssuer {
        /// The key of the product's list.
        key: &'static str,
        /// The issuer's name.
        name: String,
        /// Its kind.
        kind: IssuerKind,
    },
    /// A `federation` issuer without its one `[auth.issuer.<name>.federation]` table,
    /// or a table naming no trusted `federation` issuer or naming one twice.
    #[error("the federation table of {issuer:?} is refused: {reason}")]
    Federation {
        /// The issuer.
        issuer: String,
        /// Which rule.
        reason: &'static str,
    },
    /// An `[auth.issuer.<name>.attributes]` table naming no trusted `persons`,
    /// `patients` or `machines` issuer, naming one twice, or naming a field
    /// other than the purpose of use on a `patients` or `machines` issuer.
    #[error("the attributes table of {issuer:?} is refused: {reason}")]
    Attributes {
        /// The issuer.
        issuer: String,
        /// Which rule.
        reason: &'static str,
    },
    /// An `[auth.issuer.<name>.party]` table breaks a rule.
    #[error("an [auth.issuer.<name>.party] table is refused")]
    Party {
        /// The rule.
        #[source]
        source: PartyError,
    },
    /// A key names an issuer by a name no `[auth.issuer.<name>]` table
    /// carries.
    #[error("{key} names the issuer {name:?}, and the issuers are {known:?}")]
    UnknownIssuer {
        /// The key.
        key: &'static str,
        /// The name it gives.
        name: String,
        /// The names of the `[auth.issuer.<name>]` tables.
        known: Vec<String>,
    },
    // NOTE: cargo-semver-checks enum_no_repr_variant_discriminant_changed, a new
    // variant goes last, so no earlier variant's implicit discriminant moves.
    /// Two `[auth.issuer.<name>]` tables name one issuer, JWT or introspected
    /// alike; a token is checked under one table per issuer, so the later
    /// table would replace the earlier.
    #[error(
        "the {key} tables {first:?} and {second:?} both name the issuer {issuer:?}; \
         one issuer takes one table"
    )]
    DuplicateIssuer {
        /// The key of the tables.
        key: &'static str,
        /// The issuer, with any userinfo masked.
        issuer: String,
        /// The name of the first table naming it.
        first: String,
        /// The name of the second.
        second: String,
    },
    /// An `[auth.issuer.<name>]` name is outside the name form: a lower-case
    /// ASCII letter, then lower-case letters, digits and `_`, at most 64.
    #[error(
        "the issuer name {name:?} is refused: a lower-case letter, then lower-case letters, \
         digits and _, at most 64"
    )]
    IssuerName {
        /// The name.
        name: String,
    },
}

/// The `[auth]` section: the surface's issuers, each an
/// `[auth.issuer.<name>]` table, the discovery document's options and the
/// Basic users.
///
/// Every setting of an issuer lives on its own table, its party binding,
/// federation and attribute tables nested under it, and every other key
/// names an issuer by its table's name: no section-level value stands in
/// for one an issuer leaves out.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthSection {
    /// Whether inbound authentication is on; a product may refuse `false`.
    pub enabled: bool,
    /// The `[auth.issuer.<name>]` tables by name, each issuer with its own
    /// settings. The environment and every other key address an issuer by
    /// its name, never by a position.
    pub issuer: BTreeMap<String, IssuerEntry>,
    /// The realm the challenges name; empty for none, which a product
    /// replaces with its own default.
    pub realm: String,
    /// The SMART capabilities the discovery document adds, each a
    /// capability SMART App Launch 2.2.0 or the SMART on openEHR draft
    /// defines, or a full URI.
    pub capabilities: Vec<String>,
    /// The scopes the discovery document lists as `scopes_supported`: only
    /// scopes the product honours, because "the server SHALL support all
    /// scopes listed here".
    pub scopes_supported: Vec<String>,
    /// The name of the issuer the discovery document describes; absent for
    /// the one issuer the rule of [`crate::resource::described`] picks.
    pub described_issuer: Option<String>,
    /// The product's own scope, a full URI or a string starting with `__`;
    /// empty for none.
    pub product_scope: String,
    /// The Basic users of the surface; absent for no Basic.
    pub basic: Option<BasicSection>,
    /// The `DPoP` proof check of the surface; absent for none, so a `DPoP`
    /// request is refused as carrying no admitted credential.
    pub dpop: Option<crate::sender::proof::DpopSection>,
    /// The TLS of the discovery document, the key set and the introspection
    /// calls of every issuer: trust roots beside the platform's, for an
    /// issuer behind a private certificate authority, a client identity and
    /// the minimum version. The crate reads none of it: the product's
    /// [`TlsBuilder`] builds it once at start.
    pub tls: TlsClientSection,
}

/// How a bearer token is checked.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum AuthMode {
    /// The token is a JWT, checked against the issuer's key set (RFC 9068).
    #[default]
    Jwt,
    /// The token is posted to the issuer's introspection endpoint
    /// (RFC 7662), for a token the resource server cannot read itself.
    Introspection,
}

/// The `[auth.issuer.<name>.introspection]` table.
///
/// The product authenticates its call with exactly one of `client` (the
/// client authentication of the token endpoint, RFC 7662 §2.1) and `bearer`
/// (a token from the client credentials grant, SMART App Launch 2.2.0,
/// Token Introspection). Each takes the fields of
/// `[<lane>.credentials.oauth]`, and a refusal names those keys; `client`
/// stands in the table's issuer when it names neither `issuer` nor
/// `token_endpoint`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct IntrospectionSection {
    /// The introspection endpoint; empty for the one the issuer's metadata
    /// names. It renders with its userinfo and its query masked.
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub endpoint: ferrohealth_secret::secret_url::SecretUrl,
    /// The longest an active response is used; `0s` caches nothing.
    pub cache_max_age: Duration,
    /// The most responses held at once.
    pub cache_capacity: usize,
    /// The client authentication of the introspection call.
    pub client: Option<OauthSection>,
    /// The client credentials grant whose token authorizes the call.
    pub bearer: Option<OauthSection>,
}

/// One `[auth.issuer.<name>]` table: the issuer, its kind, how its tokens
/// are checked, its profile keys, and the tables nested under it.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct IssuerEntry {
    /// The issuer identifier. It renders with any userinfo masked, as
    /// [`SecretUrl`](ferrohealth_secret::secret_url::SecretUrl) renders
    /// itself.
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub issuer: ferrohealth_secret::secret_url::SecretUrl,
    /// `federation` for another party's issuer; unset for a SMART
    /// authorization server ([`IssuerKind`]).
    pub kind: Option<IssuerKind>,
    /// The audiences, of which a token's `aud` must contain one; the base
    /// URLs the product resolves the section for when empty.
    pub audience: Vec<String>,
    /// The signature algorithms admitted.
    #[cfg_attr(feature = "schema", schemars(with = "Vec<String>"))]
    pub algorithms: Vec<Algorithm>,
    /// The clock skew, at most `300s`.
    pub clock_skew: Duration,
    /// How long a held key set is used.
    pub jwks_max_age: Duration,
    /// The shortest time between two reads of the key set.
    pub jwks_refresh_interval: Duration,
    /// A key set file handed over out of band, in place of the issuer's
    /// `jwks_uri`; empty for none.
    pub jwks_file: String,
    /// How long one call to the authorization server may take.
    pub timeout: Duration,
    /// How the issuer's tokens are checked.
    pub mode: AuthMode,
    /// The introspection check, under `mode = "introspection"`.
    pub introspection: Option<IntrospectionSection>,
    /// The `[auth.issuer.<name>.federation]` table, which a `federation`
    /// issuer requires and no other kind takes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation: Option<FederationSection>,
    /// The `[auth.issuer.<name>.attributes]` table: where a SMART issuer
    /// states its professionals' attributes and the purpose of use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<AttributesSection>,
    /// The `[auth.issuer.<name>.party]` table of a SMART issuer whose
    /// logins are bound to a party.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub party: Option<PartySection>,
    /// The assurance level the issuer's tokens carry.
    pub assurance: Option<AssuranceSection>,
    /// Whether the issuer's tokens must be bound to a `DPoP` key or a client
    /// certificate: `none` (the default) or `required` ([`crate::sender`]).
    pub sender_constraint: SenderConstraint,
    /// The claims the issuer's roles are read from, each a dotted path that
    /// [`crate::roles`] reads, a claim name with dots included; by
    /// default `roles`, `groups` and `entitlements` (RFC 9068 §2.2.3.1), and
    /// none, never settable, on a `federation` issuer.
    pub role_claims: Option<Vec<String>>,
    /// The `[auth.issuer.<name>.profile]` table: the profile keys set over
    /// the defaults.
    #[serde(skip_serializing_if = "crate::config::is_default")]
    pub profile: ProfileKeys,
}

/// The `[auth.basic]` table.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BasicSection {
    /// The users.
    pub users: Vec<BasicUser>,
    /// How long a credential that verified is kept, so a repeat request
    /// skips the key derivation; `5min` by default, `0s` keeps none.
    pub cache_ttl: Duration,
}

/// One `[[auth.basic.users]]` entry: a person's credential, never a
/// machine's ([`crate::resource::Caller::basic`]).
///
/// The entry holds the credential alone. The scope and the roles of the
/// user are the product's to grant: from its own configuration through
/// [`BasicGrants`], or from its own data through
/// [`crate::resource::Caller::with_granted_scope`] and
/// [`crate::resource::Caller::with_granted_roles`] (no specification governs
/// this: our own design).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BasicUser {
    /// The user-id.
    pub user: String,
    /// The Argon2id PHC string of the password, rendered redacted.
    #[serde(
        serialize_with = "shapes::redact",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "Option<String>"))]
    pub password_hash: Option<SecretString>,
    /// The file holding that PHC string.
    pub password_hash_file: Option<PathBuf>,
}

// The exhaustive pattern makes a new field a compile error here until it is compared.
impl PartialEq for BasicUser {
    fn eq(&self, other: &Self) -> bool {
        let Self {
            user,
            password_hash,
            password_hash_file,
        } = self;
        shapes::same_secret(password_hash.as_ref(), other.password_hash.as_ref())
            && *user == other.user
            && *password_hash_file == other.password_hash_file
    }
}

impl Eq for BasicUser {}

/// The scopes and roles a product grants its Basic users, by user-id.
///
/// A product that keeps them in its own configuration composes the table
/// into its own section and hands it to
/// [`crate::basic::PasswordStore::with_grants`].
///
/// ```toml
/// [operator]
/// scopes = ["user/*.rs"]
/// roles = ["auditor"]
/// ```
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct BasicGrants {
    /// The grant of each user, by user-id.
    pub users: BTreeMap<String, BasicGrant>,
}

/// What a product grants one Basic user.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BasicGrant {
    /// The scopes the user is granted, never a `system/` scope.
    pub scopes: Vec<String>,
    /// The roles the user is granted, one word each ([`crate::roles`]).
    pub roles: Vec<String>,
}

/// What the `[auth]` section resolves to.
#[derive(Debug)]
pub struct Resolved {
    /// Whether inbound authentication is on.
    pub enabled: bool,
    /// The resource-server settings of each JWT issuer, in name order.
    pub issuers: Vec<Settings>,
    /// The kind of every issuer the section trusts, by identifier.
    pub kinds: BTreeMap<String, IssuerKind>,
    /// The identifier of every issuer the section trusts, by name.
    pub names: BTreeMap<String, String>,
    /// The Basic users, when the surface admits Basic.
    pub basic: Option<PasswordStore>,
    /// The realm the challenges name, when one is set.
    pub realm: Option<String>,
    /// The SMART capabilities the discovery document adds.
    pub capabilities: Vec<String>,
    /// The scopes the discovery document lists.
    pub scopes_supported: Vec<String>,
    /// The identifier of the issuer the discovery document describes, when
    /// one is named; the `named` argument of
    /// [`crate::resource::described::describe`].
    pub described_issuer: Option<ferrohealth_secret::secret_url::SecretUrl>,
    /// The product's own scope, when one is set.
    pub product_scope: Option<String>,
    /// The `[auth.dpop]` table of the surface, checked, when one is set; a
    /// product builds its [`crate::sender::proof::ProofCheck`] from
    /// [`crate::sender::proof::DpopSection::settings`] with its own public
    /// URL and its replay store.
    pub dpop: Option<crate::sender::proof::DpopSection>,
    /// The introspection check of each `mode = "introspection"` issuer, in
    /// name order.
    #[cfg(feature = "fetch")]
    pub introspection: Vec<crate::resource::introspection::IntrospectionSettings>,
    /// The party tables, each checked against its issuer and carrying its
    /// identifier.
    pub party: Vec<PartySection>,
}

/// The product's reader of an outbound `tls` table, which builds the TLS
/// configuration a connection of this crate speaks.
///
/// The crate reads no TLS material itself: every table that names some is
/// handed to the builder with its dotted key, so the family has one reader
/// of TLS material, `ferrohealth-server`'s `TlsClient` (feature
/// `server-tls` implements this trait over it as `ServerTls`). No
/// specification governs the seam: our own design.
pub trait TlsBuilder {
    /// Builds the configuration `section` names, at the dotted `key`.
    ///
    /// # Errors
    ///
    /// Returns the builder's own error when the material cannot be read or
    /// is refused; it never quotes the material.
    fn build(
        &self,
        key: &str,
        section: &TlsClientSection,
    ) -> Result<crate::client::PresentedTls, Box<dyn std::error::Error + Send + Sync>>;
}

/// Builds `section` at `key` with `builder`, naming the key in a refusal.
pub(crate) fn build_tls(
    builder: &dyn TlsBuilder,
    key: &str,
    section: &TlsClientSection,
) -> Result<crate::client::PresentedTls, ConfigError> {
    builder
        .build(key, section)
        .map_err(|source| ConfigError::TlsBuild {
            key: key.to_owned(),
            source,
        })
}

/// The [`TlsBuilder`] over `ferrohealth-server`'s `tls_client::TlsClient`:
/// the table's roots beside the platform's verifier, its identity and its
/// minimum version.
#[cfg(feature = "server-tls")]
#[derive(Debug, Clone, Copy, Default)]
pub struct ServerTls;

#[cfg(feature = "server-tls")]
impl TlsBuilder for ServerTls {
    fn build(
        &self,
        key: &str,
        section: &TlsClientSection,
    ) -> Result<crate::client::PresentedTls, Box<dyn std::error::Error + Send + Sync>> {
        let client = ferrohealth_server::tls_client::TlsClient::read(key, section)?;
        let config = client.platform_config()?;
        Ok(crate::client::PresentedTls::new(
            std::sync::Arc::new(config),
            client.certificate().cloned(),
        ))
    }
}

/// The text a set secret, or the userinfo and the query of a URL, is
/// rendered as: the family mask of `ferrohealth-secret`, so every product
/// renders every secret of its configuration one way.
pub const REDACTED: &str = ferrohealth_secret::REDACTED;

/// Returns whether `value` is its type's default, so a default table is
/// left out of a rendering.
pub(crate) fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}

/// Returns `text` with the userinfo and the query of the URL it holds
/// replaced by [`REDACTED`], or `text` itself when it holds no URL.
///
/// A text carrying `://` renders through
/// `ferrohealth_secret::secret_url::RedactedUrl`, the family mask: the
/// scheme, the host, the port, the path and the fragment show as written, so
/// the rendering still names the host and path an operator configured, and a
/// value no URL parser accepts, such as a password holding a character a URL
/// forbids, is masked all the same. Any other text is kept as written (no
/// specification governs the rendering: our own design).
///
/// ```
/// use ferrohealth_smart::config::mask_userinfo;
///
/// let masked = mask_userinfo("https://user:secret@idp.example:443/token");
/// assert_eq!(masked, "https://***@idp.example:443/token");
/// assert_eq!(mask_userinfo("postgres://u:p[x@db/x"), "postgres://***@db/x");
/// assert_eq!(mask_userinfo("https://host/path/@handle"), "https://host/path/@handle");
/// assert_eq!(mask_userinfo("https://host?next=a@b"), "https://host?***");
/// assert_eq!(mask_userinfo("not a url"), "not a url");
/// ```
#[must_use]
pub fn mask_userinfo(text: &str) -> String {
    if text.contains("://") {
        RedactedUrl(text).to_string()
    } else {
        text.to_owned()
    }
}

/// Returns `url` as an error or a log line names it: with any userinfo
/// masked, and text that is no URL as written ([`mask_userinfo`]).
pub(crate) fn shown(url: &ferrohealth_secret::secret_url::SecretUrl) -> String {
    mask_userinfo(url.expose())
}
