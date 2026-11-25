// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Why a configuration was refused: each refusal names the key, never a
//! value, so no secret reaches a message, a `Debug` rendering or a log.

use std::path::PathBuf;

/// A refused configuration.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The file, the environment or a `--set` pair does not read as the
    /// tree: a file that cannot be read, bad TOML, an unknown key, or a value
    /// of the wrong type.
    #[error(transparent)]
    Load(#[from] ferrohealth_config::error::ConfigError),
    /// A key the server needs is not set.
    #[error("`{key}` is not set")]
    Missing {
        /// The key.
        key: &'static str,
    },
    /// The issuer is no URL the rule of RFC 8414 §2 admits.
    #[error("`ferrosmart.issuer` is not an issuer identifier")]
    Issuer {
        /// Why.
        #[source]
        source: ferrohealth_smart::metadata::DiscoveryError,
    },
    /// The issuer's path is not the base path the server serves under.
    #[error("the path of `ferrosmart.issuer` is not `server.base_path`")]
    IssuerPath,
    /// No resource server is configured, or a base URL is outside the rule.
    #[error("`ferrosmart.resource`: {rule}")]
    Resource {
        /// The rule broken.
        rule: &'static str,
    },
    /// A resource server's base URL is outside the rule.
    #[error("a `ferrosmart.resource` base is no https URL without a query or a fragment")]
    ResourceBase {
        /// Why.
        #[source]
        source: ferrohealth_smart::metadata::DiscoveryError,
    },
    /// `[ferrosmart.backend]` breaks a rule.
    #[error("`ferrosmart.backend`: {rule}")]
    Backend {
        /// The rule broken.
        rule: &'static str,
    },
    /// An upstream provider's table breaks a rule.
    #[error("`ferrosmart.upstream`: {rule}")]
    Upstream {
        /// The rule broken.
        rule: &'static str,
    },
    /// An upstream provider's assurance cannot be met.
    #[error("`ferrosmart.upstream` `{name}`")]
    Assurance {
        /// The provider's name.
        name: String,
        /// Why.
        #[source]
        source: crate::assurance::AssuranceError,
    },
    /// An upstream preset's compiled file does not read.
    #[error(transparent)]
    Preset(#[from] crate::upstream::preset::PresetError),
    /// No `[[ferrosmart.upstream]]` entry has the name asked for.
    #[error("no `ferrosmart.upstream` entry is named `{name}`; the names are: {known}")]
    NoUpstream {
        /// The name asked for.
        name: String,
        /// The names configured, comma-separated.
        known: String,
    },
    /// A SAML table breaks a rule, or names a key or file that cannot be
    /// used.
    #[error(transparent)]
    Saml(#[from] crate::upstream::saml::SamlConfigError),
    /// A wallet table breaks a rule, or names a key, certificate or file
    /// that cannot be used.
    #[error(transparent)]
    Wallet(#[from] crate::upstream::wallet::WalletConfigError),
    /// `ferrosmart.branding.smart_style_url` is no https URL.
    #[error("`ferrosmart.branding.smart_style_url` is no https URL")]
    StyleUrl,
    /// `[ferrosmart.brand]` breaks a rule.
    #[error(transparent)]
    Brand(#[from] crate::brands::BrandError),
    /// `[ferrosmart.registration]` breaks a rule.
    #[error("`ferrosmart.registration`: {rule}")]
    Registration {
        /// The rule broken.
        rule: &'static str,
    },
    /// A role table breaks a rule.
    #[error("`ferrosmart.role`: {rule}")]
    Role {
        /// The rule broken.
        rule: &'static str,
    },
    /// A lifetime that must be positive is zero.
    #[error("`{key}` must be greater than zero")]
    Zero {
        /// The key.
        key: &'static str,
    },
    /// The access token lifetime is longer than one hour.
    #[error("`ferrosmart.access_token_lifetime` is at most one hour")]
    LongLifetime,
    /// A key file cannot be read.
    #[error("`{key}` cannot be read at {}", path.display())]
    KeyFile {
        /// The key.
        key: &'static str,
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// A key file holds no RSA private key that signs under `RS256`.
    #[error("`{key}` holds no RSA private key for RS256")]
    Key {
        /// The key.
        key: &'static str,
        /// Why.
        #[source]
        source: ferrohealth_smart::client::assertion::AssertionError,
    },
    /// A secret is set twice, or its `_file` sibling cannot be read.
    #[error(transparent)]
    Secret(#[from] ferrohealth_secret::file::SecretError),
    /// `[ferrosmart.audit.feed]` describes no client that can be built.
    #[error("`ferrosmart.audit.feed` describes no usable endpoint")]
    AuditFeed {
        /// Why.
        #[source]
        source: ferrohealth_smart::client::outbound::OutboundError,
    },
    /// `[ferrosmart.audit.feed]` names no `https` FHIR base.
    #[error("`ferrosmart.audit.feed` is no https FHIR base")]
    AuditBase {
        /// Why.
        #[source]
        source: ihe_atna::atna::feed::FeedConfigError,
    },
    /// `ferrosmart.keys.private_key_files` names one key twice.
    #[error("`ferrosmart.keys.private_key_files` names the key {kid} twice")]
    RepeatedKey {
        /// The key's `kid`.
        kid: String,
    },
    /// The rotation period is shorter than a key stays published after it
    /// stops signing.
    #[error("`ferrosmart.keys.rotation_period` is at least {}s", shortest.as_secs())]
    RotationPeriod {
        /// The shortest period.
        shortest: std::time::Duration,
    },
    /// The keys of the ring repeat one another.
    #[error("`ferrosmart.keys` names one key twice")]
    KeyRing {
        /// Why.
        #[source]
        source: ferrohealth_smart::client::keys::KeyRingError,
    },
}
