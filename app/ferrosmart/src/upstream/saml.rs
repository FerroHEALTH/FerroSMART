// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A SAML 2.0 identity provider upstream (`docs/architecture.md` §13.26).
//!
//! It holds the `[ferrosmart.upstream.saml]` table, FerroSMART's own
//! `[ferrosmart.saml]` service provider, and the login that reads the
//! provider's metadata and resolves an artifact.
//!
//! The protocol machinery is [`crate::saml`], which holds no configuration
//! and does no I/O; this module gives it both. FerroSMART is one service
//! provider for every SAML provider: one entity ID, one signing key, one
//! metadata document at `GET {issuer}/saml/metadata` and one assertion
//! consumer service at `{issuer}/saml/acs` (saml-metadata-2.0-os §2.4.4;
//! one entity for every partner is our own design).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use ferrohealth_config::tls::TlsClientSection;
use ferrohealth_config::units::Duration as Span;
use ferrohealth_smart::config::TlsBuilder as _;
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::saml::artifact::{Artifact, ArtifactResolve, SOAP_ACTION};
use crate::saml::keys::{DecryptionKey, KeyError, SigningKey, TrustedKey};
use crate::saml::metadata::{IdentityProvider, MetadataError, ServiceProvider};
use crate::saml::request::AuthnRequest;
use crate::saml::response::{self, Expectations, Login};
use crate::saml::{HTTP_ARTIFACT, HTTP_POST, HTTP_REDIRECT, Refusal};

/// The route of FerroSMART's service provider metadata under the issuer.
pub const METADATA_ROUTE: &str = "/saml/metadata";
/// The route of the assertion consumer service under the issuer.
pub const ACS_ROUTE: &str = "/saml/acs";

/// The largest metadata document or SOAP response read from an identity
/// provider, the cap `crate::saml` parses under.
const MAX_BODY: usize = 256 * 1024;

/// `[ferrosmart.saml]`: FerroSMART as a SAML 2.0 service provider, needed
/// once any provider has a `[ferrosmart.upstream.saml]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServiceProviderSection {
    /// FerroSMART's entity ID, an absolute URI; empty takes the metadata
    /// URL, `{issuer}/saml/metadata`.
    pub entity_id: String,
    /// The PKCS#8 PEM private key that signs every request.
    pub signing_key_file: Option<PathBuf>,
    /// The PEM certificate of that key, which the metadata publishes.
    pub signing_certificate_file: Option<PathBuf>,
    /// `[[ferrosmart.saml.decryption]]`: the RSA keys an identity provider
    /// encrypts assertions, identifiers and attributes for.
    pub decryption: Vec<KeyPairSection>,
    /// `[ferrosmart.saml.tls]`: the client identity FerroSMART presents to
    /// an artifact resolution service, which saml-profiles-2.0-os §4.1.4.4
    /// requires, and the trust roots beside the platform's for every call
    /// to an identity provider.
    pub tls: TlsClientSection,
}

/// One `[[ferrosmart.saml.decryption]]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct KeyPairSection {
    /// The PKCS#8 PEM private key.
    pub key_file: Option<PathBuf>,
    /// The PEM certificate of its public half.
    pub certificate_file: Option<PathBuf>,
}

/// The binding FerroSMART sends its `AuthnRequest` by.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestBinding {
    /// HTTP-Redirect (saml-bindings-2.0-os §3.4), the default.
    #[default]
    Redirect,
    /// HTTP-POST (saml-bindings-2.0-os §3.5).
    Post,
}

/// The binding the identity provider answers by.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ResponseBinding {
    /// HTTP-POST (saml-bindings-2.0-os §3.5), the default.
    #[default]
    Post,
    /// HTTP-Artifact (saml-bindings-2.0-os §3.6), resolved over mutual TLS.
    Artifact,
}

impl ResponseBinding {
    /// The binding's URI, as the request's `ProtocolBinding` names it.
    #[must_use]
    pub const fn uri(self) -> &'static str {
        match self {
            Self::Post => HTTP_POST,
            Self::Artifact => HTTP_ARTIFACT,
        }
    }
}

/// `[ferrosmart.upstream.saml]`: one SAML 2.0 identity provider.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SamlSection {
    /// The provider's entity ID, which its metadata describes and every
    /// message it sends names as its `Issuer`.
    pub entity_id: String,
    /// The `https` URL the provider's metadata is read from; exclusive with
    /// `metadata_file`.
    pub metadata_url: String,
    /// The file the provider's metadata is read from; exclusive with
    /// `metadata_url`.
    pub metadata_file: Option<PathBuf>,
    /// The PEM certificates whose keys must sign the metadata
    /// (saml-metadata-2.0-os §3); empty trusts it as read.
    pub metadata_signing_certificate_files: Vec<PathBuf>,
    /// How often the metadata is read again, so a rolled-over key is
    /// trusted without a restart.
    pub metadata_refresh: Span,
    /// The binding the `AuthnRequest` is sent by.
    pub request_binding: RequestBinding,
    /// The binding the provider answers by.
    pub response_binding: ResponseBinding,
    /// Whether every request asks the provider to authenticate the person
    /// afresh (`ForceAuthn`, saml-core-2.0-os §3.4.1).
    pub force_authn: bool,
    /// The name identifier format asked for (`NameIDPolicy`); empty asks
    /// for none.
    pub name_id_format: String,
    /// The `AuthnContextClassRef` values at or above the provider's minimum
    /// assurance, in the provider's own vocabulary: the request asks for
    /// them as an exact match and a login of any other class is refused
    /// (saml-core-2.0-os §3.3.2.2.1); empty asks for none and accepts any.
    pub authn_contexts: Vec<String>,
    /// The clock skew admitted at each time bound (saml-core-2.0-os §1.3.3
    /// as errata E92 adds to it).
    pub clock_skew: Span,
    /// The attribute whose one value is the person's identifier at the
    /// provider; empty takes the subject's `NameID`.
    pub subject_attribute: String,
    /// The claims a login yields, each by name the `Name` of the attribute
    /// whose values it takes: a string for one value, an array for more.
    /// `name`, `preferred_username` and `email` are read as the ID Token
    /// claims of those names are, and a `fhirUser` lookup (#674) reads
    /// any.
    pub claims: BTreeMap<String, String>,
    /// The claim of `claims` that holds the person's `fhirUser` URL; empty
    /// when the provider carries none.
    pub fhir_user_claim: String,
    /// The claims of `claims` that hold the person's roles.
    pub role_claims: Vec<String>,
}

impl Default for SamlSection {
    fn default() -> Self {
        Self {
            entity_id: String::new(),
            metadata_url: String::new(),
            metadata_file: None,
            metadata_signing_certificate_files: Vec::new(),
            metadata_refresh: Span::from_hours(24),
            request_binding: RequestBinding::default(),
            response_binding: ResponseBinding::default(),
            force_authn: false,
            name_id_format: String::new(),
            authn_contexts: Vec::new(),
            clock_skew: Span::from_mins(3),
            subject_attribute: String::new(),
            claims: BTreeMap::new(),
            fhir_user_claim: String::new(),
            role_claims: Vec::new(),
        }
    }
}

/// Why a SAML table was refused, naming the rule and never a value.
#[derive(Debug, thiserror::Error)]
pub enum SamlConfigError {
    /// A rule of the tables is broken.
    #[error("{0}")]
    Rule(&'static str),
    /// A key or certificate file cannot be read.
    #[error("`{key}` cannot be read at {}", path.display())]
    File {
        /// The key.
        key: &'static str,
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// A key or certificate is not one FerroSMART can use.
    #[error("`{key}` is not usable")]
    Key {
        /// The key.
        key: &'static str,
        /// Why.
        #[source]
        source: KeyError,
    },
    /// `[ferrosmart.saml.tls]` describes no client that can be built.
    #[error("`ferrosmart.saml.tls` describes no usable client")]
    Tls(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The HTTP client cannot be built.
    #[error("the HTTP client of the identity providers cannot be built")]
    Client(#[source] reqwest::Error),
}

/// FerroSMART as a SAML 2.0 service provider, resolved.
#[derive(Debug)]
pub struct ServiceProviderSettings {
    /// Its entity ID.
    pub entity_id: String,
    /// The assertion consumer service URL.
    pub acs_url: String,
    /// The key that signs every request.
    pub signing: SigningKey,
    /// The keys that decrypt.
    pub decryption: Vec<DecryptionKey>,
    /// The name identifier formats the providers ask for, once each.
    pub name_id_formats: Vec<String>,
    /// Whether the client presents a TLS identity.
    pub mutual_tls: bool,
    /// The HTTP client of every call to an identity provider.
    pub http: reqwest::Client,
}

impl ServiceProviderSettings {
    /// Writes the `md:EntityDescriptor` FerroSMART publishes.
    #[must_use]
    pub fn metadata(&self) -> String {
        ServiceProvider {
            entity_id: &self.entity_id,
            acs_url: &self.acs_url,
            signing_key: &self.signing,
            decryption_keys: &self.decryption,
            name_id_formats: &self.name_id_formats,
        }
        .render()
    }
}

/// Reads the file at `path`, naming `key` when it cannot be read.
fn read(key: &'static str, path: &Path) -> Result<Vec<u8>, SamlConfigError> {
    std::fs::read(path).map_err(|source| SamlConfigError::File {
        key,
        path: path.to_owned(),
        source,
    })
}

/// Returns the bytes of the file `path` names, refusing an unset one.
fn required(key: &'static str, path: Option<&Path>) -> Result<Vec<u8>, SamlConfigError> {
    let path = path.ok_or(SamlConfigError::Rule(
        "`[ferrosmart.saml]` sets `signing_key_file`, `signing_certificate_file` and each decryption key's `key_file` and `certificate_file`",
    ))?;
    read(key, path)
}

/// Returns FerroSMART's service provider `section` describes, under the
/// issuer `issuer`, asking for the name identifier formats of `upstreams`.
///
/// # Errors
/// Returns [`SamlConfigError`] naming the key the service provider cannot
/// run with.
pub fn service_provider(
    section: &ServiceProviderSection,
    issuer: &str,
    upstreams: &[&SamlSection],
) -> Result<ServiceProviderSettings, SamlConfigError> {
    let issuer = issuer.trim_end_matches('/');
    let entity_id = if section.entity_id.is_empty() {
        format!("{issuer}{METADATA_ROUTE}")
    } else {
        section.entity_id.clone()
    };
    // NOTE: saml-metadata-2.0-os §2.3.2, an entityID is a URI, held here to an absolute one.
    if Url::parse(&entity_id).is_err() {
        return Err(SamlConfigError::Rule(
            "`ferrosmart.saml.entity_id` is an absolute URI",
        ));
    }
    let signing = SigningKey::from_pem(
        &required(
            "ferrosmart.saml.signing_key_file",
            section.signing_key_file.as_deref(),
        )?,
        &required(
            "ferrosmart.saml.signing_certificate_file",
            section.signing_certificate_file.as_deref(),
        )?,
    )
    .map_err(|source| SamlConfigError::Key {
        key: "ferrosmart.saml.signing_key_file",
        source,
    })?;
    let mut decryption = Vec::with_capacity(section.decryption.len());
    for pair in &section.decryption {
        decryption.push(
            DecryptionKey::from_pem(
                &required(
                    "ferrosmart.saml.decryption.key_file",
                    pair.key_file.as_deref(),
                )?,
                &required(
                    "ferrosmart.saml.decryption.certificate_file",
                    pair.certificate_file.as_deref(),
                )?,
            )
            .map_err(|source| SamlConfigError::Key {
                key: "ferrosmart.saml.decryption.key_file",
                source,
            })?,
        );
    }
    let mut name_id_formats: Vec<String> = Vec::new();
    for upstream in upstreams {
        let format = &upstream.name_id_format;
        if !format.is_empty() && !name_id_formats.contains(format) {
            name_id_formats.push(format.clone());
        }
    }
    let mutual_tls =
        section.tls.client_identity.is_some() || section.tls.client_identity_file.is_some();
    let presented = ferrohealth_smart::config::ServerTls
        .build("ferrosmart.saml.tls", &section.tls)
        .map_err(SamlConfigError::Tls)?;
    let http = reqwest::Client::builder()
        .timeout(super::UPSTREAM_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .tls_backend_preconfigured((**presented.config()).clone())
        .build()
        .map_err(SamlConfigError::Client)?;
    Ok(ServiceProviderSettings {
        acs_url: format!("{issuer}{ACS_ROUTE}"),
        entity_id,
        signing,
        decryption,
        name_id_formats,
        mutual_tls,
        http,
    })
}

/// Where a provider's metadata is read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataSource {
    /// An `https` URL.
    Url(Url),
    /// A file.
    File(PathBuf),
}

/// A SAML 2.0 identity provider, resolved.
#[derive(Debug, Clone)]
pub struct SamlUpstream {
    /// Its entity ID.
    pub entity_id: String,
    /// Where its metadata is read from.
    pub metadata: MetadataSource,
    /// The keys that must sign its metadata, when any are configured.
    pub metadata_keys: Option<Vec<TrustedKey>>,
    /// How often the metadata is read again.
    pub metadata_refresh: Duration,
    /// The binding the request is sent by.
    pub request_binding: RequestBinding,
    /// The binding the provider answers by.
    pub response_binding: ResponseBinding,
    /// Whether every request asks for a fresh authentication.
    pub force_authn: bool,
    /// The name identifier format asked for.
    pub name_id_format: Option<String>,
    /// The accepted authentication context classes.
    pub authn_contexts: Vec<String>,
    /// The clock skew.
    pub clock_skew: SignedDuration,
    /// The attribute of the person's identifier, or the `NameID`.
    pub subject_attribute: Option<String>,
    /// The claims a login yields, by the attribute each takes.
    pub claims: BTreeMap<String, String>,
}

/// The name identifier format whose values name no one twice
/// (saml-core-2.0-os §8.3.8).
const TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

/// Why a checked login yields no identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// The subject attribute carries no value, or more than one.
    #[error("the subject attribute does not carry exactly one value")]
    SubjectAttribute,
    /// The subject is a transient name identifier, which names the person
    /// for this login alone (saml-core-2.0-os §8.3.8), so no grant or
    /// consent could find them again.
    #[error("the subject is a transient name identifier")]
    Transient,
}

impl SamlUpstream {
    /// Returns what the checked `login` says about the person: their
    /// identifier from the subject attribute or the `NameID`, and the
    /// claims the `claims` table maps from the attributes.
    ///
    /// # Errors
    /// Returns [`IdentityError`] when the login names no lasting
    /// identifier.
    pub fn identity(&self, login: &Login) -> Result<crate::upstream::Identity, IdentityError> {
        let subject = match &self.subject_attribute {
            Some(attribute) => match login.attribute(attribute) {
                [one] if !one.trim().is_empty() => one.clone(),
                _ => return Err(IdentityError::SubjectAttribute),
            },
            None if login.name_id.format.as_deref() == Some(TRANSIENT) => {
                return Err(IdentityError::Transient);
            }
            None => login.name_id.value.clone(),
        };
        let mut claims = serde_json::Map::new();
        for (claim, attribute) in &self.claims {
            let value = match login.attribute(attribute) {
                [] => continue,
                [one] => serde_json::Value::String(one.clone()),
                several => serde_json::Value::Array(
                    several
                        .iter()
                        .map(|value| serde_json::Value::String(value.clone()))
                        .collect(),
                ),
            };
            claims.insert(claim.clone(), value);
        }
        let text = |claim: &str| {
            claims
                .get(claim)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        let (name, preferred_username) = (text("name"), text("preferred_username"));
        let greeting = [&name, &preferred_username]
            .into_iter()
            .filter_map(|held| held.as_deref().map(str::trim))
            .find(|held| !held.is_empty())
            .map(str::to_owned);
        Ok(crate::upstream::Identity {
            issuer: login.issuer.clone(),
            subject,
            display_name: greeting,
            name,
            preferred_username,
            session: None,
            auth_time: Some(login.authn_instant.as_second()),
            acr: Some(login.authn_context.clone()),
            claims,
        })
    }
}

/// Returns the provider `section` describes, with the `fhirUser` claim and
/// the role claims it names.
///
/// # Errors
/// Returns [`SamlConfigError`] naming the rule the table breaks.
pub fn upstream(
    section: &SamlSection,
) -> Result<(SamlUpstream, String, Vec<String>), SamlConfigError> {
    if Url::parse(&section.entity_id).is_err() {
        return Err(SamlConfigError::Rule(
            "`[ferrosmart.upstream.saml]` sets `entity_id`, an absolute URI",
        ));
    }
    let metadata = match (section.metadata_url.as_str(), &section.metadata_file) {
        ("", Some(file)) => MetadataSource::File(file.clone()),
        (url, None) if !url.is_empty() => match Url::parse(url) {
            Ok(url) if url.scheme() == "https" => MetadataSource::Url(url),
            _ => {
                return Err(SamlConfigError::Rule(
                    "`ferrosmart.upstream.saml.metadata_url` is an https URL",
                ));
            }
        },
        _ => {
            return Err(SamlConfigError::Rule(
                "`[ferrosmart.upstream.saml]` sets one of `metadata_url` and `metadata_file`",
            ));
        }
    };
    let mut metadata_keys = Vec::new();
    for path in &section.metadata_signing_certificate_files {
        const KEY: &str = "ferrosmart.upstream.saml.metadata_signing_certificate_files";
        let pem = read(KEY, path)?;
        metadata_keys.push(
            TrustedKey::from_certificate_pem(&pem)
                .map_err(|source| SamlConfigError::Key { key: KEY, source })?,
        );
    }
    if section.metadata_refresh.is_zero() {
        return Err(SamlConfigError::Rule(
            "`ferrosmart.upstream.saml.metadata_refresh` is greater than zero",
        ));
    }
    let skew = SignedDuration::try_from(section.clock_skew.get()).map_err(|_overflow| {
        SamlConfigError::Rule("`ferrosmart.upstream.saml.clock_skew` is in range")
    })?;
    // NOTE: saml-core-2.0-os §1.3.3 as errata E92 adds to it suggests three to five
    // minutes; more than an hour would make the time bounds meaningless (our own design).
    if skew > SignedDuration::from_hours(1) {
        return Err(SamlConfigError::Rule(
            "`ferrosmart.upstream.saml.clock_skew` is at most one hour",
        ));
    }
    let mapped = |claim: &String| section.claims.contains_key(claim);
    if !section.fhir_user_claim.is_empty() && !mapped(&section.fhir_user_claim) {
        return Err(SamlConfigError::Rule(
            "`ferrosmart.upstream.saml.fhir_user_claim` names a claim of `claims`",
        ));
    }
    if !section.role_claims.iter().all(mapped) {
        return Err(SamlConfigError::Rule(
            "each of `ferrosmart.upstream.saml.role_claims` names a claim of `claims`",
        ));
    }
    if section
        .claims
        .iter()
        .any(|(claim, attribute)| claim.is_empty() || attribute.is_empty())
    {
        return Err(SamlConfigError::Rule(
            "each claim of `ferrosmart.upstream.saml.claims` names an attribute",
        ));
    }
    let set = |text: &String| Some(text.clone()).filter(|text| !text.is_empty());
    Ok((
        SamlUpstream {
            entity_id: section.entity_id.clone(),
            metadata,
            metadata_keys: Some(metadata_keys).filter(|keys| !keys.is_empty()),
            metadata_refresh: section.metadata_refresh.get(),
            request_binding: section.request_binding,
            response_binding: section.response_binding,
            force_authn: section.force_authn,
            name_id_format: set(&section.name_id_format),
            authn_contexts: section.authn_contexts.clone(),
            clock_skew: skew,
            subject_attribute: set(&section.subject_attribute),
            claims: section.claims.clone(),
        },
        section.fhir_user_claim.clone(),
        section.role_claims.clone(),
    ))
}

/// Why a provider's metadata cannot be read, or its login cannot go on.
#[derive(Debug, thiserror::Error)]
pub enum SamlError {
    /// The metadata URL did not answer with a document.
    #[error("the identity provider's metadata cannot be fetched")]
    Fetch(#[source] reqwest::Error),
    /// The metadata URL answered with a status other than `200`.
    #[error("the identity provider's metadata answered {0}")]
    FetchStatus(http::StatusCode),
    /// The metadata file cannot be read.
    #[error("the identity provider's metadata file cannot be read")]
    File(#[source] std::io::Error),
    /// The document is larger than FerroSMART reads, or not UTF-8.
    #[error("the identity provider's document is too large or not UTF-8")]
    Body,
    /// The metadata is refused.
    #[error(transparent)]
    Metadata(#[from] MetadataError),
    /// The metadata names no endpoint for a binding FerroSMART uses.
    #[error("the identity provider's metadata names no {0} endpoint")]
    Endpoint(&'static str),
    /// The request cannot be signed.
    #[error("the request cannot be signed")]
    Sign(#[from] crate::saml::dsig::SignError),
    /// The random source failed.
    #[error("the random source failed")]
    Random,
}

/// Reads the metadata of `upstream` with `http`, at `now`.
async fn load(
    upstream: &SamlUpstream,
    http: &reqwest::Client,
    now: Timestamp,
) -> Result<IdentityProvider, SamlError> {
    let text = match &upstream.metadata {
        MetadataSource::File(path) => {
            let bytes = tokio::fs::read(path).await.map_err(SamlError::File)?;
            if bytes.len() > MAX_BODY {
                return Err(SamlError::Body);
            }
            String::from_utf8(bytes).map_err(|_not_utf8| SamlError::Body)?
        }
        MetadataSource::Url(url) => get(http, url).await?,
    };
    Ok(IdentityProvider::from_metadata(
        &text,
        &upstream.entity_id,
        now,
        upstream.metadata_keys.as_deref(),
    )?)
}

/// Fetches the document at `url` with `http`, capped at [`MAX_BODY`].
async fn get(http: &reqwest::Client, url: &Url) -> Result<String, SamlError> {
    let response = http
        .get(url.clone())
        .send()
        .await
        .map_err(SamlError::Fetch)?;
    if response.status() != http::StatusCode::OK {
        return Err(SamlError::FetchStatus(response.status()));
    }
    read_capped(response).await
}

/// Reads the body of `response`, refusing one past [`MAX_BODY`] or not
/// UTF-8.
async fn read_capped(mut response: reqwest::Response) -> Result<String, SamlError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(SamlError::Fetch)? {
        if body.len().saturating_add(chunk.len()) > MAX_BODY {
            return Err(SamlError::Body);
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_not_utf8| SamlError::Body)
}

/// The request that starts a login at a SAML provider.
#[derive(Debug, Clone)]
pub struct Departure {
    /// The request's `ID`, which the response must answer.
    pub request_id: String,
    /// The `RelayState` the response carries back.
    pub relay_state: String,
    /// How the browser carries the request.
    pub leg: Leg,
}

/// How the browser carries a request to the provider.
#[derive(Debug, Clone)]
pub enum Leg {
    /// Redirected to this URL (HTTP-Redirect).
    Redirect(Url),
    /// Posting this form to the provider (HTTP-POST).
    Post {
        /// The single sign-on location.
        action: Url,
        /// The `SAMLRequest` value.
        saml_request: String,
    },
}

/// A failure of the HTTP-Artifact resolution, named for the login record.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// The artifact or the response it resolved to is refused.
    #[error(transparent)]
    Refused(#[from] Refusal),
    /// The artifact resolution service could not be reached or answered
    /// with no SOAP response.
    #[error("the artifact resolution service cannot be reached")]
    Transport(#[source] SamlError),
}

/// How a person logs in at one SAML provider: its metadata, read again on
/// a timer, and FerroSMART's service provider.
#[derive(Debug)]
pub struct SamlLogin {
    /// The provider's settings.
    upstream: SamlUpstream,
    /// FerroSMART's service provider.
    sp: Arc<ServiceProviderSettings>,
    /// The metadata last read.
    current: Arc<RwLock<Arc<IdentityProvider>>>,
    /// The task that reads the metadata again.
    refresher: tokio::task::JoinHandle<()>,
}

impl Drop for SamlLogin {
    fn drop(&mut self) {
        self.refresher.abort();
    }
}

impl SamlLogin {
    /// Reads the metadata of `upstream` and returns its login, which reads
    /// the metadata again every `metadata_refresh`.
    ///
    /// # Errors
    /// Returns [`SamlError`] when the metadata cannot be read or names no
    /// endpoint for the bindings the provider is configured with.
    pub async fn connect(
        upstream: &SamlUpstream,
        sp: Arc<ServiceProviderSettings>,
    ) -> Result<Self, SamlError> {
        let first = load(upstream, &sp.http, Timestamp::now()).await?;
        endpoints(upstream, &first)?;
        let current = Arc::new(RwLock::new(Arc::new(first)));
        let refresher = tokio::spawn(refresh(
            upstream.clone(),
            Arc::clone(&sp),
            Arc::clone(&current),
        ));
        Ok(Self {
            upstream: upstream.clone(),
            sp,
            current,
            refresher,
        })
    }

    /// Returns the provider's settings.
    #[must_use]
    pub const fn upstream(&self) -> &SamlUpstream {
        &self.upstream
    }

    /// Returns FerroSMART's service provider.
    #[must_use]
    pub fn service_provider(&self) -> &ServiceProviderSettings {
        &self.sp
    }

    /// Returns the provider's metadata last read, refusing it once its
    /// `validUntil` has passed (saml-metadata-2.0-os §2.2.1).
    ///
    /// # Errors
    /// Returns [`MetadataError::Expired`] past its validity.
    pub fn identity_provider(&self) -> Result<Arc<IdentityProvider>, MetadataError> {
        let current = match self.current.read() {
            Ok(guard) => Arc::clone(&guard),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        };
        if current
            .valid_until()
            .is_some_and(|until| until <= Timestamp::now())
        {
            return Err(MetadataError::Expired);
        }
        Ok(current)
    }

    /// Returns the single sign-on location of the configured request
    /// binding.
    #[must_use]
    pub fn single_sign_on(&self) -> Option<Url> {
        let current = self.identity_provider().ok()?;
        current
            .single_sign_on(request_binding_uri(self.upstream.request_binding))
            .cloned()
    }

    /// Writes a new `AuthnRequest`, signed, carrying `relay_state`, asking
    /// for a fresh authentication when `force_authn` or the provider's
    /// setting says so.
    ///
    /// # Errors
    /// Returns [`SamlError`] when the metadata is past its validity or
    /// names no single sign-on location, or signing fails.
    pub fn begin(&self, relay_state: String, force_authn: bool) -> Result<Departure, SamlError> {
        let idp = self.identity_provider()?;
        let binding = request_binding_uri(self.upstream.request_binding);
        let destination = idp
            .single_sign_on(binding)
            .ok_or(SamlError::Endpoint("SingleSignOnService"))?;
        let request_id = crate::saml::new_id().map_err(|_failed| SamlError::Random)?;
        let request = AuthnRequest {
            id: &request_id,
            issue_instant: Timestamp::now(),
            destination: destination.as_str(),
            entity_id: &self.sp.entity_id,
            acs_url: &self.sp.acs_url,
            protocol_binding: self.upstream.response_binding.uri(),
            force_authn: force_authn || self.upstream.force_authn,
            name_id_format: self.upstream.name_id_format.as_deref(),
            authn_contexts: &self.upstream.authn_contexts,
        };
        let leg = match self.upstream.request_binding {
            RequestBinding::Redirect => {
                Leg::Redirect(request.redirect(&self.sp.signing, &relay_state)?)
            }
            RequestBinding::Post => Leg::Post {
                action: destination.clone(),
                saml_request: request.post(&self.sp.signing)?,
            },
        };
        Ok(Departure {
            request_id,
            relay_state,
            leg,
        })
    }

    /// Returns what FerroSMART expects of the response to the request
    /// `request_id`, against the metadata `idp`, now.
    #[must_use]
    pub fn expectations<'a>(
        &'a self,
        idp: &'a IdentityProvider,
        request_id: &'a str,
    ) -> Expectations<'a> {
        Expectations {
            entity_id: &self.sp.entity_id,
            acs_url: &self.sp.acs_url,
            request_id,
            idp,
            decryption_keys: &self.sp.decryption,
            authn_contexts: &self.upstream.authn_contexts,
            now: Timestamp::now(),
            skew: self.upstream.clock_skew,
        }
    }

    /// Checks the posted `SAMLResponse` against `expect`.
    ///
    /// # Errors
    /// Returns the [`Refusal`] of the first check that fails, and
    /// [`Refusal::Binding`] when the provider was asked to answer by
    /// artifact.
    pub fn check_post(
        &self,
        saml_response: &str,
        expect: &Expectations<'_>,
    ) -> Result<Login, Refusal> {
        if self.upstream.response_binding != ResponseBinding::Post {
            return Err(Refusal::Binding);
        }
        response::check_post(saml_response, expect)
    }

    /// Resolves the artifact `encoded` at the provider's artifact
    /// resolution service over mutual TLS and checks the response it
    /// carries against `expect` (saml-bindings-2.0-os §3.6.3).
    ///
    /// # Errors
    /// Returns [`ResolveError::Refused`] naming the check that fails, and
    /// [`ResolveError::Transport`] when the service cannot be reached.
    pub async fn resolve(
        &self,
        encoded: &str,
        expect: &Expectations<'_>,
    ) -> Result<Login, ResolveError> {
        if self.upstream.response_binding != ResponseBinding::Artifact {
            return Err(Refusal::Binding.into());
        }
        let artifact = Artifact::parse(encoded)?;
        // NOTE: saml-bindings-2.0-os §3.6.4, the SourceID names the issuer; an artifact of
        // another entity is never sent to this provider's resolution service.
        if !artifact.issued_by(expect.idp.entity_id()) {
            return Err(Refusal::Issuer.into());
        }
        let location = expect
            .idp
            .artifact_resolution(artifact.endpoint_index())
            .ok_or(Refusal::Structure("md:ArtifactResolutionService"))?;
        let resolve_id =
            crate::saml::new_id().map_err(|_failed| ResolveError::Transport(SamlError::Random))?;
        let envelope = ArtifactResolve {
            id: &resolve_id,
            issue_instant: Timestamp::now(),
            destination: location.as_str(),
            entity_id: &self.sp.entity_id,
            artifact: &artifact,
        }
        .envelope(&self.sp.signing)
        .map_err(|error| ResolveError::Transport(SamlError::Sign(error)))?;
        // NOTE: saml-bindings-2.0-os §3.2.3.1 and §3.2.3.3, the SOAP request carries the
        // SOAPAction header, and a fault or any status but 200 carries no response.
        let response = self
            .sp
            .http
            .post(location.clone())
            .header(http::header::CONTENT_TYPE, "text/xml; charset=utf-8")
            .header("SOAPAction", SOAP_ACTION)
            .body(envelope)
            .send()
            .await
            .map_err(|error| ResolveError::Transport(SamlError::Fetch(error)))?;
        if response.status() != http::StatusCode::OK {
            return Err(ResolveError::Transport(SamlError::FetchStatus(
                response.status(),
            )));
        }
        let soap = read_capped(response)
            .await
            .map_err(ResolveError::Transport)?;
        Ok(crate::saml::artifact::check_response(
            &soap,
            &resolve_id,
            expect,
        )?)
    }
}

/// The URI of the request binding `binding`.
const fn request_binding_uri(binding: RequestBinding) -> &'static str {
    match binding {
        RequestBinding::Redirect => HTTP_REDIRECT,
        RequestBinding::Post => HTTP_POST,
    }
}

/// Refuses metadata `idp` that names no endpoint for a binding `upstream`
/// uses.
fn endpoints(upstream: &SamlUpstream, idp: &IdentityProvider) -> Result<(), SamlError> {
    if idp
        .single_sign_on(request_binding_uri(upstream.request_binding))
        .is_none()
    {
        return Err(SamlError::Endpoint("SingleSignOnService"));
    }
    Ok(())
}

/// Reads the metadata of `upstream` again every `metadata_refresh` into
/// `current`, keeping the last good document when a read fails.
async fn refresh(
    upstream: SamlUpstream,
    sp: Arc<ServiceProviderSettings>,
    current: Arc<RwLock<Arc<IdentityProvider>>>,
) {
    let mut interval = tokio::time::interval(upstream.metadata_refresh);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // NOTE: the first tick completes at once; the metadata was read at connect.
    interval.tick().await;
    loop {
        interval.tick().await;
        let read = load(&upstream, &sp.http, Timestamp::now())
            .await
            .and_then(|idp| endpoints(&upstream, &idp).map(|()| idp));
        match read {
            Ok(idp) => match current.write() {
                Ok(mut guard) => *guard = Arc::new(idp),
                Err(poisoned) => *poisoned.into_inner() = Arc::new(idp),
            },
            Err(error) => tracing::warn!(
                error = %ferrohealth_server::run::chain(&error),
                provider = %upstream.entity_id,
                "the identity provider's metadata was not read again; the last good copy stays"
            ),
        }
    }
}
