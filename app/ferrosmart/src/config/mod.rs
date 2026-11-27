// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The server's configuration, read by `ferrohealth-config`.
//!
//! The layers are the defaults, a TOML file, the `FERROSMART__` environment
//! overrides and the `--set` arguments. [`Config`] is the tree as written,
//! every default in its struct's `Default` impl; [`Config::resolve`] turns
//! it into the checked [`settings::Settings`] the server runs on. An
//! override names its key by path, `FERROSMART__FERROSMART__ISSUER` for
//! `[ferrosmart] issuer`, and `RUST_LOG` sets `telemetry.filter`. No
//! specification governs the configuration: our own design
//! (`docs/architecture.md` §13.10).
//!
//! ```toml
//! [server]
//! listen = "0.0.0.0:8080"
//!
//! [ferrosmart]
//! issuer = "https://smart.example.org"
//! access_token_lifetime = "5min"
//! refresh_idle = "30d"
//! online_idle = "8h"
//!
//! [ferrosmart.keys]
//! private_key_files = [
//!     "/run/secrets/ferrosmart-rs256-1.pem",
//!     "/run/secrets/ferrosmart-rs256-2.pem",
//! ]
//! rotation_period = "90d"
//!
//! [ferrosmart.database]
//! url_file = "/run/secrets/ferrosmart-database-url"
//!
//! [[ferrosmart.resource]]
//! base = "https://ehr.example.org/fhir"
//! kind = "fhir"
//!
//! [ferrosmart.audit.feed]
//! url = "https://audit.example.org/fhir"
//! ```

pub mod error;
pub mod settings;

use std::collections::BTreeMap;
use std::path::PathBuf;

use ferrohealth_config::loader::{Loaded, Loader};
use ferrohealth_config::units::Duration as Span;
use ferrohealth_server::cli::ConfigArgs;
use ferrohealth_server::section::ServerSection;
use ferrohealth_telemetry::section::TelemetrySection;
use serde::{Deserialize, Serialize};

use crate::config::error::Error;

/// The prefix of every environment override and of `FERROSMART_CONFIG`.
pub const PREFIX: &str = "FERROSMART";

/// Returns the loader of the configuration: the `FERROSMART` namespace,
/// with `RUST_LOG` as the alias of `telemetry.filter`.
///
/// # Errors
/// Returns [`Error::Load`] when the namespace is refused, which it never is
/// for [`PREFIX`].
pub fn loader() -> Result<Loader, Error> {
    Ok(Loader::new(PREFIX)?.alias("RUST_LOG", "telemetry.filter"))
}

impl Config {
    /// Reads the configuration of the running process: the file `args`
    /// names (or `FERROSMART_CONFIG` does), the environment, and the `--set`
    /// pairs of `args`, last.
    ///
    /// # Errors
    /// Returns [`Error::Load`] with every refusal of the loader.
    pub fn load(args: &ConfigArgs) -> Result<Loaded<Self>, Error> {
        Ok(loader()?.load_with(args.config.as_deref(), &args.sets)?)
    }

    /// Reads `text` as the configuration file and applies `environment`
    /// over it, for a test that states both.
    ///
    /// # Errors
    /// Returns [`Error::Load`] with every refusal of the loader.
    pub fn from_sources(
        text: Option<&str>,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self, Error> {
        let loaded = loader()?.load_sources::<Self>(text, None, environment)?;
        Ok(loaded.into_parts().0)
    }
}

/// The configuration tree as written.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// `[server]`: the listener, its TLS and the stack of every family
    /// server.
    pub server: ServerSection,
    /// `[telemetry]`: the console log of `ferrohealth-telemetry`.
    pub telemetry: TelemetrySection,
    /// `[ferrosmart]`: the authorization server itself.
    pub ferrosmart: FerroSmartSection,
}

/// `[ferrosmart]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FerroSmartSection {
    /// The deployment's name, such as the hospital's: what every page
    /// carries, and the User Access Brand's `Organization.name` when
    /// `[ferrosmart.brand]` names none.
    pub name: String,
    /// The issuer identifier (RFC 8414 §2): an `https` URL with no query and
    /// no fragment, whose path is `[server] base_path`.
    pub issuer: String,
    /// How long an access token lives: five minutes by default, which SMART
    /// Backend Services recommends and keeps every grant within SMART App
    /// Launch's one hour.
    pub access_token_lifetime: Span,
    /// How long an `offline_access` refresh token lasts unused: thirty days
    /// by default. Each refresh rotates it and starts the time again, so an
    /// idle grant lapses (OAuth 2.1 draft §4.3.3, "Refresh tokens SHOULD
    /// expire if the client has been inactive for some time").
    pub refresh_idle: Span,
    /// How long an `online_access` refresh token lasts unused: eight hours
    /// by default, and never past the end of the person's upstream login
    /// (`docs/architecture.md` §13.6 item 7).
    pub online_idle: Span,
    /// The eIDAS level every person's login reaches; `substantial` by
    /// default (`docs/architecture.md` §13.28).
    pub assurance_minimum: crate::assurance::Floor,
    /// Whether every authorization request arrives pushed (RFC 9126 §4,
    /// §5); `false` by default, when a client's own
    /// `require_pushed_authorization_requests` still holds it to PAR.
    pub require_pushed_authorization_requests: bool,
    /// `[ferrosmart.keys]`: the keys that sign every token, in rotation.
    pub keys: SigningKeysSection,
    /// `[ferrosmart.database]`: the PostgreSQL database of the state.
    pub database: DatabaseSection,
    /// `[[ferrosmart.resource]]`: the FHIR and openEHR servers a token may
    /// be for, each its own audience.
    pub resource: Vec<ResourceSection>,
    /// `[[ferrosmart.upstream]]`: the identity providers people log in at,
    /// each by name; without one the server answers Backend Services alone.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub upstream: Vec<crate::upstream::UpstreamSection>,
    /// `[ferrosmart.saml]`: FerroSMART as a SAML 2.0 service provider,
    /// which every provider with a `[ferrosmart.upstream.saml]` table needs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saml: Option<crate::upstream::saml::ServiceProviderSection>,
    /// `[[ferrosmart.role]]`: the scopes each upstream role may be granted,
    /// the policy as content (`docs/architecture.md` §13.6 item 5).
    pub role: Vec<RoleSection>,
    /// `[ferrosmart.branding]`: the deployment's words on the pages,
    /// content and never code (13.15).
    pub branding: BrandingSection,
    /// `[ferrosmart.brand]`: the User Access Brands Bundle the deployment
    /// publishes; without it the server serves none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brand: Option<crate::brands::BrandSection>,
    /// `[ferrosmart.audit]`: where every login and token is recorded.
    pub audit: AuditSection,
    /// `[ferrosmart.registration]`: whether an app may register itself.
    pub registration: RegistrationSection,
    /// `[ferrosmart.picker]`: what the patient picker keeps of a person's
    /// choices.
    pub picker: PickerSection,
    /// `[ferrosmart.backend]`: FerroSMART's own SMART Backend Services
    /// client, which every deployment that logs people in at a FHIR base
    /// needs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<BackendSection>,
}

/// `[ferrosmart.registration]`: an app's own registration at `POST
/// {issuer}/register` without an initial access token (RFC 7591 §3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RegistrationSection {
    /// Whether the endpoint answers a request without an initial access
    /// token; off by default.
    pub open: bool,
    /// The most an app that registered itself may be granted,
    /// space-separated: patient-facing scopes, since professional apps are
    /// registered by an administrator.
    pub scope: String,
}

/// `[ferrosmart.picker]` (`docs/architecture.md` §13.6 item 4).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PickerSection {
    /// How long a patient a person chose stays on their recent list; zero
    /// keeps no list.
    pub recent_retention: Span,
}

impl Default for PickerSection {
    fn default() -> Self {
        Self {
            recent_retention: Span::from_days(30),
        }
    }
}

/// `[ferrosmart.branding]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrandingSection {
    /// The deployment's own words on the consent page, such as what it does
    /// with the access a person gives; empty for none.
    pub consent_text: String,
    /// The `smart_style_url` an app's token response carries: an https URL
    /// of the deployment's SMART style document; empty for none.
    pub smart_style_url: String,
}

/// `[ferrosmart.audit]`: how FerroSMART names itself in its audit records,
/// and the Audit Record Repository it forwards them to. No specification
/// governs the section's shape: our own design.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditSection {
    /// How FerroSMART names itself as the recording system
    /// (`AuditEvent.source.observer`); empty takes the issuer's host.
    pub source_id: String,
    /// The site FerroSMART runs at (`AuditEvent.source.site`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    /// `[ferrosmart.audit.feed]`: the repository's FHIR base, an `https`
    /// URL the records are created under as `[base]/AuditEvent`, with its
    /// timeouts, TLS and credentials; without it the records stay in
    /// FerroSMART's own store alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feed: Option<ferrohealth_smart::config::endpoint::EndpointSection>,
}

/// One `[[ferrosmart.role]]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoleSection {
    /// The role, as the upstream role claims carry it.
    pub name: String,
    /// The `user/` and `patient/` scopes a person holding it may be
    /// granted.
    pub scopes: Vec<String>,
}

/// One `[[ferrosmart.resource]]` table: a server whose base URL is the
/// `aud` of the tokens issued for it (SMART App Launch 2.2.0, Obtain
/// authorization code, `aud`; RFC 9068 §3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResourceSection {
    /// The server's base URL, as its clients name it.
    pub base: String,
    /// The API the server serves.
    pub kind: ResourceKind,
    /// For an openEHR server, the namespace its EHRs name their subjects in
    /// (`EHR_STATUS.subject.external_ref.namespace`), which the patient
    /// picker looks an EHR up by; unset, the picker is not offered there.
    pub subject_namespace: Option<String>,
    /// For an openEHR server, the base of the platform's FHIR server (the
    /// `org.fhir.rest` service beside `org.openehr.rest`, SMART on openEHR
    /// draft, Service Discovery), one of the FHIR bases configured: the
    /// patient picker searches it for the patient and then looks their EHR
    /// up, so the context carries `patient` and `ehrId`.
    pub fhir_base: Option<String>,
    /// With `fhir_base`, the `system` of the `Patient.identifier` whose
    /// value is the subject id of the patient's EHR in `subject_namespace`.
    pub subject_system: Option<String>,
    /// For a FHIR server, how a person whose provider sends no `fhirUser`
    /// is found there by an identifier (`docs/architecture.md` §13.6
    /// item 9); empty, no search is made.
    pub fhir_user_lookup: Vec<FhirUserLookupSection>,
    /// For a FHIR server, the patient index a wallet login's identifier is
    /// resolved at to the person's `Patient` here (`docs/architecture.md`
    /// §13.32); unset, a wallet login takes the `fhir_user_lookup`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patient_index: Option<PatientIndexSection>,
    /// For an openEHR server, the HTTP header a professional's patient
    /// picker lookup declares its purpose of use in; unset,
    /// `x-purpose-of-use`. Only with `purpose`.
    pub purpose_header: Option<String>,
    /// For an openEHR server, the purposes of use it accepts, one of which
    /// a professional chooses on the patient picker (`docs/architecture.md`
    /// §13.6 item 4); empty, the lookup declares none.
    pub purpose: Vec<PurposeSection>,
    /// For a FHIR server, the search the patient picker lists a
    /// professional's assigned patients by; unset, it lists none.
    pub assigned: Option<Assigned>,
    /// The algorithm the access tokens for this server are signed with, one
    /// a key of `[ferrosmart.keys]` signs: `RS256` by default, or
    /// `ML-DSA-65` for a server that verifies it (RFC 9964).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_signing_alg: Option<ferrohealth_smart::jws::algorithm::Algorithm>,
}

/// The search that lists the patients assigned to a professional, by the
/// `participant` search parameter of FHIR R4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Assigned {
    /// The active care teams the professional takes part in
    /// (`CareTeam?participant=…&status=active`).
    CareTeam,
    /// The encounters in progress the professional takes part in
    /// (`Encounter?participant=…&status=in-progress`).
    Encounter,
}

/// One `[[ferrosmart.resource.purpose]]` table: a purpose of use an openEHR
/// server accepts in its purpose header.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PurposeSection {
    /// The code, sent as the header's value: visible ASCII with no comma.
    pub code: String,
    /// The code system, an absolute URI.
    pub system: String,
    /// The words the picker page shows for it.
    pub display: String,
}

/// One `[[ferrosmart.resource.fhir_user_lookup]]` table: a FHIR search by
/// identifier whose one match is the person's `fhirUser`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FhirUserLookupSection {
    /// The resource type searched.
    pub resource_type: LookupType,
    /// The upstream ID Token claim whose text is the identifier's value.
    pub claim: String,
    /// The identifier's `system`, an absolute URI.
    pub system: String,
}

/// `[ferrosmart.resource.patient_index]`: a FerroPIX or other IHE PIXm
/// Manager or PDQm Supplier, and the identifier system of the resource
/// server's own patients in it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PatientIndexSection {
    /// The index's FHIR base, the audience of the token FerroSMART asks it
    /// with.
    pub base: String,
    /// The transaction the index is asked by.
    pub transaction: IndexTransaction,
    /// The `system` of the `Patient.identifier` the resource server's
    /// patients carry, in which the index cross-references the person.
    pub system: String,
}

/// The IHE transaction a patient index is asked by.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IndexTransaction {
    /// PIXm 3.1.0 ITI-83, the `$ihe-pix` cross-reference query.
    #[default]
    Pixm,
    /// PDQm 3.2.0 ITI-78, the `Patient` search by identifier.
    Pdqm,
}

/// The resource type a `fhirUser` lookup searches (SMART App Launch 2.2.0,
/// `fhirUser`: a `Patient`, `Practitioner`, `PractitionerRole`,
/// `RelatedPerson` or `Person`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum LookupType {
    /// `Practitioner`.
    #[default]
    Practitioner,
    /// `PractitionerRole`.
    PractitionerRole,
    /// `Patient`.
    Patient,
    /// `RelatedPerson`.
    RelatedPerson,
    /// `Person`.
    Person,
}

impl LookupType {
    /// Returns the FHIR resource type name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Practitioner => "Practitioner",
            Self::PractitionerRole => "PractitionerRole",
            Self::Patient => "Patient",
            Self::RelatedPerson => "RelatedPerson",
            Self::Person => "Person",
        }
    }

    /// Returns the one scope the person's search token carries.
    #[must_use]
    pub const fn scope(self) -> &'static str {
        match self {
            Self::Practitioner => "user/Practitioner.rs",
            Self::PractitionerRole => "user/PractitionerRole.rs",
            Self::Patient => "user/Patient.rs",
            Self::RelatedPerson => "user/RelatedPerson.rs",
            Self::Person => "user/Person.rs",
        }
    }
}

/// The API a resource server serves.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// A FHIR server.
    #[default]
    Fhir,
    /// An openEHR server (the SMART on openEHR draft).
    Openehr,
}

impl Default for FerroSmartSection {
    fn default() -> Self {
        Self {
            name: String::from("FerroSMART"),
            issuer: String::new(),
            access_token_lifetime: Span::from_mins(5),
            refresh_idle: Span::from_days(30),
            online_idle: Span::from_hours(8),
            assurance_minimum: crate::assurance::Floor::Substantial,
            require_pushed_authorization_requests: false,
            keys: SigningKeysSection::default(),
            database: DatabaseSection::default(),
            resource: Vec::new(),
            upstream: Vec::new(),
            saml: None,
            role: Vec::new(),
            branding: BrandingSection::default(),
            brand: None,
            audit: AuditSection::default(),
            registration: RegistrationSection::default(),
            picker: PickerSection::default(),
            backend: None,
        }
    }
}

/// `[ferrosmart.keys]`: the keys that sign in turn, each algorithm rotating
/// on its own (`docs/architecture.md` §13.11).
///
/// An RSA key signs `RS256`, the one algorithm RFC 9068 §2.1 and OpenID
/// Connect Discovery §3 have every authorization server support, and the
/// pool holds at least one; a P-256 key signs `ES256`, an Ed25519 key
/// `EdDSA` and an ML-DSA-65 key `ML-DSA-65`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SigningKeysSection {
    /// The PEM files of the keys, in the order they take over; each is
    /// published under its RFC 7638 thumbprint.
    pub private_key_files: Vec<PathBuf>,
    /// The PEM files of RSA keys that sign `PS256` (RFC 7518 §3.5), in the
    /// order they take over, none of them among `private_key_files`.
    pub ps256_private_key_files: Vec<PathBuf>,
    /// How long a key signs before the next one takes over.
    pub rotation_period: Span,
}

impl Default for SigningKeysSection {
    fn default() -> Self {
        Self {
            private_key_files: Vec::new(),
            ps256_private_key_files: Vec::new(),
            rotation_period: Span::from_days(90),
        }
    }
}

/// `[ferrosmart.upstream.oidc.private_key_jwt.keys]`: the ring of keys
/// FerroSMART signs its own client assertions with.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct KeysSection {
    /// The PEM file of the key that signs.
    pub private_key_file: Option<PathBuf>,
    /// The `kid` the key is published under; its RFC 7638 thumbprint when
    /// empty.
    pub kid: String,
    /// The PEM file of the key that signed before a rotation, published and
    /// never signing.
    pub previous_private_key_file: Option<PathBuf>,
    /// How long the previous key stays published; zero for as long as the
    /// server runs with it configured.
    pub previous_key_overlap: Span,
    /// The PEM file of the key a rotation makes current, published ahead of
    /// it and never signing.
    pub next_private_key_file: Option<PathBuf>,
}

impl Default for KeysSection {
    fn default() -> Self {
        Self {
            private_key_file: None,
            kid: String::new(),
            previous_private_key_file: None,
            previous_key_overlap: Span::from_secs(0),
            next_private_key_file: None,
        }
    }
}

/// `[ferrosmart.backend]`: FerroSMART as a SMART Backend Services client of
/// its own token endpoint, registered under its issuer identifier
/// (`docs/architecture.md` §13.33).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackendSection {
    /// The JWS algorithm of its client assertions: `ML-DSA-65` by default,
    /// or `ML-DSA-44` or `ML-DSA-87` (RFC 9964), which its own token
    /// endpoint takes, or `ES384` or `RS384`, the two SMART App Launch
    /// 2.2.0's asymmetric client profile names.
    pub algorithm: String,
    /// `[ferrosmart.backend.keys]`: the ring that signs its assertions,
    /// sharing no key with `[ferrosmart.keys]`.
    pub keys: KeysSection,
}

impl Default for BackendSection {
    fn default() -> Self {
        Self {
            algorithm: String::from("ML-DSA-65"),
            keys: KeysSection::default(),
        }
    }
}

/// `[ferrosmart.database]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DatabaseSection {
    /// The PostgreSQL connection URL, a secret; exclusive with `url_file`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<ferrohealth_secret::secret::Secret>,
    /// The file holding the connection URL.
    pub url_file: Option<PathBuf>,
    /// The most connections one replica holds.
    pub max_connections: u32,
}

impl Default for DatabaseSection {
    fn default() -> Self {
        Self {
            url: None,
            url_file: None,
            max_connections: 16,
        }
    }
}
