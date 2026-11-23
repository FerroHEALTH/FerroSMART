// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The issuer profile: what one authorization server's tokens look like and
//! which of their claims say who stands behind them.
//!
//! The core rules are the standards': RFC 9068 for the token shape, OpenID
//! Connect Core 1.0 §5.7 for the stable person key, RFC 8693 §4.1 for an
//! actor. An authorization server that deviates from them is described as
//! data, its [`Profile`], read by one implementation with no vendor branch.
//! A [`Preset`] names a shipped set of values (`profiles/*.toml`, each value
//! labelled with its source), and every key of a preset can be set on the
//! issuer itself ([`ProfileKeys`]). No specification governs the profile
//! model: our own design over those sources.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::Serialize;
use serde_json::Map;
use serde_json::Value;

use crate::federation::FederationSection;
use crate::kind::IssuerKind;
use crate::profile::onward::OnwardGrant;
use crate::profile::onward::OnwardIndicator;
use crate::profile::onward::PreviewVariant;
use crate::profile::tables::set;
use crate::profile::tables::set_some;

pub mod onward;
mod tables;

/// The claims OpenID Connect Core 1.0 §5.7 says "MUST NOT be used as unique
/// identifiers for the End-User".
pub const UNSTABLE_CLAIMS: [&str; 4] = ["email", "phone_number", "preferred_username", "name"];

/// A shipped set of profile values, selected by `profile` on
/// `[auth.issuer.<name>]`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Preset {
    /// Every default: a standards-only RFC 9068 issuer.
    #[default]
    Rfc9068,
    /// Microsoft Entra ID v2.0 access tokens.
    Entra,
    /// Keycloak access tokens.
    Keycloak,
    /// Okta access tokens.
    Okta,
    /// FerroSMART's access tokens: plain RFC 9068, `typ` `at+jwt` and
    /// `scope` in every token.
    Ferrosmart,
}

impl Preset {
    /// Returns the preset's file, as shipped under `profiles/`.
    #[must_use]
    pub const fn source(self) -> &'static str {
        match self {
            Self::Rfc9068 => include_str!("../../profiles/rfc9068.toml"),
            Self::Entra => include_str!("../../profiles/entra.toml"),
            Self::Keycloak => include_str!("../../profiles/keycloak.toml"),
            Self::Okta => include_str!("../../profiles/okta.toml"),
            Self::Ferrosmart => include_str!("../../profiles/ferrosmart.toml"),
        }
    }

    /// Returns the preset's file read: its keys, its kind and its
    /// federation defaults.
    ///
    /// # Errors
    ///
    /// [`ProfileError::Preset`] when the shipped file does not read, which
    /// the crate's own tests rule out for every preset.
    pub fn file(self) -> Result<ProfileFile, ProfileError> {
        ProfileFile::parse(self.source()).map_err(|source| self.unreadable(source))
    }

    /// Returns the kind of the issuers the preset describes, which an issuer
    /// table that names no `kind` takes; none for a preset that leaves the
    /// kind to the table.
    ///
    /// # Errors
    ///
    /// [`ProfileError::Preset`] when the shipped file does not read.
    pub fn kind(self) -> Result<Option<IssuerKind>, ProfileError> {
        Ok(self.file()?.kind)
    }

    /// Returns the preset's values over the defaults.
    ///
    /// # Errors
    ///
    /// [`ProfileError::Preset`] when the shipped file does not read.
    pub fn keys(self) -> Result<ProfileKeys, ProfileError> {
        Ok(self.file()?.keys)
    }

    /// Returns the federation table defaults the preset's `federation`
    /// table declares, which the issuer's own table is set over; none when
    /// the preset declares none.
    ///
    /// # Errors
    ///
    /// [`ProfileError::Preset`] when the shipped file does not read.
    pub fn federation(self) -> Result<Option<FederationSection>, ProfileError> {
        Ok(self.file()?.federation)
    }

    /// Returns the error of a shipped file that does not read.
    fn unreadable(self, source: toml::de::Error) -> ProfileError {
        ProfileError::Preset {
            preset: self,
            source: Box::new(source),
        }
    }
}

/// A profile in the form of a preset file: its profile keys, the `kind` of
/// its issuers and the `[federation]` table defaults, each optional.
///
/// A deployment supplies one as an issuer's `profile_file`, for a profile no
/// shipped preset carries (a national binding, an identity provider of its
/// own); its values are set over the preset's (no specification governs the
/// profile model: our own design).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileFile {
    /// The profile keys.
    pub keys: ProfileKeys,
    /// The kind of its issuers, when it names one.
    pub kind: Option<IssuerKind>,
    /// The federation table defaults, when it declares them.
    pub federation: Option<FederationSection>,
}

impl ProfileFile {
    /// Returns the profile the file at `path` holds.
    ///
    /// # Errors
    ///
    /// [`ProfileError::File`] when the file cannot be read, and
    /// [`ProfileError::FileSyntax`] when it is no profile, an unknown key
    /// included.
    pub fn read(path: &std::path::Path) -> Result<Self, ProfileError> {
        let text = std::fs::read_to_string(path).map_err(|source| ProfileError::File {
            path: path.to_owned(),
            source,
        })?;
        Self::parse(&text).map_err(|source| ProfileError::FileSyntax {
            path: path.to_owned(),
            source: Box::new(source),
        })
    }

    /// Returns the profile `text` holds.
    ///
    /// # Errors
    ///
    /// The reader's error when `text` is no profile, an unknown key
    /// included.
    pub fn parse(text: &str) -> Result<Self, toml::de::Error> {
        let mut table: toml::Table = text.parse()?;
        let federation = table
            .remove(FEDERATION)
            .map(toml::Value::try_into)
            .transpose()?;
        let kind = table.remove(KIND).map(toml::Value::try_into).transpose()?;
        Ok(Self {
            keys: table.try_into()?,
            kind,
            federation,
        })
    }
}

/// The table of a preset file that holds its federation table defaults.
const FEDERATION: &str = "federation";

/// The key of a preset file that names the kind of its issuers.
const KIND: &str = "kind";

/// How a scope claim carries its scopes.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeForm {
    /// One space-separated string (RFC 6749 §3.3).
    #[default]
    String,
    /// A JSON array of strings.
    Array,
}

/// The claim a token's scopes are read from, and its JSON form.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeClaim {
    /// The claim.
    pub claim: String,
    /// Its JSON form.
    #[serde(default)]
    pub form: ScopeForm,
}

impl Default for ScopeClaim {
    fn default() -> Self {
        Self {
            claim: String::from("scope"),
            form: ScopeForm::String,
        }
    }
}

/// Why a scope claim does not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeFormError;

impl ScopeClaim {
    /// Returns the scope tokens `claims` carry under this claim; none when
    /// the claim is absent.
    ///
    /// # Errors
    ///
    /// [`ScopeFormError`] when the claim is present in another JSON form.
    pub fn read(&self, claims: &Map<String, Value>) -> Result<String, ScopeFormError> {
        match (claims.get(&self.claim), self.form) {
            (None, _) => Ok(String::new()),
            (Some(Value::String(scope)), ScopeForm::String) => Ok(scope.clone()),
            (Some(Value::Array(items)), ScopeForm::Array) => items
                .iter()
                .map(|item| item.as_str().ok_or(ScopeFormError))
                .collect::<Result<Vec<_>, _>>()
                .map(|tokens| tokens.join(" ")),
            (Some(_), _) => Err(ScopeFormError),
        }
    }
}

/// A test one token's claims either pass or fail, written as one table.
///
/// Exactly one form per table: `{ claim, value }`, `{ absent_claim }`,
/// `{ subjects }`, `{ sub_is_client = true }` or `{ differs_from_iss }`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "tables::MarkerTable", into = "tables::MarkerTable")]
#[non_exhaustive]
pub enum Marker {
    /// The claim is present and its text is the value.
    Claim {
        /// The claim.
        claim: String,
        /// Its value, a string's text or a number's or boolean's JSON text.
        value: String,
    },
    /// The claim is absent.
    Absent {
        /// The claim.
        claim: String,
    },
    /// The token's `sub` is one of the subjects.
    Subjects(Vec<String>),
    /// The token's `sub` equals its client claim.
    SubIsClient,
    /// The claim is present and differs from the token's `iss`.
    DiffersFromIssuer {
        /// The claim.
        claim: String,
    },
}

/// The claims a `persons` issuer names a represented subject in.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Representation {
    /// The claim naming the subject the person represents.
    pub claim: String,
    /// The claim carrying the ground of the representation, as asserted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ground_claim: Option<String>,
}

/// The profile keys, each optional: a preset's file, or the keys set on one
/// `[auth.issuer.<name>]`, which win over the preset's.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProfileKeys {
    /// [`Profile::person_key`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub person_key: Option<String>,
    /// [`Profile::tenant_claim`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_claim: Option<String>,
    /// [`Profile::client_claims`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_claims: Option<Vec<String>>,
    /// [`Profile::app_only`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_only: Option<Vec<Marker>>,
    /// [`Profile::guest`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest: Option<Vec<Marker>>,
    /// [`Profile::impersonation_marker`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impersonation_marker: Option<String>,
    /// [`Profile::expect`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expect: Option<BTreeMap<String, String>>,
    /// [`Profile::user_claims`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_claims: Option<Vec<String>>,
    /// [`Profile::person_equality`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub person_equality: Option<Vec<String>>,
    /// [`Profile::unstable_claims`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unstable_claims: Option<Vec<String>>,
    /// [`Profile::max_actor_chain`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_actor_chain: Option<usize>,
    /// [`Profile::representation`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub representation: Option<Representation>,
    /// [`Profile::act_represents_patient`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act_represents_patient: Option<bool>,
    /// [`Profile::fhir_user_patient`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fhir_user_patient: Option<bool>,
    /// [`Profile::patient_context`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patient_context: Option<bool>,
    /// [`Profile::party_identifier_type`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub party_identifier_type: Option<String>,
    /// [`Profile::token_types`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_types: Option<Vec<String>>,
    /// [`Profile::required_claims`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_claims: Option<Vec<String>>,
    /// [`Profile::scope_claim`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_claim: Option<ScopeClaim>,
    /// [`Profile::app_only_scope_claim`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_only_scope_claim: Option<ScopeClaim>,
    /// [`Profile::adapter`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter: Option<String>,
    /// [`Profile::max_onward_lifetime`], a duration such as `"10min"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_onward_lifetime: Option<ferrohealth_config::units::Duration>,
    /// [`Profile::onward_grant`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onward_grant: Option<OnwardGrant>,
    /// [`Profile::onward_indicator`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onward_indicator: Option<OnwardIndicator>,
    /// [`Profile::onward_parameters`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onward_parameters: Option<BTreeMap<String, String>>,
    /// [`Profile::onward_client_id`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onward_client_id: Option<bool>,
    /// [`Profile::onward_subject_audience`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onward_subject_audience: Option<bool>,
    /// [`Profile::onward_preview`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onward_preview: Option<Vec<PreviewVariant>>,
}

/// What one issuer's tokens look like, every key resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is an independent configuration key of its own, set on its own"
)]
pub struct Profile {
    /// The claim that is the stable person identifier; `sub` by default
    /// (OpenID Connect Core 1.0 §5.7).
    pub person_key: String,
    /// The claim naming a tenant within the issuer, when it has tenants.
    pub tenant_claim: Option<String>,
    /// The claims naming the client, read in order; `client_id` by default
    /// (RFC 9068 §2.2).
    pub client_claims: Vec<String>,
    /// The markers of a token with no user, all of which must agree; by
    /// default `sub` equal to the client claim (RFC 9068 §5).
    pub app_only: Vec<Marker>,
    /// The markers of a guest, any of which marks one; none by default.
    pub guest: Vec<Marker>,
    /// A claim marking an administrator acting as a user, which is refused.
    pub impersonation_marker: Option<String>,
    /// The claims and values every token must carry.
    pub expect: BTreeMap<String, String>,
    /// The claims every token that is not app-only must carry.
    pub user_claims: Vec<String>,
    /// The claims whose values together decide that two tokens of this
    /// issuer name one person; `iss` and `sub` by default.
    pub person_equality: Vec<String>,
    /// The claims never accepted as an identifier, beside
    /// [`UNSTABLE_CLAIMS`].
    pub unstable_claims: Vec<String>,
    /// The deepest `act` chain admitted, 1 by default: prior actors are
    /// "informational only" (RFC 8693 §4.1).
    pub max_actor_chain: usize,
    /// The claims naming a represented subject, on a `persons` issuer.
    pub representation: Option<Representation>,
    /// Whether a top-level `act` of a `patients` token names the patient's
    /// representative (RFC 8693 §4.1); `false` by default, and a `patients`
    /// token carrying `act` is then refused.
    pub act_represents_patient: bool,
    /// Whether a `persons` token through an admitted client is the
    /// patient's own when its `fhirUser` is `Patient/<x>`, its `patient`
    /// claim is `x`, and it carries `patient/` scopes with no `user/` or
    /// `system/` one; `false` by default, and read on a `persons` issuer
    /// only.
    pub fhir_user_patient: bool,
    /// Whether the issuer may assert a patient context: the `patient` claim
    /// of its tokens is read as the launch context only when it is (SMART
    /// App Launch 2.2.0, Scopes and Launch Context, `launch/patient`);
    /// `false` by default, `true` under the `ferrosmart` preset.
    pub patient_context: bool,
    /// The identifier type of the party table of the issuer when the table
    /// names none; none by default.
    pub party_identifier_type: Option<String>,
    /// The accepted `typ` header values; `at+jwt` and `application/at+jwt`
    /// by default (RFC 9068 §4).
    pub token_types: Vec<String>,
    /// The claims every token must carry; the RFC 9068 §2.2 set by default.
    pub required_claims: Vec<String>,
    /// Where a token's scopes are read from; `scope` as a string by default
    /// (RFC 9068 §2.2.3).
    pub scope_claim: ScopeClaim,
    /// Where an app-only token's scopes are read from; the `scope_claim`
    /// when none.
    pub app_only_scope_claim: Option<ScopeClaim>,
    /// The vendor adapter the issuer needs, by its feature name.
    pub adapter: Option<String>,
    /// The longest an onward token this issuer issues may live, in seconds
    /// from its `iat`; required on an issuer the onward grants use.
    pub max_onward_lifetime: Option<u64>,
    /// The grant the issuer issues onward tokens under; token exchange by
    /// default (RFC 8693 §2.1).
    pub onward_grant: OnwardGrant,
    /// The token-exchange parameter a target is named in; `resource` by
    /// default (RFC 8707 §2).
    pub onward_indicator: OnwardIndicator,
    /// The parameters an onward request carries beside the grant's own.
    pub onward_parameters: BTreeMap<String, String>,
    /// Whether an onward request names `client_id` beside a client
    /// assertion, which RFC 7523 §3 leaves optional.
    pub onward_client_id: bool,
    /// Whether the subject token must name the requesting client in its
    /// `aud` before it is sent.
    pub onward_subject_audience: bool,
    /// The grant variants the issuer labels preview, which are refused.
    pub onward_preview: Vec<PreviewVariant>,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            person_key: String::from("sub"),
            tenant_claim: None,
            client_claims: vec![String::from("client_id")],
            app_only: vec![Marker::SubIsClient],
            guest: Vec::new(),
            impersonation_marker: None,
            expect: BTreeMap::new(),
            user_claims: Vec::new(),
            person_equality: vec![String::from("iss"), String::from("sub")],
            unstable_claims: Vec::new(),
            max_actor_chain: 1,
            representation: None,
            act_represents_patient: false,
            fhir_user_patient: false,
            patient_context: false,
            party_identifier_type: None,
            token_types: vec![String::from("at+jwt"), String::from("application/at+jwt")],
            required_claims: ["iss", "exp", "aud", "sub", "client_id", "iat", "jti"]
                .iter()
                .map(|&claim| claim.to_owned())
                .collect(),
            scope_claim: ScopeClaim::default(),
            app_only_scope_claim: None,
            adapter: None,
            max_onward_lifetime: None,
            onward_grant: OnwardGrant::TokenExchange,
            onward_indicator: OnwardIndicator::Resource,
            onward_parameters: BTreeMap::new(),
            onward_client_id: false,
            onward_subject_audience: false,
            onward_preview: Vec::new(),
        }
    }
}

/// A profile that breaks a rule.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProfileError {
    /// A shipped preset file does not read.
    #[error("the {preset:?} preset does not read")]
    Preset {
        /// The preset.
        preset: Preset,
        /// What the reader reported.
        #[source]
        source: Box<toml::de::Error>,
    },
    /// A deployment's profile file cannot be read.
    #[error("the profile file {} cannot be read", path.display())]
    File {
        /// The file.
        path: std::path::PathBuf,
        /// What the file system reported.
        #[source]
        source: std::io::Error,
    },
    /// A deployment's profile file is no profile.
    #[error("the profile file {} is no profile", path.display())]
    FileSyntax {
        /// The file.
        path: std::path::PathBuf,
        /// What the reader reported.
        #[source]
        source: Box<toml::de::Error>,
    },
    /// A key the issuer needs is empty.
    #[error("the profile key {key} is empty")]
    Empty {
        /// The key.
        key: &'static str,
    },
    /// A claim used as an identifier is one OpenID Connect Core 1.0 §5.7
    /// or the profile's `unstable_claims` bans as a key.
    #[error("the profile key {key} names the unstable claim {claim:?}")]
    Unstable {
        /// The key.
        key: &'static str,
        /// The claim.
        claim: String,
    },
    /// A key is set on an issuer kind it has no meaning for.
    #[error("the profile key {key} is refused on a {kind} issuer")]
    Kind {
        /// The key.
        key: &'static str,
        /// The issuer's kind.
        kind: &'static str,
    },
    /// The profile names an adapter whose feature this build leaves out.
    #[error("the profile names the adapter {adapter:?}, whose feature is not compiled in")]
    Adapter {
        /// The adapter.
        adapter: String,
    },
    /// `onward_parameters` names a parameter the client writes itself.
    #[error("onward_parameters names {parameter:?}, which the client writes itself")]
    Reserved {
        /// The parameter.
        parameter: String,
    },
    /// `onward_parameters` asks for a refresh token.
    #[error("onward_parameters asks for a refresh token")]
    RefreshToken,
}

impl Profile {
    /// Returns the profile of `preset` with `keys` set over it.
    ///
    /// # Errors
    ///
    /// [`ProfileError::Preset`] when the preset's file does not read.
    pub fn resolve(preset: Preset, keys: &ProfileKeys) -> Result<Self, ProfileError> {
        let mut profile = Self::default();
        profile.overlay(preset.keys()?);
        profile.overlay(keys.clone());
        Ok(profile)
    }

    /// Returns this profile with every key `keys` names set over it.
    #[must_use]
    pub fn with_keys(mut self, keys: ProfileKeys) -> Self {
        self.overlay(keys);
        self
    }

    /// Sets every key `keys` names over this profile.
    fn overlay(&mut self, keys: ProfileKeys) {
        let ProfileKeys {
            person_key,
            tenant_claim,
            client_claims,
            app_only,
            guest,
            impersonation_marker,
            expect,
            user_claims,
            person_equality,
            unstable_claims,
            max_actor_chain,
            representation,
            act_represents_patient,
            fhir_user_patient,
            patient_context,
            party_identifier_type,
            token_types,
            required_claims,
            scope_claim,
            app_only_scope_claim,
            adapter,
            max_onward_lifetime,
            onward_grant,
            onward_indicator,
            onward_parameters,
            onward_client_id,
            onward_subject_audience,
            onward_preview,
        } = keys;
        set(&mut self.person_key, person_key);
        set_some(&mut self.tenant_claim, tenant_claim);
        set(&mut self.client_claims, client_claims);
        set(&mut self.app_only, app_only);
        set(&mut self.guest, guest);
        set_some(&mut self.impersonation_marker, impersonation_marker);
        set(&mut self.expect, expect);
        set(&mut self.user_claims, user_claims);
        set(&mut self.person_equality, person_equality);
        set(&mut self.unstable_claims, unstable_claims);
        set(&mut self.max_actor_chain, max_actor_chain);
        set_some(&mut self.representation, representation);
        set(&mut self.act_represents_patient, act_represents_patient);
        set(&mut self.fhir_user_patient, fhir_user_patient);
        set(&mut self.patient_context, patient_context);
        set_some(&mut self.party_identifier_type, party_identifier_type);
        set(&mut self.token_types, token_types);
        set(&mut self.required_claims, required_claims);
        set(&mut self.scope_claim, scope_claim);
        set_some(&mut self.app_only_scope_claim, app_only_scope_claim);
        set_some(&mut self.adapter, adapter);
        // NOTE: RFC 7519 §2, a NumericDate counts whole seconds, so a lifetime bound
        // holds its whole seconds; rounding down only tightens it.
        set_some(
            &mut self.max_onward_lifetime,
            max_onward_lifetime.map(ferrohealth_config::units::Duration::as_secs),
        );
        set(&mut self.onward_grant, onward_grant);
        set(&mut self.onward_indicator, onward_indicator);
        set(&mut self.onward_parameters, onward_parameters);
        set(&mut self.onward_client_id, onward_client_id);
        set(&mut self.onward_subject_audience, onward_subject_audience);
        set(&mut self.onward_preview, onward_preview);
    }

    /// Checks the profile for an issuer of `kind`: no empty key the
    /// classification reads, no unstable identifier, no representation
    /// outside a `persons` issuer, no adapter this build leaves out.
    ///
    /// # Errors
    ///
    /// The [`ProfileError`] naming the first rule broken.
    pub fn validate(&self, kind: IssuerKind) -> Result<(), ProfileError> {
        let empty = [
            ("token_types", self.token_types.is_empty()),
            ("client_claims", self.client_claims.is_empty()),
            ("app_only", self.app_only.is_empty()),
            ("person_equality", self.person_equality.is_empty()),
            ("person_key", self.person_key.trim().is_empty()),
            (
                "app_only",
                self.app_only.iter().any(
                    |marker| matches!(marker, Marker::Subjects(subjects) if subjects.is_empty()),
                ),
            ),
        ];
        if let Some((key, _)) = empty.iter().find(|(_, empty)| *empty) {
            return Err(ProfileError::Empty { key });
        }
        let identifiers = std::iter::once(("person_key", &self.person_key))
            .chain(
                self.tenant_claim
                    .iter()
                    .map(|claim| ("tenant_claim", claim)),
            )
            .chain(
                self.client_claims
                    .iter()
                    .map(|claim| ("client_claims", claim)),
            )
            .chain(
                self.person_equality
                    .iter()
                    .map(|claim| ("person_equality", claim)),
            );
        for (key, claim) in identifiers {
            if self.is_unstable(claim) {
                return Err(ProfileError::Unstable {
                    key,
                    claim: claim.clone(),
                });
            }
        }
        if self.representation.is_some() && kind != IssuerKind::Persons {
            return Err(ProfileError::Kind {
                key: "representation",
                kind: kind.as_str(),
            });
        }
        if self.act_represents_patient && kind != IssuerKind::Patients {
            return Err(ProfileError::Kind {
                key: "act_represents_patient",
                kind: kind.as_str(),
            });
        }
        onward::validate(&self.onward_parameters, self.max_onward_lifetime)?;
        // NOTE: no specification governs adapters: our own design, in which a profile names
        // only an adapter this build compiles in, and any other name refuses the issuer.
        if let Some(adapter) = &self.adapter
            && !crate::idp::is_compiled(adapter)
        {
            return Err(ProfileError::Adapter {
                adapter: adapter.clone(),
            });
        }
        Ok(())
    }

    /// Returns whether `claim` may never be an identifier under this
    /// profile.
    #[must_use]
    pub fn is_unstable(&self, claim: &str) -> bool {
        UNSTABLE_CLAIMS.contains(&claim)
            || self.unstable_claims.iter().any(|banned| banned == claim)
    }

    /// Returns the client `claims` name: the first of the client claims
    /// present as a string.
    #[must_use]
    pub fn client<'a>(&self, claims: &'a Map<String, Value>) -> Option<&'a str> {
        self.client_claims
            .iter()
            .find_map(|claim| claims.get(claim).and_then(Value::as_str))
    }

    /// Returns whether `typ` is a header value the profile accepts,
    /// compared without regard to case (RFC 7515 §4.1.9).
    #[must_use]
    pub fn accepts_type(&self, typ: Option<&str>) -> bool {
        typ.is_some_and(|typ| {
            self.token_types
                .iter()
                .any(|accepted| typ.eq_ignore_ascii_case(accepted))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_preset_file_reads() {
        for preset in [
            Preset::Rfc9068,
            Preset::Entra,
            Preset::Keycloak,
            Preset::Okta,
            Preset::Ferrosmart,
        ] {
            assert!(preset.keys().is_ok(), "{preset:?} reads");
        }
        assert_eq!(Preset::Rfc9068.keys().ok(), Some(ProfileKeys::default()));
    }

    // NOTE: RFC 9068 §2.1 and §2.2, FerroSMART's tokens are plain RFC 9068; its
    // preset narrows `typ`, requires `scope` and reads a patient's own token.
    #[test]
    fn the_ferrosmart_preset_is_rfc9068_with_its_token_type_scope_and_patient() {
        let keys = Preset::Ferrosmart.keys().expect("the preset reads");
        let expected = ProfileKeys {
            fhir_user_patient: Some(true),
            patient_context: Some(true),
            party_identifier_type: Some(String::from("pairwise")),
            token_types: Some(vec![String::from("at+jwt")]),
            required_claims: Some(
                [
                    "iss",
                    "exp",
                    "aud",
                    "sub",
                    "client_id",
                    "iat",
                    "jti",
                    "scope",
                ]
                .map(String::from)
                .to_vec(),
            ),
            ..ProfileKeys::default()
        };
        assert_eq!(expected, keys, "no other key leaves its rfc9068 default");
        assert!(
            Preset::Ferrosmart
                .federation()
                .expect("the preset reads")
                .is_none()
        );
    }

    #[test]
    fn every_key_set_on_the_issuer_wins_over_the_preset() {
        let keys = ProfileKeys {
            person_key: Some(String::from("k")),
            tenant_claim: Some(String::from("t")),
            client_claims: Some(vec![String::from("c")]),
            app_only: Some(vec![Marker::Absent {
                claim: String::from("u"),
            }]),
            guest: Some(Vec::new()),
            impersonation_marker: Some(String::from("i")),
            expect: Some(BTreeMap::new()),
            user_claims: Some(Vec::new()),
            person_equality: Some(vec![String::from("iss"), String::from("k")]),
            unstable_claims: Some(vec![String::from("x")]),
            max_actor_chain: Some(3),
            representation: Some(Representation {
                claim: String::from("r"),
                ground_claim: None,
            }),
            act_represents_patient: Some(true),
            fhir_user_patient: Some(true),
            patient_context: Some(true),
            party_identifier_type: Some(String::from("login")),
            token_types: Some(vec![String::from("at+jwt")]),
            required_claims: Some(vec![String::from("iss")]),
            scope_claim: Some(ScopeClaim::default()),
            app_only_scope_claim: Some(ScopeClaim::default()),
            adapter: Some(String::from("a")),
            max_onward_lifetime: Some(ferrohealth_config::units::Duration::from_mins(10)),
            onward_grant: Some(OnwardGrant::JwtBearer),
            onward_indicator: Some(OnwardIndicator::Audience),
            onward_parameters: Some(BTreeMap::from([(
                String::from("requested_token_use"),
                String::from("on_behalf_of"),
            )])),
            onward_client_id: Some(true),
            onward_subject_audience: Some(true),
            onward_preview: Some(vec![PreviewVariant::ActorToken]),
        };
        for preset in [
            Preset::Rfc9068,
            Preset::Entra,
            Preset::Keycloak,
            Preset::Okta,
            Preset::Ferrosmart,
        ] {
            let profile = Profile::resolve(preset, &keys).expect("the preset reads");
            let back = ProfileKeys {
                person_key: Some(profile.person_key),
                tenant_claim: profile.tenant_claim,
                client_claims: Some(profile.client_claims),
                app_only: Some(profile.app_only),
                guest: Some(profile.guest),
                impersonation_marker: profile.impersonation_marker,
                expect: Some(profile.expect),
                user_claims: Some(profile.user_claims),
                person_equality: Some(profile.person_equality),
                unstable_claims: Some(profile.unstable_claims),
                max_actor_chain: Some(profile.max_actor_chain),
                representation: profile.representation,
                act_represents_patient: Some(profile.act_represents_patient),
                fhir_user_patient: Some(profile.fhir_user_patient),
                patient_context: Some(profile.patient_context),
                party_identifier_type: profile.party_identifier_type,
                token_types: Some(profile.token_types),
                required_claims: Some(profile.required_claims),
                scope_claim: Some(profile.scope_claim),
                app_only_scope_claim: profile.app_only_scope_claim,
                adapter: profile.adapter,
                max_onward_lifetime: profile
                    .max_onward_lifetime
                    .map(ferrohealth_config::units::Duration::from_secs),
                onward_grant: Some(profile.onward_grant),
                onward_indicator: Some(profile.onward_indicator),
                onward_parameters: Some(profile.onward_parameters),
                onward_client_id: Some(profile.onward_client_id),
                onward_subject_audience: Some(profile.onward_subject_audience),
                onward_preview: Some(profile.onward_preview),
            };
            assert_eq!(keys, back, "{preset:?}");
        }
    }

    #[test]
    fn a_marker_table_names_exactly_one_form() {
        let two: Result<Vec<Marker>, _> = toml::from_str::<BTreeMap<String, Vec<Marker>>>(
            "m = [{ absent_claim = \"a\", sub_is_client = true }]",
        )
        .map(|map| map.into_values().flatten().collect());
        assert!(two.is_err());
    }
}
