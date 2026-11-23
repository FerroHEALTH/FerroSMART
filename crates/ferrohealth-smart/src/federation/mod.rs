// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The attributes a `federation` issuer asserts about another party's
//! professional or organisation, and the bounds they are held to.
//!
//! One `[auth.issuer.<name>.federation]` table per `federation` issuer maps each field,
//! named after the Commission Implementing Regulation (EU) 2026/2099 Annex
//! Tables 1 and 2, to its sources: a claim path (IHE IUA §3.71.4.2.2.1.1
//! puts its claims under `extensions.ihe_iua`), a constant, an RFC 9396
//! `authorization_details` entry of the declared type whose `locations`
//! names this node, or a credential subject path in the Verifiable
//! Presentations of a Nuts RFC021 §6 introspection response. A token that
//! names a professional must carry every required professional field; one
//! that names none is an organisation's only with an explicit organisation
//! statement, or as a Nuts token without a user-authenticated credential
//! (Nuts RFC021 §8). Strings are compared exactly (RFC 9396 §12: "No
//! additional transformation or normalization is to be done"). How the
//! fields are mapped and bounded is our own design over those sources.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;
use serde::Serialize;

use crate::assurance::AssuranceLevel;

#[cfg(feature = "ehdsi-assertion")]
pub mod assertion;
pub mod contact;
pub mod person;
pub(crate) mod read;
mod section;

/// A field a `federation` issuer asserts, named after the 2026/2099 Annex.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[non_exhaustive]
pub enum Field {
    /// Table 1 `family_name`.
    #[serde(rename = "professional.family_name")]
    ProfessionalFamilyName,
    /// Table 1 `given_name`.
    #[serde(rename = "professional.given_name")]
    ProfessionalGivenName,
    /// One full-name string, as IHE IUA `subject_name` ("The user's name as
    /// String") and the eHDSI `subject-id` carry it.
    #[serde(rename = "professional.name")]
    ProfessionalName,
    /// Table 1 `country_code`.
    #[serde(rename = "professional.country_code")]
    ProfessionalCountryCode,
    /// Table 1 `hp_identifier`.
    #[serde(rename = "professional.hp_identifier")]
    ProfessionalHpIdentifier,
    /// Table 1 `issuing_authority_name`.
    #[serde(rename = "professional.issuing_authority_name")]
    ProfessionalIssuingAuthorityName,
    /// Table 1 `hp_professional_role`.
    #[serde(rename = "professional.hp_professional_role")]
    ProfessionalHpProfessionalRole,
    /// Table 1 `healthcare_provider_identifier`.
    #[serde(rename = "professional.healthcare_provider_identifier")]
    ProfessionalHealthcareProviderIdentifier,
    /// Table 2 `healthcare_provider_identifier`.
    #[serde(rename = "provider.healthcare_provider_identifier")]
    ProviderHealthcareProviderIdentifier,
    /// Table 2 `issuing_authority_name`.
    #[serde(rename = "provider.issuing_authority_name")]
    ProviderIssuingAuthorityName,
    /// Table 2 `healthcare_provider_name`.
    #[serde(rename = "provider.healthcare_provider_name")]
    ProviderHealthcareProviderName,
    /// Table 2 `healthcare_provider_address`.
    #[serde(rename = "provider.healthcare_provider_address")]
    ProviderHealthcareProviderAddress,
    /// The purpose of use of the request.
    #[serde(rename = "purpose_of_use")]
    PurposeOfUse,
    /// The authentication context the deployment maps to a level.
    #[serde(rename = "assurance")]
    Assurance,
    /// The role the professional acts on behalf of (eHDSI SAML Profile 10.0.0 §2.3, `on-behalf-of`).
    #[serde(rename = "professional.on_behalf_of")]
    ProfessionalOnBehalfOf,
    /// The authentication context class of the professional (SAML Profile §2.1, `AuthnContextClassRef`).
    #[serde(rename = "professional.authentication_method")]
    ProfessionalAuthenticationMethod,
    /// The clinical speciality of the professional (SAML Profile §2.3).
    #[serde(rename = "professional.speciality")]
    ProfessionalSpeciality,
    /// The National Provider Identifier of the professional (SAML Profile §2.3).
    #[serde(rename = "professional.npi")]
    ProfessionalNpi,
    /// The permissions of the professional (SAML Profile §2.5).
    #[serde(rename = "professional.permissions")]
    ProfessionalPermissions,
    /// The healthcare facility type (SAML Profile §2.3).
    #[serde(rename = "provider.facility_type")]
    ProviderFacilityType,
    /// The home community identifier (SAML Profile §2.3).
    #[serde(rename = "provider.home_community_id")]
    ProviderHomeCommunityId,
    /// The name of the point of care (SAML Profile §2.3, `environment:locality`).
    #[serde(rename = "point_of_care")]
    PointOfCare,
    /// The issuer of the identity assertion the token was issued on.
    #[serde(rename = "assertion.issuer")]
    AssertionIssuer,
    /// The identifier of the identity assertion.
    #[serde(rename = "assertion.id")]
    AssertionId,
    /// The start of the identity assertion's window, in seconds since the epoch.
    #[serde(rename = "assertion.not_before")]
    AssertionNotBefore,
    /// The end of the identity assertion's window, in seconds since the epoch.
    #[serde(rename = "assertion.not_on_or_after")]
    AssertionNotOnOrAfter,
    /// The identifier of the treatment relationship confirmation assertion.
    #[serde(rename = "trc.id")]
    TrcId,
    /// The start of the treatment relationship confirmation's window.
    #[serde(rename = "trc.not_before")]
    TrcNotBefore,
    /// The end of the treatment relationship confirmation's window.
    #[serde(rename = "trc.not_on_or_after")]
    TrcNotOnOrAfter,
    /// The care role the treatment relationship attests for the
    /// professional: one coded value with its code system, from the value
    /// set the deployment's access policy names. Coded only.
    #[serde(rename = "trc.care_role")]
    TrcCareRole,
    /// The patient identifier of a patient-data request.
    #[serde(rename = "patient.id")]
    PatientId,
    /// The source of the patient identifier.
    #[serde(rename = "patient.id_source")]
    PatientIdSource,
    /// The country that issued the patient identifier.
    #[serde(rename = "patient.pid_issuer_country")]
    PatientPidIssuerCountry,
    /// The reference of the consent decision the issuer rendered its
    /// authorization on: the Consent entity of the IHE BALP 1.1.4 3:5.7.6
    /// consent decision record. Text only.
    #[serde(rename = "consent.reference")]
    ConsentReference,
    /// The log correlation id of a chained organisation request, which the
    /// requester sets and each hop carries on. Text only.
    #[serde(rename = "correlation_id")]
    CorrelationId,
    /// The format of the identity assertion's `NameID`, one of the three
    /// eHDSI SAML Profile 10.0.0 §2.1 allows. Text only.
    #[serde(rename = "assertion.name_id_format")]
    AssertionNameIdFormat,
    /// The UUID of the cross-border request message, its WS-Addressing
    /// `MessageID` (eHDSI `NCPeH` Components Specifications 10.0.0 §3.5),
    /// which a MyHealth@EU contact point relays so the data holder's access
    /// record joins the contact point's audit entry. Text only; optional.
    #[serde(rename = "message_id")]
    MessageId,
}

impl Field {
    /// Returns the configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProfessionalFamilyName => "professional.family_name",
            Self::ProfessionalGivenName => "professional.given_name",
            Self::ProfessionalName => "professional.name",
            Self::ProfessionalCountryCode => "professional.country_code",
            Self::ProfessionalHpIdentifier => "professional.hp_identifier",
            Self::ProfessionalIssuingAuthorityName => "professional.issuing_authority_name",
            Self::ProfessionalHpProfessionalRole => "professional.hp_professional_role",
            Self::ProfessionalHealthcareProviderIdentifier => {
                "professional.healthcare_provider_identifier"
            }
            Self::ProviderHealthcareProviderIdentifier => "provider.healthcare_provider_identifier",
            Self::ProviderIssuingAuthorityName => "provider.issuing_authority_name",
            Self::ProviderHealthcareProviderName => "provider.healthcare_provider_name",
            Self::ProviderHealthcareProviderAddress => "provider.healthcare_provider_address",
            Self::PurposeOfUse => "purpose_of_use",
            Self::Assurance => "assurance",
            Self::ProfessionalOnBehalfOf => "professional.on_behalf_of",
            Self::ProfessionalAuthenticationMethod => "professional.authentication_method",
            Self::ProfessionalSpeciality => "professional.speciality",
            Self::ProfessionalNpi => "professional.npi",
            Self::ProfessionalPermissions => "professional.permissions",
            Self::ProviderFacilityType => "provider.facility_type",
            Self::ProviderHomeCommunityId => "provider.home_community_id",
            Self::PointOfCare => "point_of_care",
            Self::AssertionIssuer => "assertion.issuer",
            Self::AssertionId => "assertion.id",
            Self::AssertionNotBefore => "assertion.not_before",
            Self::AssertionNotOnOrAfter => "assertion.not_on_or_after",
            Self::TrcId => "trc.id",
            Self::TrcNotBefore => "trc.not_before",
            Self::TrcNotOnOrAfter => "trc.not_on_or_after",
            Self::TrcCareRole => "trc.care_role",
            Self::PatientId => "patient.id",
            Self::PatientIdSource => "patient.id_source",
            Self::PatientPidIssuerCountry => "patient.pid_issuer_country",
            Self::ConsentReference => "consent.reference",
            Self::CorrelationId => "correlation_id",
            Self::AssertionNameIdFormat => "assertion.name_id_format",
            Self::MessageId => "message_id",
        }
    }

    /// Returns whether the field describes the professional.
    pub(crate) const fn professional(self) -> bool {
        matches!(
            self,
            Self::ProfessionalFamilyName
                | Self::ProfessionalGivenName
                | Self::ProfessionalName
                | Self::ProfessionalCountryCode
                | Self::ProfessionalHpIdentifier
                | Self::ProfessionalIssuingAuthorityName
                | Self::ProfessionalHpProfessionalRole
                | Self::ProfessionalHealthcareProviderIdentifier
                | Self::ProfessionalOnBehalfOf
                | Self::ProfessionalAuthenticationMethod
                | Self::ProfessionalSpeciality
                | Self::ProfessionalNpi
                | Self::ProfessionalPermissions
        )
    }

    /// Returns whether the field takes one string, never coded values.
    pub(crate) const fn text_only(self) -> bool {
        matches!(
            self,
            Self::ConsentReference
                | Self::CorrelationId
                | Self::AssertionNameIdFormat
                | Self::MessageId
        )
    }

    /// Returns whether the field takes one code with its code system, never
    /// a string or an unsystemed code.
    pub(crate) const fn coded_only(self) -> bool {
        matches!(self, Self::TrcCareRole)
    }

    /// Returns the longest value the field takes, in characters (no
    /// specification governs the caps: our own design).
    const fn cap(self) -> usize {
        match self {
            Self::ProviderHealthcareProviderAddress => 512,
            _ => 256,
        }
    }
}

/// Where one field's value is read from, written as one table.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "SourceTable", into = "SourceTable")]
pub enum Source {
    /// A dotted claim path of the token.
    Claim(String),
    /// A value the deployment configures.
    Constant(String),
    /// A coded value the deployment configures, with its code system:
    /// `{ constant = "<code>", system = "<system>" }`, so the value carries
    /// its system and no field name says where it comes from.
    Coded {
        /// The code system.
        system: String,
        /// The code.
        code: String,
    },
    /// A dotted path within the attested `authorization_details` entry.
    AuthorizationDetails(String),
    /// A dotted path within a credential subject of the Verifiable
    /// Presentations.
    Presentation(String),
}

impl Source {
    /// Returns the value a configured source holds: a constant as text, a
    /// coded constant as one code with its system; `None` for a source the
    /// token is read for.
    pub(crate) fn configured(&self) -> Option<Attribute> {
        match self {
            Self::Constant(value) => Some(Attribute::Text(value.clone())),
            Self::Coded { system, code } => Some(Attribute::Codes(vec![Code {
                system: Some(system.clone()),
                code: code.clone(),
            }])),
            Self::Claim(_) | Self::AuthorizationDetails(_) | Self::Presentation(_) => None,
        }
    }
}

/// The table form of a [`Source`].
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct SourceTable {
    /// The claim path.
    #[serde(skip_serializing_if = "Option::is_none")]
    claim: Option<String>,
    /// The constant.
    #[serde(skip_serializing_if = "Option::is_none")]
    constant: Option<String>,
    /// The code system of the constant, which makes it a coded value.
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    /// The path within the `authorization_details` entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_details: Option<String>,
    /// The path within a credential subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    presentation: Option<String>,
}

impl TryFrom<SourceTable> for Source {
    type Error = String;

    fn try_from(table: SourceTable) -> Result<Self, Self::Error> {
        match (
            table.claim,
            table.constant,
            table.system,
            table.authorization_details,
            table.presentation,
        ) {
            (Some(path), None, None, None, None) => Ok(Self::Claim(path)),
            (None, Some(value), None, None, None) => Ok(Self::Constant(value)),
            (None, Some(code), Some(system), None, None) if !system.is_empty() => {
                Ok(Self::Coded { system, code })
            }
            (None, None, None, Some(path), None) => Ok(Self::AuthorizationDetails(path)),
            (None, None, None, None, Some(path)) => Ok(Self::Presentation(path)),
            _ => Err(String::from(
                "a source is exactly one of { claim }, { constant }, { constant, system }, \
                 { authorization_details } and { presentation }",
            )),
        }
    }
}

impl From<Source> for SourceTable {
    fn from(source: Source) -> Self {
        match source {
            Source::Claim(path) => Self {
                claim: Some(path),
                ..Self::default()
            },
            Source::Constant(value) => Self {
                constant: Some(value),
                ..Self::default()
            },
            Source::Coded { system, code } => Self {
                constant: Some(code),
                system: Some(system),
                ..Self::default()
            },
            Source::AuthorizationDetails(path) => Self {
                authorization_details: Some(path),
                ..Self::default()
            },
            Source::Presentation(path) => Self {
                presentation: Some(path),
                ..Self::default()
            },
        }
    }
}

/// A named set of default sources a table starts from.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mapping {
    /// The IHE IUA extension claims under `extensions.ihe_iua`
    /// (§3.71.4.2.2.1.1); `person_id`, the patient's identifier, is never
    /// read as the professional.
    Iua,
    /// The claims a MyHealth@EU contact point's authorization server writes
    /// from the validated identity and treatment assertions, each field under
    /// `ehdsi` at its own name (the claim names are our own design).
    Ehdsi,
}

impl Mapping {
    /// Returns the sources of every field: those `mapping` names, with
    /// `fields` over them.
    fn with_fields(
        mapping: Option<Self>,
        fields: &BTreeMap<Field, Vec<Source>>,
    ) -> BTreeMap<Field, Vec<Source>> {
        let mut sources = mapping.map(Self::sources).unwrap_or_default();
        sources.extend(fields.clone());
        sources
    }

    /// Returns the sources the mapping names.
    fn sources(self) -> BTreeMap<Field, Vec<Source>> {
        match self {
            Self::Iua => [
                (Field::ProfessionalName, "subject_name"),
                (Field::ProfessionalHpProfessionalRole, "subject_role"),
                (Field::PurposeOfUse, "purpose_of_use"),
                (
                    Field::ProfessionalHpIdentifier,
                    "national_provider_identifier",
                ),
                (
                    Field::ProfessionalHealthcareProviderIdentifier,
                    "subject_organization_id",
                ),
                (
                    Field::ProviderHealthcareProviderIdentifier,
                    "subject_organization_id",
                ),
                (
                    Field::ProviderHealthcareProviderName,
                    "subject_organization",
                ),
            ]
            .into_iter()
            .map(|(field, claim)| {
                (
                    field,
                    vec![Source::Claim(format!("extensions.ihe_iua.{claim}"))],
                )
            })
            .collect(),
            Self::Ehdsi => EHDSI_FIELDS
                .iter()
                .map(|field| {
                    (
                        *field,
                        vec![Source::Claim(format!("ehdsi.{}", field.as_str()))],
                    )
                })
                .collect(),
        }
    }
}

/// The fields a contact point's token carries under `ehdsi`: what NCPeH-A's
/// authorization server read from the identity assertion (eHDSI SAML Profile
/// 10.0.0 §2.1, §2.3) and the treatment relationship confirmation. The
/// assertion's `NameID` is `professional.hp_identifier`, and its format
/// `assertion.name_id_format`.
const EHDSI_FIELDS: [Field; 25] = [
    Field::ProfessionalHpIdentifier,
    Field::ProfessionalName,
    Field::ProfessionalHpProfessionalRole,
    Field::ProfessionalOnBehalfOf,
    Field::ProfessionalAuthenticationMethod,
    Field::ProfessionalSpeciality,
    Field::ProfessionalNpi,
    Field::ProfessionalPermissions,
    Field::ProviderHealthcareProviderIdentifier,
    Field::ProviderHealthcareProviderName,
    Field::ProviderFacilityType,
    Field::ProviderHomeCommunityId,
    Field::PointOfCare,
    Field::PurposeOfUse,
    Field::AssertionIssuer,
    Field::AssertionId,
    Field::AssertionNameIdFormat,
    Field::AssertionNotBefore,
    Field::AssertionNotOnOrAfter,
    Field::TrcId,
    Field::TrcNotBefore,
    Field::TrcNotOnOrAfter,
    Field::PatientId,
    Field::PatientIdSource,
    Field::MessageId,
];

/// One `[auth.issuer.<name>.federation]` table: what the `federation` issuer `issuer`
/// asserts and the bounds it is held to.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FederationSection {
    /// The issuer this table describes, of kind `federation`: `[auth]` sets
    /// it from the `[auth.issuer.<name>]` table it sits under. It renders
    /// with any userinfo masked, as
    /// [`SecretUrl`](ferrohealth_secret::secret_url::SecretUrl) renders itself.
    #[cfg_attr(feature = "schema", schemars(skip))]
    #[serde(skip)]
    pub issuer: ferrohealth_secret::secret_url::SecretUrl,
    /// Whether the issuer is a MyHealth@EU contact point; required, with no
    /// default.
    pub contact_point: Option<bool>,
    /// The default sources the table starts from.
    pub mapping: Option<Mapping>,
    /// The sources of each field, over the mapping's.
    pub fields: BTreeMap<Field, Vec<Source>>,
    /// The country codes a professional may carry.
    pub countries: Vec<String>,
    /// The issuing authorities a professional or provider may name.
    pub issuing_authorities: Vec<String>,
    /// The prefixes a healthcare provider identifier must start with.
    pub provider_identifier_prefixes: Vec<String>,
    /// Whether the issuer attests the `authorization_details` it puts in a
    /// token, which RFC 9396 §12 has "sent through the user agent".
    pub attests_authorization_details: bool,
    /// The `authorization_details` type the attributes are read from.
    pub authorization_details_type: Option<String>,
    /// The `authorization_details` types that state an organisation's
    /// access.
    pub organisation_types: Vec<String>,
    /// The claim holding the Verifiable Presentations of a Nuts RFC021 §6
    /// introspection response, `vps`.
    pub presentations_claim: Option<String>,
    /// The credential types the deployment declares user-authenticated.
    pub user_credential_types: Vec<String>,
    /// The fields every token of the issuer must carry, each with a source.
    pub required_fields: Vec<Field>,
    /// Whether the issuer's tokens must be sender-constrained, so the issuer
    /// fails to load without `sender_constraint = "required"`.
    pub requires_sender_constraint: bool,
    /// The subject-token issuers whose persons this issuer is trusted to map
    /// to its own, when it issues onward tokens (`client::onward`).
    pub exchanges_from: Vec<String>,
    /// The subject-token claim, a dotted path, whose value an onward token
    /// of this issuer must carry as `professional.hp_identifier`.
    pub person_mapping: Option<String>,
}

/// A `[auth.issuer.<name>.federation]` table that breaks a rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FederationError {
    /// A key the table needs is not set or empty.
    #[error("auth.federation.{key} is not set")]
    Missing {
        /// The key.
        key: &'static str,
    },
    /// A contact-point issuer declares provider identifier prefixes, which
    /// would deny access on another country's identifiers (MyHealth@EU
    /// Requirements Catalogue 10.0.0, requirements 01 and 01.02).
    #[error("a contact_point = true issuer takes no provider_identifier_prefixes")]
    ContactPointPrefixes,
    /// A source of `authorization_details` without the issuer's attestation
    /// or the declared type.
    #[error(
        "an authorization_details source needs attests_authorization_details = true \
         and authorization_details_type"
    )]
    Unattested,
    /// A presentation source without the presentations claim.
    #[error("a presentation source needs presentations_claim")]
    Presentations,
    /// A field with no source.
    #[error("the field {field} has no source")]
    NoSource {
        /// The field.
        field: &'static str,
    },
}

/// One coded value: a FHIR Coding's `system` and `code`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code {
    /// The code system, when the Coding names one.
    pub system: Option<String>,
    /// The code.
    pub code: String,
}

/// The value of one field, as asserted.
#[derive(Clone, PartialEq, Eq)]
pub enum Attribute {
    /// A string value.
    Text(String),
    /// Coded values, read from an array of FHIR Coding (IHE IUA
    /// §3.71.4.2.2.1.1) or of strings.
    Codes(Vec<Code>),
}

impl fmt::Debug for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(_) => f.debug_tuple("Text").finish_non_exhaustive(),
            Self::Codes(codes) => f.debug_tuple("Codes").field(&codes.len()).finish(),
        }
    }
}

impl Attribute {
    /// Returns every string the value carries, for the attribute checks.
    fn strings(&self) -> Vec<&str> {
        match self {
            Self::Text(text) => vec![text.as_str()],
            Self::Codes(codes) => codes
                .iter()
                .flat_map(|code| std::iter::once(code.code.as_str()).chain(code.system.as_deref()))
                .collect(),
        }
    }

    /// Returns the values a field carries: the text of a string, the codes
    /// of coded values.
    #[must_use]
    pub fn values(&self) -> Vec<&str> {
        match self {
            Self::Text(text) => vec![text.as_str()],
            Self::Codes(codes) => codes.iter().map(|code| code.code.as_str()).collect(),
        }
    }

    /// Returns the text of a string value.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            Self::Codes(_) => None,
        }
    }
}

/// The consent decision reference a `federation` token asserts.
///
/// It is the value of [`Field::ConsentReference`]: the Consent entity of the
/// IHE BALP 1.1.4 3:5.7.6 consent decision record, the decision the issuer
/// rendered its authorization on.
///
/// The `Debug` rendering never carries the value.
#[derive(Clone, PartialEq, Eq)]
pub struct ConsentReference(String);

impl fmt::Debug for ConsentReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ConsentReference").finish_non_exhaustive()
    }
}

impl ConsentReference {
    /// Returns the reference, as asserted.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The correlation id of a chained organisation request a `federation`
/// token asserts.
///
/// It is the value of [`Field::CorrelationId`], read only from the source
/// the issuer's table maps, never from a request header. The `Debug`
/// rendering never carries the value.
#[derive(Clone, PartialEq, Eq)]
pub struct CorrelationId(String);

impl fmt::Debug for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CorrelationId").finish_non_exhaustive()
    }
}

impl CorrelationId {
    /// Returns the id, as asserted.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The UUID of the cross-border request message a MyHealth@EU contact
/// point's token relays.
///
/// It is the value of [`Field::MessageId`]: the WS-Addressing `MessageID` of
/// the request (eHDSI `NCPeH` Components Specifications 10.0.0 §3.5), as
/// relayed, a `urn:uuid:` form included. A product records it in its access
/// record to join the contact point's Patient Privacy audit entry. The
/// `Debug` rendering never carries the value.
#[derive(Clone, PartialEq, Eq)]
pub struct MessageId(String);

impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MessageId").finish_non_exhaustive()
    }
}

impl MessageId {
    /// Returns the id, as relayed.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a `federation` token asserts about another party, recorded as
/// asserted and never bound to a local party.
///
/// The `Debug` rendering names the fields, never their values.
#[derive(Clone, PartialEq, Eq)]
pub struct External {
    /// The token's `sub`, in the issuer's own namespace.
    remote_subject: String,
    /// The fields the token carries.
    fields: BTreeMap<Field, Attribute>,
}

impl fmt::Debug for External {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("External")
            .field("fields", &self.fields.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl External {
    /// Returns the external party asserting `fields` for the remote subject
    /// `remote_subject`, for a test of a downstream crate (feature
    /// `test-support`).
    ///
    /// The fields are taken as given: none of the checks a `federation`
    /// token's classification applies runs here, so a product never builds
    /// the value it admits a caller under this way.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn new(remote_subject: impl Into<String>, fields: BTreeMap<Field, Attribute>) -> Self {
        Self {
            remote_subject: remote_subject.into(),
            fields,
        }
    }

    /// Returns the token's `sub`, which names a user in the issuer's
    /// namespace and is never matched against a local party.
    #[must_use]
    pub fn remote_subject(&self) -> &str {
        &self.remote_subject
    }

    /// Returns the value of `field`, when the token asserts it.
    #[must_use]
    pub fn field(&self, field: Field) -> Option<&Attribute> {
        self.fields.get(&field)
    }

    /// Returns every field the token asserts.
    #[must_use]
    pub const fn fields(&self) -> &BTreeMap<Field, Attribute> {
        &self.fields
    }

    /// Returns the consent decision reference the token asserts, when its
    /// issuer's table maps [`Field::ConsentReference`] and the token carries
    /// it.
    #[must_use]
    pub fn consent_reference(&self) -> Option<ConsentReference> {
        self.field(Field::ConsentReference)
            .and_then(Attribute::text)
            .map(|text| ConsentReference(text.to_owned()))
    }

    /// Returns the correlation id the token asserts, when its issuer's table
    /// maps [`Field::CorrelationId`] and the token carries it.
    #[must_use]
    pub fn correlation_id(&self) -> Option<CorrelationId> {
        self.field(Field::CorrelationId)
            .and_then(Attribute::text)
            .map(|text| CorrelationId(text.to_owned()))
    }

    /// Returns the UUID of the cross-border request message the token
    /// relays, when its issuer's table maps [`Field::MessageId`] (the
    /// `ehdsi` mapping reads `ehdsi.message_id`) and the token carries it.
    #[must_use]
    pub fn message_id(&self) -> Option<MessageId> {
        self.field(Field::MessageId)
            .and_then(Attribute::text)
            .map(|text| MessageId(text.to_owned()))
    }
}

/// What a `federation` token was classified as.
pub(crate) enum Outcome {
    /// A professional of the other party.
    Person(External),
    /// The other party's organisation.
    Organisation(External),
}

/// What the classification of a `federation` token reads beside its
/// claims.
pub(crate) struct Context<'a> {
    /// The issuer's table.
    pub(crate) section: &'a FederationSection,
    /// This node's audiences, one of which an entry's `locations` names.
    pub(crate) audiences: &'a [String],
    /// The level of the issuer's assurance claim, when it maps one.
    pub(crate) level: Option<AssuranceLevel>,
    /// The issuer's assurance mapping, for a mapped `assurance` field.
    pub(crate) levels: Option<&'a BTreeMap<String, AssuranceLevel>>,
}

/// The fields a professional must carry beside a name (2026/2099 Annex
/// Table 1).
pub(crate) const REQUIRED: [Field; 5] = [
    Field::ProfessionalCountryCode,
    Field::ProfessionalHpIdentifier,
    Field::ProfessionalIssuingAuthorityName,
    Field::ProfessionalHpProfessionalRole,
    Field::ProfessionalHealthcareProviderIdentifier,
];
