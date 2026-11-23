// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Who stands behind a credential, read from the token's standard claims
//! the same way for every issuer.
//!
//! A token with no user is a client credentials token, whose `sub` names
//! its client (RFC 9068 §2.2; SMART App Launch 2.2.0, Backend Services).
//! A user is named by their `fhirUser` and its resource type, with
//! `patient` the launch context (SMART App Launch 2.2.0, Scopes and Launch
//! Context), and an RFC 8693 §4.1 `act` names the actor beside them. A
//! `federation` issuer's tokens are read under its own table
//! ([`crate::federation`]). A Basic credential is a user's, never a
//! system's: a machine authenticates with the client credentials grant
//! (RFC 6749 §4.4).

use std::fmt;

use serde::Deserialize;
use serde::Serialize;
use serde_json::Map;
use serde_json::Value;

use crate::federation::Context;
use crate::federation::External;
use crate::federation::Outcome;
use crate::profile::Profile;

/// Whose tokens an issuer signs.
///
/// Every issuer is a SMART authorization server unless its table declares
/// `kind = "federation"`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IssuerKind {
    /// A SMART App Launch 2.2 authorization server, FerroSMART among them,
    /// whose tokens are read from their standard claims.
    #[default]
    #[serde(skip_deserializing)]
    Smart,
    /// Another party's issuer, whose tokens name its professionals or its
    /// organisation (Regulation (EU) 2025/327 Art 23).
    Federation,
}

impl IssuerKind {
    /// Returns the name the configuration and the refusals use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Smart => "smart",
            Self::Federation => "federation",
        }
    }
}

impl fmt::Display for IssuerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An RFC 8693 §4.1 actor: "the combination of the two claims `iss` and
/// `sub` might be necessary to uniquely identify an actor".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    /// The actor's issuer, the token's own when `act` names none.
    pub issuer: String,
    /// The actor's `sub`.
    pub sub: String,
}

/// Who stands behind a caller's credential.
///
/// A user is named by the resource type of their `fhirUser` (SMART App
/// Launch 2.2.0, Scopes and Launch Context). The `Debug` rendering names the
/// kind alone.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CallerKind {
    /// No user: a client credentials token, whose `sub` is its `client_id`.
    System,
    /// A user whose `fhirUser` is a `Patient`.
    Patient,
    /// A user whose `fhirUser` is a `Practitioner`.
    Practitioner,
    /// A user whose `fhirUser` is a `PractitionerRole`.
    PractitionerRole,
    /// A user whose `fhirUser` is a `RelatedPerson`: with a patient in
    /// context, that patient's representative (Regulation (EU) 2025/327
    /// Art 4(2)).
    RelatedPerson,
    /// A user whose `fhirUser` is a `Person`.
    Person,
    /// A user of no stated type: a token without `fhirUser`, or a Basic
    /// credential.
    User,
    /// A professional of another party, on a `federation` issuer, with what
    /// the token asserts about them.
    ExternalPerson(Box<External>),
    /// Another party's organisation, on a `federation` issuer.
    ExternalOrganisation(Box<External>),
}

impl fmt::Debug for CallerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExternalPerson(external) => {
                f.debug_tuple("ExternalPerson").field(external).finish()
            }
            Self::ExternalOrganisation(external) => f
                .debug_tuple("ExternalOrganisation")
                .field(external)
                .finish(),
            other => f.write_str(other.variant()),
        }
    }
}

impl CallerKind {
    /// Returns the name the audit line records.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Patient => "patient",
            Self::Practitioner => "practitioner",
            Self::PractitionerRole => "practitioner_role",
            Self::RelatedPerson => "related_person",
            Self::Person => "person",
            Self::User => "user",
            Self::ExternalPerson(_) => "external_person",
            Self::ExternalOrganisation(_) => "external_organisation",
        }
    }

    /// Returns the variant's name, for the `Debug` rendering.
    const fn variant(&self) -> &'static str {
        match self {
            Self::System => "System",
            Self::Patient => "Patient",
            Self::Practitioner => "Practitioner",
            Self::PractitionerRole => "PractitionerRole",
            Self::RelatedPerson => "RelatedPerson",
            Self::Person => "Person",
            Self::User => "User",
            Self::ExternalPerson(_) => "ExternalPerson",
            Self::ExternalOrganisation(_) => "ExternalOrganisation",
        }
    }

    /// Returns the kind of the user whose `fhirUser` names a resource of
    /// `resource_type`, or `None` for a type SMART App Launch 2.2.0 does
    /// not name for `fhirUser`.
    #[must_use]
    pub fn of_fhir_user(resource_type: &str) -> Option<Self> {
        Some(match resource_type {
            "Patient" => Self::Patient,
            "Practitioner" => Self::Practitioner,
            "PractitionerRole" => Self::PractitionerRole,
            "RelatedPerson" => Self::RelatedPerson,
            "Person" => Self::Person,
            _ => return None,
        })
    }

    /// Returns whether the caller is a user, a person named by a token or a
    /// Basic credential, and not a system or another party.
    #[must_use]
    pub const fn is_user(&self) -> bool {
        matches!(
            self,
            Self::Patient
                | Self::Practitioner
                | Self::PractitionerRole
                | Self::RelatedPerson
                | Self::Person
                | Self::User
        )
    }

    /// Returns what a `federation` token asserts about the other party,
    /// for an [`CallerKind::ExternalPerson`] or an
    /// [`CallerKind::ExternalOrganisation`].
    #[must_use]
    pub fn external(&self) -> Option<&External> {
        match self {
            Self::ExternalPerson(external) | Self::ExternalOrganisation(external) => Some(external),
            _ => None,
        }
    }
}

/// Why a valid token matches no step of the classification for its issuer's
/// kind. Each names a check or a configured claim, never a claim value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Unclassified {
    /// The `scope` claim is not one string (RFC 9068 §2.2.3).
    #[error("the scope claim is not one string")]
    ScopeForm,
    /// A user's token names no client.
    #[error("a user's token names no client")]
    NoClient,
    /// The `fhirUser` claim is no reference to a `Patient`, a
    /// `Practitioner`, a `PractitionerRole`, a `RelatedPerson` or a
    /// `Person`.
    #[error("the fhirUser claim names no user resource")]
    FhirUser,
    /// The `act` chain is deeper than the profile admits, or `act` is not
    /// an object with a string `sub`.
    #[error("the act chain is deeper than admitted or malformed")]
    ActorChain,
    /// A token that names a professional misses required fields, each named.
    #[error("a federation token names a professional and misses {missing:?}")]
    ExternalIncomplete {
        /// The fields it misses.
        missing: Vec<&'static str>,
    },
    /// A token misses fields the issuer's table requires, each named.
    #[error("a federation token misses the required fields {missing:?}")]
    RequiredFields {
        /// The fields it misses.
        missing: Vec<&'static str>,
    },
    /// An attribute is outside the bounds the issuer's table declares.
    #[error("the attribute {field} is outside the declared bounds")]
    OutOfBounds {
        /// The field.
        field: &'static str,
    },
    /// An attribute holds a control or bidi-control character, or is too
    /// long.
    #[error("the attribute {field} holds a refused character or is too long")]
    Attribute {
        /// The field.
        field: &'static str,
    },
    /// Two sources of one field give different values.
    #[error("the sources of {field} disagree")]
    SourcesDisagree {
        /// The field.
        field: &'static str,
    },
    /// The `authorization_details` carry no single entry of a declared type
    /// whose `locations` names this node.
    #[error("no declared authorization_details entry names this node")]
    AuthorizationDetails,
    /// A token that names no professional carries no organisation statement.
    #[error("a federation token names no professional and states no organisation access")]
    NoOrganisationStatement,
    /// A professional's authentication is below the level a domestic
    /// federation issuer requires.
    #[error("the professional's authentication is below the required level")]
    AssuranceTooLow,
    /// The Verifiable Presentations do not read.
    #[error("the verifiable presentations do not read")]
    Presentations,
    /// A contact-point token misses an attribute or outlives its assertions,
    /// with the MyHealth@EU Requirements Catalogue 10.0.0 §1.25 code name.
    #[error("a contact-point token is refused as {code}, missing {missing:?}")]
    ContactPoint {
        /// The §1.25 code name.
        code: crate::federation::contact::EhdsiCode,
        /// The fields it misses, for `ERROR_HPI_INSUFFICIENT_INFORMATION`.
        missing: Vec<&'static str>,
    },
    /// The issuer's kind has no step this build classifies.
    #[error("no step classifies a token of a {kind} issuer")]
    NoStep {
        /// The kind.
        kind: IssuerKind,
    },
}

impl Unclassified {
    /// Returns the stable reason code of the step that refused the token
    /// ([`crate::refusal::Reason::Unclassified`]).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ScopeForm => "scope-form",
            Self::NoClient => "client-missing",
            Self::FhirUser => "fhir-user-refused",
            Self::ActorChain => "actor-chain-refused",
            Self::ExternalIncomplete { .. } => "professional-incomplete",
            Self::RequiredFields { .. } => "required-fields-missing",
            Self::OutOfBounds { .. } => "attribute-out-of-bounds",
            Self::Attribute { .. } => "attribute-refused",
            Self::SourcesDisagree { .. } => "sources-disagree",
            Self::AuthorizationDetails => "authorization-details-refused",
            Self::NoOrganisationStatement => "organisation-statement-missing",
            Self::AssuranceTooLow => "assurance-too-low",
            Self::Presentations => "presentations-unreadable",
            Self::ContactPoint { .. } => "contact-point-refused",
            Self::NoStep { .. } => "kind-unclassified",
        }
    }
}

/// What a classification read from a token's claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Classified {
    /// The kind.
    pub(crate) kind: CallerKind,
    /// The client the token names.
    pub(crate) client: Option<String>,
    /// The current RFC 8693 §4.1 actor, when the token names one.
    pub(crate) actor: Option<Actor>,
}

/// Returns the kind of the caller whose verified `claims` an issuer of
/// `kind` signed under `profile`, attributed to `issuer`.
pub(crate) fn classify(
    kind: IssuerKind,
    profile: &Profile,
    federation: Option<&Context<'_>>,
    claims: &Map<String, Value>,
    issuer: &str,
) -> Result<Classified, Unclassified> {
    let client = Profile::client(claims).map(str::to_owned);
    let caller = match kind {
        IssuerKind::Smart if Profile::app_only(claims) => CallerKind::System,
        IssuerKind::Smart => {
            if client.is_none() {
                return Err(Unclassified::NoClient);
            }
            user(claims)?
        }
        IssuerKind::Federation => {
            let context = federation.ok_or(Unclassified::NoStep { kind })?;
            match crate::federation::read::classify(claims, client.as_deref(), context)? {
                Outcome::Person(external) => CallerKind::ExternalPerson(Box::new(external)),
                Outcome::Organisation(external) => {
                    CallerKind::ExternalOrganisation(Box::new(external))
                }
            }
        }
    };
    let actor = match claims.get("act") {
        Some(act) => Some(actor(
            act,
            &token_issuer(claims, issuer),
            profile.max_actor_chain,
        )?),
        None => None,
    };
    Ok(Classified {
        kind: caller,
        client,
        actor,
    })
}

/// Returns the kind of the user `claims` name by their `fhirUser`, a user
/// of no stated type when the token carries none.
fn user(claims: &Map<String, Value>) -> Result<CallerKind, Unclassified> {
    match claims.get("fhirUser") {
        None => Ok(CallerKind::User),
        Some(Value::String(fhir_user)) => fhir_user_type(fhir_user)
            .and_then(CallerKind::of_fhir_user)
            .ok_or(Unclassified::FhirUser),
        Some(_) => Err(Unclassified::FhirUser),
    }
}

/// Returns the resource type of the `fhirUser` reference `fhir_user`,
/// relative (`Practitioner/<id>`) or absolute.
pub(crate) fn fhir_user_type(fhir_user: &str) -> Option<&str> {
    fhir_user_parts(fhir_user).map(|(resource_type, _)| resource_type)
}

/// Returns the resource type and the id of the `fhirUser` reference
/// `fhir_user`: a relative `<type>/<id>`, or the last two path segments of
/// an absolute URL.
pub(crate) fn fhir_user_parts(fhir_user: &str) -> Option<(&str, &str)> {
    // NOTE: SMART App Launch 2.2.0, Scopes for requesting identity data: the
    // `fhirUser` URL MAY be absolute or relative to the FHIR base.
    let mut segments = fhir_user.rsplit('/');
    let id = segments.next().filter(|id| !id.is_empty())?;
    let resource_type = segments.next().filter(|kind| !kind.is_empty())?;
    match segments.next() {
        None => Some((resource_type, id)),
        Some(_) if fhir_user.contains("://") => Some((resource_type, id)),
        Some(_) => None,
    }
}

/// Returns the issuer of `claims`: its `iss`, or `issuer`, the one it is
/// attributed to, when it names none (an RFC 7662 §2.2 response).
fn token_issuer(claims: &Map<String, Value>, issuer: &str) -> String {
    text(claims, "iss").unwrap_or_else(|| issuer.to_owned())
}

/// Returns the current actor `act` names, with its object, refusing an
/// `act` that is no object with a string `sub`.
fn current_actor<'a>(
    act: &'a Value,
    token_issuer: &str,
) -> Result<(Actor, &'a Map<String, Value>), Unclassified> {
    let object = act.as_object().ok_or(Unclassified::ActorChain)?;
    let sub = object
        .get("sub")
        .and_then(Value::as_str)
        .filter(|sub| !sub.trim().is_empty())
        .ok_or(Unclassified::ActorChain)?;
    let issuer = object
        .get("iss")
        .and_then(Value::as_str)
        .unwrap_or(token_issuer);
    Ok((
        Actor {
            issuer: issuer.to_owned(),
            sub: sub.to_owned(),
        },
        object,
    ))
}

/// Returns the actor `act` names, refusing a chain deeper than `max`.
pub(crate) fn actor(act: &Value, token_issuer: &str, max: usize) -> Result<Actor, Unclassified> {
    let (actor, object) = current_actor(act, token_issuer)?;
    let mut depth = 1_usize;
    let mut current = object;
    while let Some(prior) = current.get("act") {
        depth = depth.saturating_add(1);
        current = prior.as_object().ok_or(Unclassified::ActorChain)?;
    }
    if depth > max {
        return Err(Unclassified::ActorChain);
    }
    Ok(actor)
}

/// Returns the string claim `name`, trimmed, when it is not blank.
fn text(claims: &Map<String, Value>, name: &str) -> Option<String> {
    crate::roles::claim_text(claims, name).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fhir_user_reference_is_relative_or_absolute() {
        assert_eq!(Some("Practitioner"), fhir_user_type("Practitioner/p-1"));
        assert_eq!(
            Some(("Patient", "p-1")),
            fhir_user_parts("https://fhir.example.org/r4/Patient/p-1")
        );
        assert_eq!(None, fhir_user_type("Patient"));
        assert_eq!(None, fhir_user_type("Patient/"));
        assert_eq!(None, fhir_user_type("Group/Patient/p-1"));
        assert_eq!(Some("RelatedPerson"), fhir_user_type("RelatedPerson/r-1"));
    }
}
