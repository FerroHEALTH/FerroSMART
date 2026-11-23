// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The attributes a `persons` issuer states about its own professional, and
//! the purposes of use every caller of a `persons`, `patients` or `machines`
//! issuer declares.
//!
//! They are the IHE IUA extension claims (ITI TF-2 §3.71.4.2.2.1.1, under
//! `extensions.ihe_iua`) and the purposes of use of RFC 9396
//! `authorization_details`.
//! One `[auth.issuer.<name>.attributes]` table per `persons` issuer maps each field to
//! its sources, the [`Field`] set and the [`Mapping::Iua`] defaults the
//! `federation` step reads. A source is a claim path or a constant: the
//! attestation and the presentations of a `federation` issuer have no place
//! on an issuer of the deployment's own. Which claims are read and how they
//! are bounded is our own design over IUA and RFC 9396.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;
use serde::Serialize;
use serde_json::Map;
use serde_json::Value;

use crate::federation::Attribute;
use crate::federation::Code;
use crate::federation::FederationError;
use crate::federation::Field;
use crate::federation::Mapping;
use crate::federation::Source;
use crate::federation::read::attribute;
use crate::federation::read::check_attribute;
use crate::federation::read::read_fields;
use crate::kind::Unclassified;
use crate::roles::lookup;

/// One `[auth.issuer.<name>.attributes]` table: where the SMART issuer
/// `issuer` states its professional's attributes and the purpose of use.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AttributesSection {
    /// The SMART issuer this table describes: `[auth]` sets it from the `[auth.issuer.<name>]` table it
    /// sits under. It renders with any userinfo masked, as
    /// [`SecretUrl`](ferrohealth_secret::secret_url::SecretUrl) renders itself.
    #[cfg_attr(feature = "schema", schemars(skip))]
    #[serde(skip)]
    pub issuer: ferrohealth_secret::secret_url::SecretUrl,
    /// The default sources the table starts from.
    pub mapping: Option<Mapping>,
    /// The sources of each field, over the mapping's.
    pub fields: BTreeMap<Field, Vec<Source>>,
    /// Whether the `purpose_of_use` of each RFC 9396 `authorization_details`
    /// entry, written `system|code`, is read as a purpose of use.
    pub authorization_details_purposes: bool,
}

impl AttributesSection {
    /// Returns the sources of every field: the mapping's, with the table's
    /// own over them.
    #[must_use]
    pub fn sources(&self) -> BTreeMap<Field, Vec<Source>> {
        Mapping::with_fields(self.mapping, &self.fields)
    }

    /// Checks the table: a source for every field, each a claim or a
    /// constant.
    ///
    /// # Errors
    ///
    /// [`FederationError::NoSource`] for a field with no source,
    /// [`FederationError::Unattested`] for an `authorization_details` source
    /// and [`FederationError::Presentations`] for a presentation source,
    /// neither of which a `persons` issuer reads.
    pub fn validate(&self) -> Result<(), FederationError> {
        for (field, sources) in self.sources() {
            if sources.is_empty() {
                return Err(FederationError::NoSource {
                    field: field.as_str(),
                });
            }
            for source in sources {
                match source {
                    Source::Claim(_) | Source::Constant(_) | Source::Coded { .. } => {}
                    Source::AuthorizationDetails(_) => return Err(FederationError::Unattested),
                    Source::Presentation(_) => return Err(FederationError::Presentations),
                }
            }
        }
        Ok(())
    }

    /// Returns the attributes the verified `claims` state under this table:
    /// every field when `professional`, the purposes of use alone otherwise.
    pub(crate) fn read(
        &self,
        claims: &Map<String, Value>,
        professional: bool,
    ) -> Result<Attributes, Unclassified> {
        let mut sources = self.sources();
        if !professional {
            sources.retain(|field, _| *field == Field::PurposeOfUse);
        }
        let fields = read_fields(sources, |field, source| {
            Ok(match source {
                Source::Claim(path) => match lookup(claims, path) {
                    None => None,
                    Some(value) => Some(shaped(field, value)?),
                },
                Source::Constant(_) | Source::Coded { .. } => source.configured(),
                Source::AuthorizationDetails(_) | Source::Presentation(_) => None,
            })
        })?;
        let mut purposes = match fields.get(&Field::PurposeOfUse) {
            Some(Attribute::Codes(codes)) => codes.clone(),
            _ => Vec::new(),
        };
        if self.authorization_details_purposes {
            purposes.extend(detail_purposes(claims)?);
        }
        purposes.sort_by(|left, right| {
            (left.system.as_deref(), left.code.as_str())
                .cmp(&(right.system.as_deref(), right.code.as_str()))
        });
        purposes.dedup();
        Ok(Attributes { fields, purposes })
    }
}

/// Returns the attribute a present claim holds for `field`, refusing a value
/// of no attribute shape, and one that is no array of codings where IUA
/// makes the field one (§3.71.4.2.2.1.1: `subject_role` and
/// `purpose_of_use` "shall be formatted as array of FHIR Coding").
fn shaped(field: Field, value: &Value) -> Result<Attribute, Unclassified> {
    let refused = || Unclassified::Attribute {
        field: field.as_str(),
    };
    let read = attribute(value).ok_or_else(refused)?;
    let coded = matches!(
        field,
        Field::ProfessionalHpProfessionalRole | Field::PurposeOfUse
    );
    if coded && !matches!(read, Attribute::Codes(_)) {
        return Err(refused());
    }
    Ok(read)
}

/// Returns the purposes of use the `authorization_details` entries name,
/// each `purpose_of_use` written `system|code`; an entry without one names
/// none.
fn detail_purposes(claims: &Map<String, Value>) -> Result<Vec<Code>, Unclassified> {
    let refused = || Unclassified::Attribute {
        field: Field::PurposeOfUse.as_str(),
    };
    let entries = match claims.get("authorization_details") {
        None => return Ok(Vec::new()),
        Some(Value::Array(entries)) => entries,
        Some(_) => return Err(refused()),
    };
    let mut purposes = Vec::new();
    for entry in entries {
        let Some(value) = entry
            .as_object()
            .and_then(|entry| entry.get("purpose_of_use"))
        else {
            continue;
        };
        let text = value.as_str().ok_or_else(refused)?;
        let (system, code) = match text.split_once('|') {
            Some((system, code)) => ((!system.is_empty()).then(|| system.to_owned()), code),
            None => (None, text),
        };
        if code.is_empty() {
            return Err(refused());
        }
        let code = Code {
            system,
            code: code.to_owned(),
        };
        check_attribute(Field::PurposeOfUse, &Attribute::Codes(vec![code.clone()]))?;
        purposes.push(code);
    }
    Ok(purposes)
}

/// What a token states under its issuer's `[auth.issuer.<name>.attributes]` table: the
/// professional of a `persons` caller other than `System`, and the purposes
/// of use of every caller.
///
/// The `Debug` rendering names the fields, never their values.
#[derive(Clone, PartialEq, Eq)]
pub struct Attributes {
    /// The fields the token states.
    fields: BTreeMap<Field, Attribute>,
    /// The purposes of use, sorted and without duplicates.
    purposes: Vec<Code>,
}

impl fmt::Debug for Attributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attributes")
            .field("fields", &self.fields.keys().collect::<Vec<_>>())
            .field("purposes", &self.purposes.len())
            .finish()
    }
}

impl Attributes {
    /// Returns the value of `field`, when the token states it.
    #[must_use]
    pub fn field(&self, field: Field) -> Option<&Attribute> {
        self.fields.get(&field)
    }

    /// Returns every field the token states.
    #[must_use]
    pub const fn fields(&self) -> &BTreeMap<Field, Attribute> {
        &self.fields
    }

    /// Returns the professional's roles, the codings of
    /// [`Field::ProfessionalHpProfessionalRole`].
    #[must_use]
    pub fn roles(&self) -> &[Code] {
        match self.fields.get(&Field::ProfessionalHpProfessionalRole) {
            Some(Attribute::Codes(codes)) => codes,
            _ => &[],
        }
    }

    /// Returns the purposes of use: the codings of [`Field::PurposeOfUse`]
    /// and, when the table reads them, the `system|code` of each
    /// `authorization_details` entry, sorted and without duplicates.
    #[must_use]
    pub fn purposes(&self) -> &[Code] {
        &self.purposes
    }
}
