// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The table form a [`Marker`] is written in, the conversions that hold
//! each table to exactly one form, the test a marker
//! runs, and the helpers a profile overlay sets its keys with.

use serde::Deserialize;
use serde::Serialize;
use serde_json::Map;
use serde_json::Value;

use crate::profile::Marker;

/// The table form of a [`Marker`].
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct MarkerTable {
    /// The claim of `{ claim, value }`.
    #[serde(skip_serializing_if = "Option::is_none")]
    claim: Option<String>,
    /// The value of `{ claim, value }`.
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    /// The claim of `{ absent_claim }`.
    #[serde(skip_serializing_if = "Option::is_none")]
    absent_claim: Option<String>,
    /// The subjects of `{ subjects }`.
    #[serde(skip_serializing_if = "Option::is_none")]
    subjects: Option<Vec<String>>,
    /// The `{ sub_is_client = true }` form.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    sub_is_client: bool,
    /// The claim of `{ differs_from_iss }`.
    #[serde(skip_serializing_if = "Option::is_none")]
    differs_from_iss: Option<String>,
}

impl TryFrom<MarkerTable> for Marker {
    type Error = String;

    fn try_from(table: MarkerTable) -> Result<Self, Self::Error> {
        match table {
            MarkerTable {
                claim: Some(claim),
                value: Some(value),
                absent_claim: None,
                subjects: None,
                sub_is_client: false,
                differs_from_iss: None,
            } => Ok(Self::Claim { claim, value }),
            MarkerTable {
                claim: None,
                value: None,
                absent_claim: Some(claim),
                subjects: None,
                sub_is_client: false,
                differs_from_iss: None,
            } => Ok(Self::Absent { claim }),
            MarkerTable {
                claim: None,
                value: None,
                absent_claim: None,
                subjects: Some(subjects),
                sub_is_client: false,
                differs_from_iss: None,
            } => Ok(Self::Subjects(subjects)),
            MarkerTable {
                claim: None,
                value: None,
                absent_claim: None,
                subjects: None,
                sub_is_client: true,
                differs_from_iss: None,
            } => Ok(Self::SubIsClient),
            MarkerTable {
                claim: None,
                value: None,
                absent_claim: None,
                subjects: None,
                sub_is_client: false,
                differs_from_iss: Some(claim),
            } => Ok(Self::DiffersFromIssuer { claim }),
            _ => Err(String::from(
                "a marker is exactly one of { claim, value }, { absent_claim }, { subjects }, \
                 { sub_is_client = true } and { differs_from_iss }",
            )),
        }
    }
}

impl From<Marker> for MarkerTable {
    fn from(marker: Marker) -> Self {
        match marker {
            Marker::Claim { claim, value } => Self {
                claim: Some(claim),
                value: Some(value),
                ..Self::default()
            },
            Marker::Absent { claim } => Self {
                absent_claim: Some(claim),
                ..Self::default()
            },
            Marker::Subjects(subjects) => Self {
                subjects: Some(subjects),
                ..Self::default()
            },
            Marker::SubIsClient => Self {
                sub_is_client: true,
                ..Self::default()
            },
            Marker::DiffersFromIssuer { claim } => Self {
                differs_from_iss: Some(claim),
                ..Self::default()
            },
        }
    }
}

/// Replaces `slot` with `value` when one is set.
pub(super) fn set<T>(slot: &mut T, value: Option<T>) {
    if let Some(value) = value {
        *slot = value;
    }
}

/// Replaces the optional `slot` with `value` when one is set.
pub(super) fn set_some<T>(slot: &mut Option<T>, value: Option<T>) {
    if value.is_some() {
        *slot = value;
    }
}

impl Marker {
    /// Returns whether `claims`, whose client claim reads `client`, pass
    /// this test.
    #[must_use]
    pub fn matches(&self, claims: &Map<String, Value>, client: Option<&str>) -> bool {
        match self {
            Self::Claim { claim, value } => claims
                .get(claim)
                .is_some_and(|found| text_of(found).as_deref() == Some(value.as_str())),
            Self::Absent { claim } => !claims.contains_key(claim),
            Self::Subjects(subjects) => claims
                .get("sub")
                .and_then(Value::as_str)
                .is_some_and(|sub| subjects.iter().any(|listed| listed == sub)),
            Self::SubIsClient => {
                client.is_some() && claims.get("sub").and_then(Value::as_str) == client
            }
            Self::DiffersFromIssuer { claim } => {
                let issuer = claims.get("iss").and_then(Value::as_str);
                claims
                    .get(claim)
                    .and_then(Value::as_str)
                    .is_some_and(|found| Some(found) != issuer)
            }
        }
    }
}

/// Returns the text a marker value is compared with: a string's own text,
/// or a number's or boolean's JSON text.
fn text_of(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}
