// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The assurance level of the authentication behind a bearer token.
//!
//! [`AssuranceSection`] maps the values of the token's authentication
//! context class claim (`acr`, OpenID Connect Core 1.0 §2, by default) to the
//! three eIDAS levels a deployment reads them as, and refuses a token below
//! its minimum with the RFC 9470 §3 step-up challenge, which names the
//! accepted values in `acr_values`. Each `[auth.issuer.<name>]` carries its own
//! section, since each issuer writes its own values. Which routes a product holds to these, and
//! what it records of them, stay the product's; RFC 9470 §3 leaves "the
//! logic through which the resource server determines that the current
//! request does not meet the authentication requirements" out of scope.
//!
//! A Basic credential carries no level, so a Basic caller has none. The mapping of claim values to levels is
//! the deployment's (no specification governs it: our own design).

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::Serialize;

use crate::refusal::AcrValueError;
use crate::refusal::Refusal;
use crate::refusal::StepUp;
use crate::resource::Caller;

/// A level of assurance of an electronic identification, in order.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AssuranceLevel {
    /// The level of assurance low.
    Low,
    /// The level of assurance substantial.
    Substantial,
    /// The level of assurance high.
    High,
}

impl AssuranceLevel {
    /// The configuration spelling: `low`, `substantial` or `high`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Substantial => "substantial",
            Self::High => "high",
        }
    }
}

/// The level a token carries and the minimum a request is held to.
///
/// Off by default: with no `minimum` nothing is refused, and with an empty
/// `levels` map no value carries a level.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AssuranceSection {
    /// The claim carrying the authentication context class, a dotted path;
    /// `acr` by default (OpenID Connect Core 1.0 §2).
    pub claim: String,
    /// The level each claim value the issuer emits stands for; a value the
    /// map does not name carries none.
    pub levels: BTreeMap<String, AssuranceLevel>,
    /// The level a request held to the section must carry; none refuses
    /// nothing.
    pub minimum: Option<AssuranceLevel>,
}

impl Default for AssuranceSection {
    fn default() -> Self {
        Self {
            claim: String::from("acr"),
            levels: BTreeMap::new(),
            minimum: None,
        }
    }
}

/// What a token says about the authentication behind it.
///
/// The `Debug` rendering names the level alone, never the claim's value.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Assessment {
    /// The claim's value, trimmed.
    pub value: Option<String>,
    /// The level the value stands for.
    pub level: Option<AssuranceLevel>,
}

impl std::fmt::Debug for Assessment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Assessment")
            .field("level", &self.level)
            .finish_non_exhaustive()
    }
}

/// Why an [`AssuranceSection`] is refused at boot.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AssuranceError {
    /// A claim path is blank, has an empty step or carries whitespace.
    #[error("the claim path {key} is blank, has an empty step or carries whitespace")]
    Claim {
        /// The key of the path.
        key: &'static str,
    },
    /// A minimum is set and no value of the map reaches it, so every
    /// request held to it would be refused.
    #[error("assurance minimum {minimum} is set and no value of the levels map reaches it")]
    Unreachable {
        /// The minimum.
        minimum: &'static str,
    },
    /// A value of the map cannot travel in the step-up challenge.
    #[error("an assurance value cannot travel in the step-up challenge")]
    Value(#[source] AcrValueError),
}

impl AssuranceSection {
    /// Checks the section: a claim path with no empty step, a minimum some
    /// mapped value reaches, and values the step-up challenge can carry.
    ///
    /// # Errors
    ///
    /// The [`AssuranceError`] naming the first rule broken.
    pub fn validate(&self) -> Result<(), AssuranceError> {
        if !crate::roles::well_formed(&self.claim) {
            return Err(AssuranceError::Claim {
                key: "assurance.claim",
            });
        }
        StepUp::new()
            .with_acr_values(self.levels.keys().cloned())
            .map_err(AssuranceError::Value)?;
        if let Some(minimum) = self.minimum
            && self.accepted().is_empty()
        {
            return Err(AssuranceError::Unreachable {
                minimum: minimum.as_str(),
            });
        }
        Ok(())
    }

    /// Returns the claim values that meet the minimum, in the map's order;
    /// none when no minimum is set.
    #[must_use]
    pub fn accepted(&self) -> Vec<&str> {
        let Some(minimum) = self.minimum else {
            return Vec::new();
        };
        self.levels
            .iter()
            .filter(|(_, level)| **level >= minimum)
            .map(|(value, _)| value.as_str())
            .collect()
    }

    /// Returns what a token's verified `claims` say about its
    /// authentication.
    #[must_use]
    pub fn assess(&self, claims: &serde_json::Map<String, serde_json::Value>) -> Assessment {
        let value = crate::roles::claim_text(claims, &self.claim).map(str::to_owned);
        let level = value
            .as_deref()
            .and_then(|value| self.levels.get(value).copied());
        Assessment { value, level }
    }

    /// Returns whether `caller` meets the minimum, by the assessment its
    /// issuer made when it was admitted; every caller does when none is set,
    /// and a Basic caller, which carries no level, meets none.
    #[must_use]
    pub fn meets(&self, caller: &Caller) -> bool {
        self.minimum.is_none_or(|minimum| {
            caller
                .assurance()
                .level
                .is_some_and(|level| level >= minimum)
        })
    }

    /// Returns the refusal of a caller below the minimum: `401` with
    /// `insufficient_user_authentication` and the accepted values in
    /// `acr_values` (RFC 9470 §3).
    ///
    /// # Errors
    ///
    /// [`AcrValueError`] for a mapped value the challenge cannot carry,
    /// which [`AssuranceSection::validate`] refuses at boot.
    pub fn step_up(&self) -> Result<Refusal, AcrValueError> {
        StepUp::new()
            .with_acr_values(self.accepted())
            .map(Refusal::StepUp)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::kind::CallerKind;

    fn bearer(sub: &str, claims: &serde_json::Value) -> Caller {
        let claims = claims.as_object().cloned().expect("an object");
        Caller::new(String::from(sub), None, "", None, CallerKind::Person)
            .with_assurance(section(None).assess(&claims))
            .with_claims(claims)
    }

    fn section(minimum: Option<AssuranceLevel>) -> AssuranceSection {
        AssuranceSection {
            levels: BTreeMap::from([
                (String::from("urn:acr:low"), AssuranceLevel::Low),
                (
                    String::from("urn:acr:substantial"),
                    AssuranceLevel::Substantial,
                ),
                (String::from("urn:acr:high"), AssuranceLevel::High),
            ]),
            minimum,
            ..AssuranceSection::default()
        }
    }

    #[test]
    fn a_token_carries_the_level_its_value_maps_to() {
        let caller = bearer("p-1", &json!({ "acr": "urn:acr:substantial" }));
        let assessment = caller.assurance().clone();
        assert_eq!(assessment.value.as_deref(), Some("urn:acr:substantial"));
        assert_eq!(assessment.level, Some(AssuranceLevel::Substantial));
        let unmapped = bearer("p-1", &json!({ "acr": "urn:acr:other" }));
        assert_eq!(unmapped.assurance().level, None);
    }

    #[test]
    fn the_minimum_refuses_lower_unmapped_and_missing_levels() {
        let substantial = section(Some(AssuranceLevel::Substantial));
        assert!(substantial.meets(&bearer("p", &json!({ "acr": "urn:acr:high" }))));
        assert!(!substantial.meets(&bearer("p", &json!({ "acr": "urn:acr:low" }))));
        assert!(!substantial.meets(&bearer("p", &json!({ "acr": "urn:acr:other" }))));
        assert!(!substantial.meets(&bearer("p", &json!({}))));
        assert!(!substantial.meets(&Caller::basic(String::from("etl"), "")));
        assert!(section(None).meets(&bearer("p", &json!({}))));
    }

    #[test]
    fn the_step_up_names_the_accepted_values() {
        let refusal = section(Some(AssuranceLevel::Substantial))
            .step_up()
            .expect("the values travel");
        let Refusal::StepUp(step_up) = refusal else {
            panic!("expected a step-up refusal, got {refusal:?}");
        };
        assert_eq!(
            step_up.acr_values(),
            ["urn:acr:high", "urn:acr:substantial"]
        );
    }

    #[test]
    fn a_section_that_would_refuse_everything_is_refused() {
        let unreachable = AssuranceSection {
            minimum: Some(AssuranceLevel::High),
            ..AssuranceSection::default()
        };
        assert_eq!(
            unreachable.validate(),
            Err(AssuranceError::Unreachable { minimum: "high" })
        );
        let blank = AssuranceSection {
            claim: String::from("a..b"),
            ..AssuranceSection::default()
        };
        assert!(matches!(
            blank.validate(),
            Err(AssuranceError::Claim { .. })
        ));
        let quoted = AssuranceSection {
            levels: BTreeMap::from([(String::from("a b"), AssuranceLevel::Low)]),
            ..AssuranceSection::default()
        };
        assert!(matches!(quoted.validate(), Err(AssuranceError::Value(_))));
        assert_eq!(section(Some(AssuranceLevel::High)).validate(), Ok(()));
    }

    #[test]
    fn a_claim_path_carrying_whitespace_is_refused() {
        for claim in [" acr", "auth context.acr", "acr\t"] {
            let spaced = AssuranceSection {
                claim: String::from(claim),
                ..AssuranceSection::default()
            };
            assert!(
                matches!(spaced.validate(), Err(AssuranceError::Claim { .. })),
                "{claim:?}"
            );
        }
    }
}
