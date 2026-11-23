// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The eIDAS level of assurance of a person's login, which every token
//! issued on it carries as `acr` (`docs/architecture.md` §13.28).
//!
//! The levels are those of Regulation (EU) No 910/2014 Article 8(2), whose
//! technical specifications Implementing Regulation (EU) 2015/1502 sets out.
//! Each upstream provider names its own values for them, so each
//! `[[ferrosmart.upstream]]` entry maps its values to a level; a login is
//! held to the deployment's floor, the provider's minimum, the client's
//! minimum and the level the app asks for with `acr_values`.

use std::collections::BTreeMap;

use ferrohealth_smart::assurance::AssuranceLevel;
use serde::{Deserialize, Serialize};

/// The `acr` value of each level: the eIDAS level-of-assurance URIs.
const URIS: [(AssuranceLevel, &str); 3] = [
    (AssuranceLevel::Low, "http://eidas.europa.eu/LoA/low"),
    (
        AssuranceLevel::Substantial,
        "http://eidas.europa.eu/LoA/substantial",
    ),
    (AssuranceLevel::High, "http://eidas.europa.eu/LoA/high"),
];

/// Returns the `acr` value FerroSMART writes for `level`.
#[must_use]
pub fn uri(level: AssuranceLevel) -> &'static str {
    URIS.iter()
        .find(|(known, _)| *known == level)
        .map_or("", |(_, uri)| uri)
}

/// Returns the level whose `acr` value is `uri`, none for any other value.
#[must_use]
pub fn of_uri(uri: &str) -> Option<AssuranceLevel> {
    URIS.iter()
        .find(|(_, known)| *known == uri)
        .map(|(level, _)| *level)
}

/// Returns the level spelled `text` as configuration and the store spell
/// it: `low`, `substantial` or `high`.
#[must_use]
pub fn parse(text: &str) -> Option<AssuranceLevel> {
    [
        AssuranceLevel::Low,
        AssuranceLevel::Substantial,
        AssuranceLevel::High,
    ]
    .into_iter()
    .find(|level| level.as_str() == text)
}

/// The deployment's floor, `[ferrosmart] assurance_minimum`.
///
/// Every person's login reaches it. It is `substantial` by default, the
/// least Implementing Regulation (EU) 2026/2099 Articles 4(2) and 6(3) admit
/// for a natural person and a health professional.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Floor {
    /// No floor, for a deployment outside the eIDAS area.
    None,
    /// The level of assurance low.
    Low,
    /// The level of assurance substantial.
    #[default]
    Substantial,
    /// The level of assurance high.
    High,
}

impl Floor {
    /// Returns the level of the floor, none for [`Floor::None`].
    #[must_use]
    pub const fn level(self) -> Option<AssuranceLevel> {
        match self {
            Self::None => None,
            Self::Low => Some(AssuranceLevel::Low),
            Self::Substantial => Some(AssuranceLevel::Substantial),
            Self::High => Some(AssuranceLevel::High),
        }
    }
}

/// `[ferrosmart.upstream.assurance]`: the level each of the provider's
/// values stands for, and the provider's own minimum.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AssuranceSection {
    /// The level each value stands for: an OpenID Connect provider's `acr`,
    /// a SAML provider's `AuthnContextClassRef`. A value the map does not
    /// name carries no level.
    pub levels: BTreeMap<String, AssuranceLevel>,
    /// The level every login at the provider reaches, above the
    /// deployment's floor; none leaves the floor alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum: Option<AssuranceLevel>,
}

/// A provider's assurance, resolved: its levels and the minimum a login
/// at it reaches, the deployment's floor included.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Assurance {
    /// The level each of the provider's values stands for.
    levels: BTreeMap<String, AssuranceLevel>,
    /// The higher of the deployment's floor and the provider's minimum.
    minimum: Option<AssuranceLevel>,
}

/// Why a provider's assurance is refused at load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AssuranceError {
    /// No value of the map reaches the minimum, so every login at the
    /// provider would be refused.
    #[error("no value of `assurance.levels` reaches the minimum {minimum}")]
    Unreachable {
        /// The minimum.
        minimum: &'static str,
    },
}

impl Assurance {
    /// Returns the assurance `section` describes under the deployment's
    /// `floor`.
    ///
    /// # Errors
    /// Returns [`AssuranceError::Unreachable`] when a minimum is set and no
    /// mapped value reaches it.
    pub fn resolve(section: &AssuranceSection, floor: Floor) -> Result<Self, AssuranceError> {
        let minimum = floor.level().max(section.minimum);
        if let Some(minimum) = minimum
            && !section.levels.values().any(|level| *level >= minimum)
        {
            return Err(AssuranceError::Unreachable {
                minimum: minimum.as_str(),
            });
        }
        Ok(Self {
            levels: section.levels.clone(),
            minimum,
        })
    }

    /// Returns the minimum a login at the provider reaches.
    #[must_use]
    pub const fn minimum(&self) -> Option<AssuranceLevel> {
        self.minimum
    }

    /// Returns the level the provider's `value` stands for.
    #[must_use]
    pub fn level_of(&self, value: Option<&str>) -> Option<AssuranceLevel> {
        value.and_then(|value| self.levels.get(value.trim()).copied())
    }

    /// Returns the levels the provider's values map to, each once, lowest
    /// first.
    pub fn levels(&self) -> impl Iterator<Item = AssuranceLevel> + '_ {
        let mut levels: Vec<AssuranceLevel> = self.levels.values().copied().collect();
        levels.sort_unstable();
        levels.dedup();
        levels.into_iter()
    }

    /// Returns the provider's values at or above `at_least`, lowest level
    /// first: what an upstream request asks for in `acr_values`.
    #[must_use]
    pub fn values_from(&self, at_least: AssuranceLevel) -> Vec<&str> {
        let mut values: Vec<(&AssuranceLevel, &String)> = self
            .levels
            .iter()
            .filter(|(_, level)| **level >= at_least)
            .map(|(value, level)| (level, value))
            .collect();
        values.sort();
        values
            .into_iter()
            .map(|(_, value)| value.as_str())
            .collect()
    }
}

/// Returns the level an app's `acr_values` asks for: the lowest level among
/// the eIDAS URIs it lists, since any of them answers the request (OpenID
/// Connect Core 1.0 §3.1.2.1); none when it lists none.
#[must_use]
pub fn requested(acr_values: &str) -> Option<AssuranceLevel> {
    acr_values.split(' ').filter_map(of_uri).min()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(minimum: Option<AssuranceLevel>) -> AssuranceSection {
        AssuranceSection {
            levels: BTreeMap::from([
                (String::from("urn:idp:password"), AssuranceLevel::Low),
                (String::from("urn:idp:app"), AssuranceLevel::Substantial),
                (String::from("urn:idp:wallet"), AssuranceLevel::High),
            ]),
            minimum,
        }
    }

    #[test]
    fn each_level_has_its_eidas_uri_and_reads_back() {
        for level in [
            AssuranceLevel::Low,
            AssuranceLevel::Substantial,
            AssuranceLevel::High,
        ] {
            assert_eq!(Some(level), of_uri(uri(level)));
        }
        assert_eq!(
            "http://eidas.europa.eu/LoA/substantial",
            uri(AssuranceLevel::Substantial)
        );
        assert_eq!(None, of_uri("http://eidas.europa.eu/LoA/other"));
    }

    #[test]
    fn the_minimum_is_the_higher_of_the_floor_and_the_provider_s() {
        let floor = Assurance::resolve(&section(None), Floor::Substantial).expect("resolves");
        assert_eq!(Some(AssuranceLevel::Substantial), floor.minimum());
        let own =
            Assurance::resolve(&section(Some(AssuranceLevel::High)), Floor::Low).expect("resolves");
        assert_eq!(Some(AssuranceLevel::High), own.minimum());
        let none = Assurance::resolve(&AssuranceSection::default(), Floor::None).expect("resolves");
        assert_eq!(None, none.minimum());
    }

    #[test]
    fn a_minimum_no_value_reaches_is_refused() {
        let low = AssuranceSection {
            levels: BTreeMap::from([(String::from("urn:idp:password"), AssuranceLevel::Low)]),
            minimum: None,
        };
        assert_eq!(
            Err(AssuranceError::Unreachable {
                minimum: "substantial"
            }),
            Assurance::resolve(&low, Floor::Substantial)
        );
        assert_eq!(
            Err(AssuranceError::Unreachable {
                minimum: "substantial"
            }),
            Assurance::resolve(&AssuranceSection::default(), Floor::Substantial)
        );
    }

    #[test]
    fn a_value_maps_to_its_level_and_an_unknown_one_to_none() {
        let assurance = Assurance::resolve(&section(None), Floor::None).expect("resolves");
        assert_eq!(
            Some(AssuranceLevel::High),
            assurance.level_of(Some("urn:idp:wallet"))
        );
        assert_eq!(None, assurance.level_of(Some("urn:idp:other")));
        assert_eq!(None, assurance.level_of(None));
        assert_eq!(
            vec!["urn:idp:app", "urn:idp:wallet"],
            assurance.values_from(AssuranceLevel::Substantial)
        );
    }

    #[test]
    fn acr_values_ask_for_the_lowest_eidas_level_they_list() {
        assert_eq!(
            Some(AssuranceLevel::Substantial),
            requested("http://eidas.europa.eu/LoA/high http://eidas.europa.eu/LoA/substantial")
        );
        assert_eq!(None, requested("urn:other 0"));
        assert_eq!(None, requested(""));
    }
}
