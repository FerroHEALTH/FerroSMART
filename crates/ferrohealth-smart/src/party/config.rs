// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `[auth.issuer.<name>.party]` table, one per SMART issuer whose logins
//! are bound, and the rules it is loaded under.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::Serialize;

use crate::kind::IssuerKind;

/// One `[auth.issuer.<name>.party]` table: where the logins of one SMART
/// issuer are looked up.
///
/// It names no key claim: the token's `sub` is the key.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PartySection {
    /// The SMART issuer whose logins the table binds: `[auth]` sets it
    /// from the `[auth.issuer.<name>]` table it sits under. It renders with
    /// any userinfo masked, as [`SecretUrl`](ferrohealth_secret::secret_url::SecretUrl) renders itself.
    #[cfg_attr(feature = "schema", schemars(skip))]
    #[serde(skip)]
    pub issuer: ferrohealth_secret::secret_url::SecretUrl,
    /// The issuer of the identifiers the key is matched against; no two
    /// tables share one. Empty for the issuer's own identifier, which
    /// `[auth]` sets.
    pub identifier_issuer: String,
    /// The type of those identifiers, which declares the key's canonical
    /// form: `guid` or `uuid` is compared in lower case, any other type
    /// exactly. Empty for `pairwise`, FerroSMART's pairwise `sub`, which
    /// `[auth]` sets.
    pub identifier_type: String,
    /// The claim naming the groups the token asserts, an array of strings;
    /// empty to read no group.
    pub group_claim: String,
    /// The issuer of the group identifiers the group claim names; set with
    /// `group_claim`.
    pub group_identifier_issuer: String,
}

/// A party binding that breaks a rule, naming the table.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PartyError {
    /// A table names no trusted SMART issuer.
    #[error("the party table of {issuer:?} names no trusted SMART issuer")]
    NotSmart {
        /// The table's issuer.
        issuer: String,
        /// Its kind, when the section trusts it.
        kind: Option<IssuerKind>,
    },
    /// Two tables name one issuer.
    #[error("two party tables name the issuer {issuer:?}")]
    DuplicateIssuer {
        /// The issuer.
        issuer: String,
    },
    /// Two tables share an `identifier_issuer`, which would merge two
    /// subject spaces.
    #[error(
        "the party tables of {first:?} and {second:?} share the identifier_issuer \
         {identifier_issuer:?}"
    )]
    SharedIdentifierIssuer {
        /// The first table's issuer.
        first: String,
        /// The second table's issuer.
        second: String,
        /// The identifier issuer they share.
        identifier_issuer: String,
    },
    /// A key the table needs is empty.
    #[error("{key} of the party table of {issuer:?} is empty")]
    Missing {
        /// The table's issuer.
        issuer: String,
        /// The key.
        key: &'static str,
    },
    /// `group_claim` and `group_identifier_issuer` are not set together.
    #[error(
        "group_claim and group_identifier_issuer of the party table of {issuer:?} \
         are set together or not at all"
    )]
    Groups {
        /// The table's issuer.
        issuer: String,
    },
    /// A Basic user is mapped twice, or to an identifier issuer no table
    /// names.
    #[error("the Basic user {user:?} is mapped twice or to an identifier issuer no table names")]
    BasicKey {
        /// The user-id.
        user: String,
    },
    /// A Basic user of the store maps to no key.
    #[error("the Basic user {user:?} maps to no party key")]
    BasicUnmapped {
        /// The user-id.
        user: String,
    },
}

/// Checks the `tables` of a section whose issuers `kind` names, by
/// identifier.
pub(crate) fn check_tables(
    tables: &[PartySection],
    kind: impl Fn(&str) -> Option<IssuerKind>,
) -> Result<(), PartyError> {
    let mut by_identifier: BTreeMap<&str, &ferrohealth_secret::secret_url::SecretUrl> =
        BTreeMap::new();
    let mut seen = Vec::new();
    for table in tables {
        check_table(table, kind(table.issuer.expose()))?;
        if seen.contains(&table.issuer.expose()) {
            return Err(PartyError::DuplicateIssuer {
                issuer: crate::config::shown(&table.issuer),
            });
        }
        seen.push(table.issuer.expose());
        if let Some(first) = by_identifier.insert(&table.identifier_issuer, &table.issuer) {
            return Err(PartyError::SharedIdentifierIssuer {
                first: crate::config::shown(first),
                second: crate::config::shown(&table.issuer),
                identifier_issuer: table.identifier_issuer.clone(),
            });
        }
    }
    Ok(())
}

/// Checks one table against its issuer's `kind`.
pub(crate) fn check_table(
    table: &PartySection,
    kind: Option<IssuerKind>,
) -> Result<(), PartyError> {
    let issuer = || crate::config::shown(&table.issuer);
    if kind != Some(IssuerKind::Smart) {
        return Err(PartyError::NotSmart {
            issuer: issuer(),
            kind,
        });
    }
    for (key, value) in [
        (
            "auth.issuer.party.identifier_issuer",
            &table.identifier_issuer,
        ),
        ("auth.issuer.party.identifier_type", &table.identifier_type),
    ] {
        if value.trim().is_empty() {
            return Err(PartyError::Missing {
                issuer: issuer(),
                key,
            });
        }
    }
    if table.group_claim.trim().is_empty() != table.group_identifier_issuer.trim().is_empty() {
        return Err(PartyError::Groups { issuer: issuer() });
    }
    Ok(())
}

/// Returns `value` in the canonical form `identifier_type` declares: lower
/// case for a GUID, the value itself for any other type.
pub(crate) fn canonical(identifier_type: &str, value: &str) -> String {
    // NOTE: no vendored specification governs the case of a GUID: our own design,
    // which compares one in lower case.
    if identifier_type.eq_ignore_ascii_case("guid") || identifier_type.eq_ignore_ascii_case("uuid")
    {
        value.to_ascii_lowercase()
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(issuer: &str, identifier_issuer: &str) -> PartySection {
        PartySection {
            issuer: ferrohealth_secret::secret_url::SecretUrl::new(issuer),
            identifier_issuer: identifier_issuer.to_owned(),
            identifier_type: String::from("guid"),
            ..PartySection::default()
        }
    }

    #[test]
    fn a_guid_key_is_compared_in_lower_case_and_any_other_exactly() {
        assert_eq!(
            "0a1b2c3d-aaaa-bbbb-cccc-ddddeeeeffff",
            canonical("GUID", "0A1B2C3D-AAAA-bbbb-CCCC-DDDDEEEEFFFF")
        );
        assert_eq!(
            "Ab-1",
            canonical("login", "Ab-1"),
            "exact for any other type"
        );
    }

    #[test]
    fn two_tables_of_one_issuer_are_refused() {
        let tables = [table("https://a", "urn:a"), table("https://a", "urn:b")];
        assert_eq!(
            Err(PartyError::DuplicateIssuer {
                issuer: String::from("https://a")
            }),
            check_tables(&tables, |_| Some(IssuerKind::Smart))
        );
    }

    #[test]
    fn a_group_claim_needs_its_identifier_issuer() {
        let mut table = table("https://a", "urn:a");
        table.group_claim = String::from("groups");
        assert!(matches!(
            check_table(&table, Some(IssuerKind::Smart)),
            Err(PartyError::Groups { .. })
        ));
    }
}
