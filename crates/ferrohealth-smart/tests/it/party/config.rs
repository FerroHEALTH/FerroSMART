// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `[auth.issuer.<name>.party]` tables as a deployment writes them, and every rule
//! they are loaded under.

use super::*;

/// Returns the `[auth]` section `text` reads as.
fn section(text: &str) -> Result<AuthSection, toml::de::Error> {
    toml::from_str(text)
}

/// The issuer tables of the configuration cases.
const ISSUERS: &str = r#"
[issuer.i1]
issuer = "https://login.example.org/tenant-1/v2.0"
audience = ["api://ferro"]
jwks_file = "/dev/null"

[issuer.i2]
issuer = "https://as.example.org/realms/other"
audience = ["api://ferro"]
jwks_file = "/dev/null"

[issuer.i3]
issuer = "https://other-party.example.org"
kind = "federation"
audience = ["api://ferro"]
jwks_file = "/dev/null"

[issuer.i3.federation]
contact_point = false
countries = ["NL"]
issuing_authorities = ["CIBG"]
provider_identifier_prefixes = ["urn:oid:2.16.528.1.1007.3.3."]
"#;

/// Returns the party error a section of [`ISSUERS`] and `party` resolves to.
fn party_error(party: &str) -> Result<PartyError, Box<dyn StdError>> {
    match section(&format!("{ISSUERS}{party}"))?.resolve(&[]) {
        Err(ConfigError::Party { source }) => Ok(source),
        other => Err(format!("a party error, not {other:?}").into()),
    }
}

#[test]
fn a_table_that_sets_claim_is_an_unknown_key_at_load() {
    let read = section(&format!(
        r#"{ISSUERS}
[issuer.i1.party]
identifier_issuer = "urn:example:ferro:login"
identifier_type = "guid"
claim = "sub"
"#
    ));
    assert!(read.is_err(), "claim is no key of the table");
}

// NOTE: no specification governs the configuration: our own design, in which two tables
// never share an identifier_issuer, because two subject spaces would merge.
#[test]
fn two_tables_sharing_an_identifier_issuer_fail_to_load_naming_both() -> Outcome2 {
    let error = party_error(
        r#"
[issuer.i1.party]
identifier_issuer = "urn:example:ferro:login"
identifier_type = "guid"

[issuer.i2.party]
identifier_issuer = "urn:example:ferro:login"
identifier_type = "login"
"#,
    )?;
    assert_eq!(
        PartyError::SharedIdentifierIssuer {
            first: String::from(ISSUER),
            second: String::from("https://as.example.org/realms/other"),
            identifier_issuer: String::from(IDENTIFIERS),
        },
        error
    );
    Ok(())
}

// NOTE: no specification governs the configuration: our own design; a table binds only
// a trusted SMART issuer, and its unknown keys are refused.
#[test]
fn a_table_loads_with_deny_unknown_fields_and_binds_only_a_smart_issuer() -> Outcome2 {
    let unknown = section(&format!(
        "{ISSUERS}
[issuer.i1.party]
identifier_issuer = \"urn:example:ferro:login\"
identifier_type = \"guid\"
match = \"exact\"
"
    ));
    assert!(
        unknown.is_err_and(|error| error.to_string().contains("match")),
        "an unknown key is refused naming it"
    );
    assert!(matches!(
        party_error(
            r#"
[issuer.i3.party]
identifier_issuer = "urn:example:ferro:other"
identifier_type = "login"
"#,
        )?,
        PartyError::NotSmart {
            kind: Some(IssuerKind::Federation),
            ..
        }
    ));
    let resolved = section(&format!(
        "{ISSUERS}
[issuer.i1.party]
identifier_issuer = \"urn:example:ferro:login\"
identifier_type = \"guid\"
group_claim = \"groups\"
group_identifier_issuer = \"urn:example:ferro:groups\"
"
    ))?
    .resolve(&[])?;
    assert_eq!(vec![table()], resolved.party);
    let source: Arc<dyn PartySource> = FakeSource::answering(one_professional());
    let binding = PartyBinding::new(source).with_resolved(&resolved)?;
    assert!(format!("{binding:?}").contains(ISSUER), "{binding:?}");
    Ok(())
}
