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
kind = "persons"
preset = "entra"
audience = ["api://ferro"]
jwks_file = "/dev/null"

[issuer.i1.profile]

[issuer.i2]
issuer = "https://as.example.org/realms/other"
kind = "persons"
audience = ["api://ferro"]
jwks_file = "/dev/null"

[issuer.i3]
issuer = "https://as.example.org/realms/machines"
kind = "machines"
audience = ["api://ferro"]
jwks_file = "/dev/null"
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

// NOTE: OpenID Connect Core 1.0 §5.7: `email`, `phone_number`, `preferred_username` and
// `name` "MUST NOT be used as unique identifiers for the End-User".
#[test]
fn a_banned_claim_as_key_fails_to_load() -> Outcome2 {
    let banned = ISSUERS.replacen(
        "[issuer.i1.profile]\n",
        "[issuer.i1.profile]\nperson_key = \"email\"\n",
        1,
    );
    let text = format!(
        "{banned}
[issuer.i1.party]
identifier_issuer = \"urn:example:ferro:login\"
identifier_type = \"guid\"
"
    );
    assert!(
        matches!(
            section(&text)?.resolve(&[]),
            Err(ConfigError::Issuer { .. })
        ),
        "the profile refuses the key at load"
    );
    let source: Arc<dyn PartySource> = FakeSource::answering(one_professional());
    let unstable = Profile {
        person_key: String::from("preferred_username"),
        ..profile()
    };
    assert_eq!(
        Err(PartyError::UnstableKey {
            issuer: String::from(ISSUER),
            claim: String::from("preferred_username"),
        }),
        PartyBinding::new(source)
            .with_issuer(table(), IssuerKind::Persons, &unstable)
            .map(|_binding| ())
    );
    Ok(())
}

// NOTE: no specification governs the configuration: our own design; a table binds only
// a trusted persons issuer, and its unknown keys are refused.
#[test]
fn a_table_loads_with_deny_unknown_fields_and_binds_only_a_persons_issuer() -> Outcome2 {
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
identifier_issuer = "urn:example:ferro:machines"
identifier_type = "login"
"#,
        )?,
        PartyError::NotPersons {
            kind: Some(IssuerKind::Machines),
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

/// The `[auth.idp.entra]` table of the configuration cases, with `base_url`.
#[cfg(feature = "idp-entra")]
fn entra_table(base_url: &str) -> String {
    format!(
        "
[idp.entra]
base_url = \"{base_url}\"
[idp.entra.credentials]
token_endpoint = \"https://login.example.org/tenant-1/oauth2/v2.0/token\"
client_id = \"synthetic-graph-reader\"
client_secret = \"synthetic-graph-secret\"
"
    )
}

#[cfg(feature = "idp-entra")]
#[test]
fn the_idp_entra_table_builds_its_adapter_and_the_binding_registers_it() -> Outcome2 {
    let resolved = section(&format!(
        "{ISSUERS}{}",
        entra_table("https://graph.microsoft.com/v1.0")
    ))?
    .resolve(&[])?;
    let names: Vec<&str> = resolved.adapters.iter().map(|(name, _)| name).collect();
    assert_eq!(vec![ferrohealth_smart::idp::entra::NAME], names);
    let source: Arc<dyn PartySource> = FakeSource::answering(one_professional());
    let binding = PartyBinding::new(source)
        .with_resolved(&resolved)?
        .with_issuer(
            table(),
            IssuerKind::Persons,
            &Profile {
                adapter: Some(String::from(ferrohealth_smart::idp::entra::NAME)),
                ..profile()
            },
        )?;
    assert!(format!("{binding:?}").contains("idp-entra"), "{binding:?}");
    Ok(())
}

#[cfg(feature = "idp-entra")]
#[test]
fn an_idp_entra_table_breaking_a_rule_is_refused_naming_the_adapter() -> Outcome2 {
    let refused = section(&format!(
        "{ISSUERS}{}",
        entra_table("http://graph.example.org")
    ))?
    .resolve(&[])
    .expect_err("an http Graph root is refused");
    assert!(
        matches!(
            refused,
            ConfigError::Adapter {
                adapter: "idp-entra",
                ..
            }
        ),
        "{refused:?}"
    );
    Ok(())
}

#[cfg(feature = "idp-entra")]
#[test]
fn an_unknown_key_of_the_idp_tables_is_refused() {
    for unknown in [
        format!(
            "{}colour = \"blue\"\n",
            entra_table("https://graph.microsoft.com/v1.0")
        ),
        String::from("\n[idp.okta]\nbase_url = \"https://okta.example.org\"\n"),
    ] {
        assert!(
            section(&format!("{ISSUERS}{unknown}")).is_err(),
            "{unknown:?} was read"
        );
    }
}

#[test]
fn without_an_idp_table_no_adapter_is_built() -> Outcome2 {
    let resolved = section(ISSUERS)?.resolve(&[])?;
    assert!(resolved.adapters.is_empty(), "{:?}", resolved.adapters);
    Ok(())
}

#[cfg(not(feature = "idp-entra"))]
#[test]
fn a_build_without_the_entra_adapter_refuses_its_table() {
    assert!(
        section(&format!(
            "{ISSUERS}\n[idp.entra]\nbase_url = \"https://graph.microsoft.com/v1.0\"\n"
        ))
        .is_err(),
        "a table for an adapter the build lacks was read"
    );
}
