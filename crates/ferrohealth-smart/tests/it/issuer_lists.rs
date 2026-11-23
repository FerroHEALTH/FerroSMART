// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! What holds per issuer: `role_claims` sit on each `[auth.issuer.<name>]`
//! table and read that issuer's tokens alone, and a section-level form is
//! refused.

use std::error::Error as StdError;

use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::config::IssuerEntry;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::resource::IssuerSet;
use ferrohealth_smart::resource::Verifier;
use jsonwebtoken::Algorithm;

use crate::support::AUDIENCE;
use crate::support::Issuer;
use crate::support::ec_key;
use crate::support::mint;
use crate::support::server;

const ONE: &str = "https://one.example.org";
const TWO: &str = "https://two.example.org";

/// Returns the `persons` issuer table of `issuer` reading roles from
/// `roles`.
fn entry(issuer: &str, roles: &[&str]) -> IssuerEntry {
    IssuerEntry {
        issuer: ferrohealth_secret::secret_url::SecretUrl::new(issuer),
        kind: Some(IssuerKind::Persons),
        audience: vec![String::from(AUDIENCE)],
        role_claims: Some(roles.iter().map(|&role| role.to_owned()).collect()),
        ..IssuerEntry::default()
    }
}

/// Returns a section trusting `entries`, named `i1` on.
fn section(entries: Vec<IssuerEntry>) -> AuthSection {
    let issuer = entries
        .into_iter()
        .enumerate()
        .map(|(index, entry)| (format!("i{}", index + 1), entry))
        .collect();
    AuthSection {
        issuer,
        ..AuthSection::default()
    }
}

fn owned(values: &[&str]) -> Vec<String> {
    values.iter().map(|&value| value.to_owned()).collect()
}

#[test]
fn each_issuer_receives_only_its_own_entries() -> Result<(), Box<dyn StdError>> {
    let resolved = section(vec![
        entry(ONE, &["realm_access.roles", "roles"]),
        entry(TWO, &["groups"]),
    ])
    .resolve(&[])?;
    assert_eq!(
        owned(&["realm_access.roles", "roles"]),
        resolved.issuers[0].role_claims
    );
    assert_eq!(owned(&["groups"]), resolved.issuers[1].role_claims);
    Ok(())
}

#[test]
fn a_section_level_role_claims_is_refused_at_load() {
    let read = toml::from_str::<AuthSection>(&format!(
        "role_claims = [\"https://one.example.org#roles\"]\n\
         [issuer.i2]\nissuer = \"{ONE}\"\nkind = \"persons\"\naudience = [\"a\"]\n"
    ));
    assert!(read.is_err(), "role_claims is no key of the section");
}

#[test]
fn scopeless_subjects_is_an_unknown_key() {
    let read = toml::from_str::<AuthSection>(&format!(
        "[issuer.one]\nissuer = \"{ONE}\"\nkind = \"persons\"\naudience = [\"a\"]\n\
         scopeless_subjects = [\"svc\"]\n"
    ));
    assert!(
        read.is_err_and(|error| error.to_string().contains("unknown field")),
        "scopeless_subjects is no key of an issuer table"
    );
}

#[test]
fn a_role_claim_path_is_still_checked() {
    assert!(matches!(
        section(vec![entry(ONE, &["realm_access..roles"])]).resolve(&[]),
        Err(ConfigError::Missing {
            key: "auth.issuer.role_claims"
        })
    ));
}

/// The stub issuers of `auth` behind one `IssuerSet`.
async fn trusted(auth: &AuthSection) -> Result<IssuerSet, Box<dyn StdError>> {
    let mut set = IssuerSet::new();
    for settings in auth.resolve(&[])?.issuers {
        set = set.with(server(settings).await);
    }
    Ok(set)
}

#[tokio::test]
async fn roles_are_read_only_from_the_issuer_that_names_the_claim() -> Result<(), Box<dyn StdError>>
{
    let one_key = ec_key("k1", Algorithm::ES256);
    let two_key = ec_key("k2", Algorithm::ES256);
    let one = Issuer::start(&[&one_key]).await;
    let two = Issuer::start(&[&two_key]).await;
    let auth = section(vec![entry(&one.uri(), &["roles"]), entry(&two.uri(), &[])]);
    let set = trusted(&auth).await?;
    let mut one_claims = one.claims("system/Condition.r");
    one_claims["roles"] = serde_json::json!(["ADMIN"]);
    let from_one = set.verify(&mint(&one_key, &one_claims)).await?;
    assert!(from_one.has_role("ADMIN"));
    let mut two_claims = two.claims("system/Condition.r");
    two_claims["roles"] = serde_json::json!(["ADMIN"]);
    two_claims["groups"] = serde_json::json!(["ADMIN"]);
    let from_two = set.verify(&mint(&two_key, &two_claims)).await?;
    assert!(from_two.roles().is_empty(), "{:?}", from_two.roles());
    Ok(())
}
