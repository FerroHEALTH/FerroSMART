// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The roles a caller holds: read from the claims RFC 9068 §2.2.3.1 names,
//! or from the paths a deployment configures, and granted to a Basic user by
//! the product.

use std::error::Error as StdError;

use ferrohealth_smart::basic::StoreError;
use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::BasicGrant;
use ferrohealth_smart::config::BasicGrants;
use ferrohealth_smart::config::BasicSection;
use ferrohealth_smart::config::BasicUser;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::config::IssuerEntry;
use ferrohealth_smart::kind::IssuerKind;
use jsonwebtoken::Algorithm;
use secrecy::SecretString;

use crate::support::Issuer;
use crate::support::ec_key;
use crate::support::mint;
use crate::support::server;

#[tokio::test]
async fn a_token_carries_the_roles_of_the_default_claims() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let server = server(issuer.settings()).await;
    let mut claims = issuer.claims("system/Condition.r");
    claims["roles"] = serde_json::json!(["Clinician", "admin"]);
    claims["groups"] = serde_json::json!(["admin", "ward-3"]);
    claims["entitlements"] = serde_json::json!("export");
    let caller = server.authenticate(&mint(&key, &claims)).await?;
    assert_eq!(caller.roles(), ["Clinician", "admin", "ward-3", "export"]);
    assert!(caller.has_role("CLINICIAN"));
    assert!(!caller.has_role("auditor"));
    Ok(())
}

#[tokio::test]
async fn configured_paths_replace_the_default_claims() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let mut settings = issuer.settings();
    settings.role_claims = vec![String::from("realm_access.roles")];
    let server = server(settings).await;
    let mut claims = issuer.claims("system/Condition.r");
    claims["roles"] = serde_json::json!(["ignored"]);
    claims["realm_access"] = serde_json::json!({ "roles": ["auditor"] });
    let caller = server.authenticate(&mint(&key, &claims)).await?;
    assert_eq!(caller.roles(), ["auditor"]);
    Ok(())
}

#[tokio::test]
async fn a_token_without_role_claims_holds_no_role() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let server = server(issuer.settings()).await;
    let caller = server
        .authenticate(&mint(&key, &issuer.claims("system/Condition.r")))
        .await?;
    assert!(caller.roles().is_empty(), "{:?}", caller.roles());
    Ok(())
}

/// A synthetic Argon2id hash at the OWASP floor, of no real password.
const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c3ludGhldGljLXNhbHQtMTY$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn section() -> AuthSection {
    AuthSection {
        basic: Some(BasicSection {
            users: vec![BasicUser {
                user: String::from("etl"),
                password_hash: Some(SecretString::from(HASH)),
                ..BasicUser::default()
            }],
            ..BasicSection::default()
        }),
        ..AuthSection::default()
    }
}

#[test]
fn a_basic_user_role_must_be_one_word() -> Result<(), Box<dyn StdError>> {
    let grants = BasicGrants {
        users: [(
            String::from("etl"),
            BasicGrant {
                roles: vec![String::from("two words")],
                ..BasicGrant::default()
            },
        )]
        .into(),
    };
    let store = section().resolve(&[])?.basic.ok_or("a Basic store")?;
    assert!(matches!(
        store.with_grants(&grants),
        Err(StoreError::Role { username, role }) if username == "etl" && role == "two words"
    ));
    Ok(())
}

#[test]
fn a_blank_role_claim_path_is_refused() {
    let mut auth = section();
    auth.issuer = std::collections::BTreeMap::from([(
        String::from("i1"),
        IssuerEntry {
            issuer: ferrohealth_secret::secret_url::SecretUrl::new("https://as.example.org"),
            kind: Some(IssuerKind::Smart),
            audience: vec![String::from("a")],
            role_claims: Some(vec![String::from("realm_access..roles")]),
            ..IssuerEntry::default()
        },
    )]);
    assert!(matches!(
        auth.resolve(&[]),
        Err(ConfigError::Missing {
            key: "auth.issuer.role_claims"
        })
    ));
}
