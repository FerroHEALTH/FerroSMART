// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! HTTP Basic end to end: the credential one side sends is the one the
//! other side verifies, a verified user carries the scopes and roles the
//! product grants it, and a refused credential is one outcome.

use std::error::Error as StdError;

use argon2::Argon2;
use argon2::password_hash::PasswordHasher;
use ferrohealth_smart::basic::Credential;
use ferrohealth_smart::basic::InvalidCredential;
use ferrohealth_smart::basic::PasswordStore;
use ferrohealth_smart::basic::StoreError;
use ferrohealth_smart::basic::Verified;
use ferrohealth_smart::config::BasicGrant;
use ferrohealth_smart::config::BasicGrants;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::resource::Caller;
use ferrohealth_smart::scope::Permission;
use ferrohealth_smart::scope::Reach;
use secrecy::SecretString;

/// Returns the Argon2id PHC string of `password` under a fixed salt.
fn hash(password: &str) -> SecretString {
    SecretString::from(
        Argon2::default()
            .hash_password_with_salt(password.as_bytes(), b"synthetic-salt-16")
            .expect("the hash")
            .to_string(),
    )
}

#[test]
fn the_sent_credential_verifies_against_the_store() -> Result<(), Box<dyn StdError>> {
    let store = PasswordStore::new()
        .with_user("ferro-bridge", hash("synthetic-pw"))?
        .with_scope("ferro-bridge", "user/*.rs")?
        .with_user("ferro-fed", hash("another-pw"))?;
    let sent = Credential::new("ferro-bridge", SecretString::from("synthetic-pw"))?;
    assert_eq!(
        Ok(Verified {
            username: String::from("ferro-bridge"),
            scope: String::from("user/*.rs"),
            roles: Vec::new(),
            cached: false,
        }),
        store.verify(&sent.header_value())
    );
    let wrong = Credential::new("ferro-bridge", SecretString::from("another-pw"))?;
    assert_eq!(Err(InvalidCredential), store.verify(&wrong.header_value()));
    let unknown = Credential::new("ferro-term", SecretString::from("synthetic-pw"))?;
    assert_eq!(
        Err(InvalidCredential),
        store.verify(&unknown.header_value())
    );
    assert_eq!(2, store.len());
    Ok(())
}

#[test]
fn a_verified_user_carries_its_configured_roles() -> Result<(), Box<dyn StdError>> {
    // A password made when the case runs, so no credential is written down.
    let password = format!("pw-{}", std::process::id());
    let store = PasswordStore::new()
        .with_user("ferro-bridge", hash(&password))?
        .with_roles(
            "ferro-bridge",
            vec![String::from("etl"), String::from("reader")],
        )?;
    let sent = Credential::new("ferro-bridge", SecretString::from(password))?;
    let verified = store.verify(&sent.header_value())?;
    assert_eq!(verified.roles, ["etl", "reader"]);
    assert!(matches!(
        PasswordStore::new().with_roles("nobody", vec![String::from("etl")]),
        Err(StoreError::UnknownUser { .. })
    ));
    Ok(())
}

#[test]
fn a_bearer_value_is_no_basic_credential() -> Result<(), Box<dyn StdError>> {
    let store = PasswordStore::new().with_user("ferro-bridge", hash("synthetic-pw"))?;
    let bearer = http::HeaderValue::from_static("Bearer ZmVycm8tYnJpZGdlOnN5bnRoZXRpYy1wdw==");
    assert_eq!(Err(InvalidCredential), store.verify(&bearer));
    let bare = http::HeaderValue::from_static("Basic");
    assert_eq!(Err(InvalidCredential), store.verify(&bare));
    Ok(())
}

// NOTE: a Basic credential is a person's, never a system caller's (owner ruling on #215), and a
// `system/` scope is a backend service's grant (SMART App Launch 2.2.0, Scopes and Launch Context).
#[test]
fn a_store_refuses_a_system_scope_naming_the_user_and_the_scope() {
    // A password made when the case runs, so no credential is written down.
    let password = format!("pw-{}", std::process::id());
    for scope in [
        "system/*.rs",
        "user/Condition.r system/Condition.c",
        "system/composition-*.r",
    ] {
        let refused = PasswordStore::new()
            .with_user("batch-loader", hash(&password))
            .and_then(|store| store.with_scope("batch-loader", scope));
        let Err(StoreError::SystemScope {
            username,
            scope: named,
        }) = refused
        else {
            panic!("{scope}: a system scope, not {refused:?}");
        };
        assert_eq!("batch-loader", username, "{scope}");
        assert!(named.starts_with("system/"), "{scope}: {named}");
    }
}

#[test]
fn a_store_grants_each_user_of_the_product_table() -> Result<(), Box<dyn StdError>> {
    // A password made when the case runs, so no credential is written down.
    let password = format!("pw-{}", std::process::id());
    let grants = BasicGrants {
        users: [(
            String::from("ferro-bridge"),
            BasicGrant {
                scopes: vec![String::from("user/*.rs"), String::from("__ops")],
                roles: vec![String::from("etl")],
            },
        )]
        .into(),
    };
    let store = PasswordStore::new()
        .with_user("ferro-bridge", hash(&password))?
        .with_user("ferro-fed", hash(&password))?
        .with_grants(&grants)?;
    let granted = Credential::new("ferro-bridge", SecretString::from(password.clone()))?;
    let verified = store.verify(&granted.header_value())?;
    assert_eq!("user/*.rs __ops", verified.scope);
    assert_eq!(verified.roles, ["etl"]);
    let bare = Credential::new("ferro-fed", SecretString::from(password))?;
    let verified = store.verify(&bare.header_value())?;
    assert_eq!(
        "", verified.scope,
        "a user the table does not name is granted nothing"
    );
    assert_eq!(Vec::<String>::new(), verified.roles);
    Ok(())
}

#[test]
fn a_scope_granted_to_a_verified_caller_reaches_every_scope_reader() {
    let caller = Caller::basic(String::from("clinician"), "user/Patient.r")
        .with_granted_scope(["user/Condition.rs __ops", "user/Patient.r"])
        .with_granted_scope(vec![String::from("openid")]);
    assert_eq!(
        caller.scope(),
        ["user/Patient.r", "user/Condition.rs", "__ops", "openid"],
        "each token once, in the order granted"
    );
    assert!(caller.has_scope("__ops"));
    assert!(caller.has_scope("openid"));
    assert_eq!(
        Some(Reach::Any),
        caller.scopes().reach(Permission::Search, "Condition")
    );
    assert_eq!(
        Some(Reach::Any),
        caller.scopes().reach(Permission::Read, "Patient")
    );
    assert_eq!(None, caller.scopes().reach(Permission::Create, "Condition"));
}

#[cfg(feature = "openehr")]
#[test]
fn a_granted_openehr_scope_is_read_under_the_openehr_grammar() {
    use ferrohealth_smart::openehr::smart_scopes::SmartScope;

    let caller =
        Caller::basic(String::from("clinician"), "").with_granted_scope(["user/composition-*.cr"]);
    assert_eq!(
        vec![SmartScope::parse("user/composition-*.cr")],
        caller.openehr_scopes()
    );
    assert!(matches!(
        caller.openehr_scopes().first(),
        Some(SmartScope::Resource(_))
    ));
}

// NOTE: a Basic credential is a person's (owner ruling on #215), so a granted `system/` scope
// reaches it no more than a configured one (SMART App Launch 2.2.0, Scopes and Launch Context).
#[test]
fn a_basic_caller_is_granted_no_system_scope() {
    let caller = Caller::basic(String::from("batch-loader"), "")
        .with_granted_scope(["system/*.rs user/Condition.r", "system/composition-*.r"]);
    assert_eq!(caller.scope(), ["user/Condition.r"]);
    assert!(!caller.has_scope("system/*.rs"));
    assert_eq!(None, caller.scopes().reach(Permission::Search, "Condition"));
    let system = Caller::new(
        String::from("svc"),
        Some(String::from("svc")),
        "",
        None,
        CallerKind::System,
    )
    .with_granted_scope(["system/Condition.r"]);
    assert_eq!(
        Some(Reach::Any),
        system.scopes().reach(Permission::Read, "Condition"),
        "a bearer caller keeps a granted system scope"
    );
}

#[test]
fn roles_granted_to_a_verified_caller_join_its_own_once() {
    let caller = Caller::basic(String::from("clinician"), "")
        .with_roles(vec![String::from("Clinician")])
        .with_granted_roles(["Clinician", " auditor ", "admin reader", ""])
        .with_granted_roles(vec![String::from("auditor")]);
    assert_eq!(caller.roles(), ["Clinician", "auditor", "admin", "reader"]);
    assert!(caller.has_role("ADMIN"));
    assert!(caller.has_role("reader"));
}
