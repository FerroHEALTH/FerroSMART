// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The configuration sections compare by value, a secret included, so a
//! product can diff a reloaded configuration against the running one, and
//! the comparison renders no secret.

use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::BasicSection;
use ferrohealth_smart::config::BasicUser;
use ferrohealth_smart::config::IntrospectionSection;
use ferrohealth_smart::config::IssuerEntry;
use ferrohealth_smart::config::credentials::CredentialsSection;
use ferrohealth_smart::config::credentials::OauthSection;
use ferrohealth_smart::config::endpoint::EndpointSection;

/// A client credentials table with the client secret `secret`.
fn oauth(secret: &str, scope: &str) -> OauthSection {
    toml::from_str(&format!(
        "token_endpoint = \"https://as.example.org/token\"\n\
         client_id = \"synthetic-client\"\n\
         client_secret = \"{secret}\"\n\
         scope = \"{scope}\"\n\
         timeout = \"5s\""
    ))
    .expect("parses")
}

/// Holds only for a type that implements `Eq`.
fn is_eq<T: Eq>() {}

#[test]
fn every_section_implements_eq() {
    is_eq::<AuthSection>();
    is_eq::<IssuerEntry>();
    is_eq::<IntrospectionSection>();
    is_eq::<BasicSection>();
    is_eq::<BasicUser>();
    is_eq::<CredentialsSection>();
    is_eq::<OauthSection>();
    is_eq::<EndpointSection>();
}

#[test]
fn oauth_sections_with_the_same_values_are_equal() {
    assert_eq!(
        oauth("synthetic-secret", "system/*.rs"),
        oauth("synthetic-secret", "system/*.rs")
    );
    assert_eq!(OauthSection::default(), OauthSection::default());
}

#[test]
fn oauth_sections_differ_by_their_secret_value() {
    let running = oauth("synthetic-secret", "system/*.rs");
    let reloaded = oauth("synthetic-rotated", "system/*.rs");
    assert_ne!(running, reloaded);
    let rendered = format!("{running:?} {reloaded:?}");
    assert!(!rendered.contains("synthetic-secret"), "{rendered}");
    assert!(!rendered.contains("synthetic-rotated"), "{rendered}");
}

#[test]
fn oauth_sections_differ_by_a_set_and_an_unset_secret() {
    let unset = OauthSection {
        client_secret: None,
        ..oauth("synthetic-secret", "system/*.rs")
    };
    assert_ne!(oauth("synthetic-secret", "system/*.rs"), unset);
    assert_ne!(unset, oauth("synthetic-secret", "system/*.rs"));
}

#[test]
fn oauth_sections_differ_by_a_plain_field() {
    assert_ne!(
        oauth("synthetic-secret", "system/*.rs"),
        oauth("synthetic-secret", "system/*.r")
    );
    let longer = OauthSection {
        timeout: "6s".parse().expect("a duration"),
        ..oauth("synthetic-secret", "system/*.rs")
    };
    assert_ne!(oauth("synthetic-secret", "system/*.rs"), longer);
}

#[test]
fn credentials_sections_compare_the_password_by_value() {
    let basic = |password: &str| -> CredentialsSection {
        toml::from_str(&format!("user = \"bridge\"\npassword = \"{password}\"")).expect("parses")
    };
    assert_eq!(basic("synthetic-one"), basic("synthetic-one"));
    assert_ne!(basic("synthetic-one"), basic("synthetic-two"));
    let granted = |secret: &str| CredentialsSection {
        oauth: Some(oauth(secret, "system/*.rs")),
        ..CredentialsSection::default()
    };
    assert_eq!(granted("synthetic-one"), granted("synthetic-one"));
    assert_ne!(granted("synthetic-one"), granted("synthetic-two"));
}

#[test]
fn basic_users_compare_the_hash_by_value() {
    let user = |hash: &str| BasicUser {
        user: String::from("clinician"),
        password_hash: Some(hash.into()),
        ..BasicUser::default()
    };
    assert_eq!(
        user("$argon2id$synthetic-one"),
        user("$argon2id$synthetic-one")
    );
    assert_ne!(
        user("$argon2id$synthetic-one"),
        user("$argon2id$synthetic-two")
    );
}

#[test]
fn auth_sections_compare_their_tables() {
    let section = |audience: &str| -> AuthSection {
        toml::from_str(&format!(
            "[issuer.i1]\n\
             issuer = \"https://as.example.org\"\n\
             \
             audience = [\"{audience}\"]\n\
             [basic]\n\
             [[basic.users]]\n\
             user = \"clinician\"\n\
             password_hash = \"$argon2id$synthetic\""
        ))
        .expect("parses")
    };
    assert_eq!(
        section("https://fhir.example.org"),
        section("https://fhir.example.org")
    );
    assert_ne!(
        section("https://fhir.example.org"),
        section("https://ehr.example.org")
    );
}
