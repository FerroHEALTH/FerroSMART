// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `[auth]` schema of the caller classification: every issuer a
//! `[auth.issuer.<name>]` table with a required `kind` and its own settings, the
//! profile a preset with keys set over it, and every removed key refused
//! naming its replacement.

use std::error::Error as StdError;

use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::profile::Marker;
use ferrohealth_smart::profile::ScopeForm;

type Outcome = Result<(), Box<dyn StdError>>;

/// An issuer table of `kind` with `extra` keys.
fn issuer(kind: &str, extra: &str) -> String {
    format!(
        "[issuer.i2]\nissuer = \"https://as.example.org\"\nkind = \"{kind}\"\naudience = [\"a\"]\n{extra}\n"
    )
}

/// An issuer table of `kind` with `extra` keys and the profile keys `keys`.
fn profiled(kind: &str, extra: &str, keys: &str) -> String {
    format!("{}[issuer.i2.profile]\n{keys}\n", issuer(kind, extra))
}

/// Returns the section `text` reads to.
fn section(text: &str) -> AuthSection {
    toml::from_str(text).expect("the section parses")
}

#[test]
fn an_issuer_without_kind_fails_to_load() {
    let refused = section("[issuer.i3]\nissuer = \"https://as.example.org\"\naudience = [\"a\"]\n")
        .resolve(&[]);
    assert!(
        matches!(
            refused,
            Err(ConfigError::Missing {
                key: "auth.issuer.kind"
            })
        ),
        "{refused:?}"
    );
}

#[test]
fn every_retired_key_and_form_is_an_unknown_key_at_load() {
    let persons = issuer("persons", "");
    let mut retired = vec![
        String::from("issuer = \"https://as.example.org\""),
        format!(
            "scopeless_subjects = [\"https://as.example.org#svc\"]\n{}",
            issuer("machines", "")
        ),
        issuer("persons", "token_profile = \"rfc9068\""),
        issuer("persons", "acting_for_claim = \"act.sub\""),
        issuer("persons", "client_tokens = \"claim_absent\""),
        issuer("machines", "scopeless_subjects = [\"svc\"]"),
        profiled("persons", "", "first_party_clients = [\"portal\"]"),
        profiled("persons", "", "delegates = [{ client = \"app\" }]"),
        profiled(
            "persons",
            "preset = \"ferrosmart\"",
            "audience_delegates = true",
        ),
    ];
    for key in [
        "audience = [\"a\"]",
        "algorithms = [\"ES256\"]",
        "clock_skew_seconds = 30",
        "jwks_max_age_seconds = 60",
        "jwks_refresh_interval_seconds = 60",
        "jwks_file = \"/keys.json\"",
        "timeout_ms = 500",
        "mode = \"jwt\"",
        "role_claims = []",
        "token_profile = \"jwt\"",
        "acting_for_claim = \"act.sub\"",
        "client_tokens = \"sub_is_client\"",
        "ca_file = \"/etc/ca.pem\"",
    ] {
        retired.push(format!("{key}\n{persons}"));
    }
    for text in retired {
        assert!(
            toml::from_str::<AuthSection>(&text).is_err(),
            "{text} is no key or form of the section"
        );
    }
}

// NOTE: OpenID Connect Core 1.0 §5.7: "email, phone_number, preferred_username,
// and name MUST NOT be used as unique identifiers for the End-User".
#[test]
fn a_banned_key_fails_to_load() {
    for text in [
        profiled("persons", "", "person_key = \"email\""),
        profiled("persons", "", "person_key = \"preferred_username\""),
        profiled("persons", "", "client_claims = [\"name\"]"),
        profiled("persons", "preset = \"entra\"", "person_key = \"upn\""),
        profiled(
            "persons",
            "",
            "person_key = \"login\"\nunstable_claims = [\"login\"]",
        ),
    ] {
        let refused = section(&text).resolve(&[]);
        assert!(
            matches!(refused, Err(ConfigError::Issuer { .. })),
            "{text}: {refused:?}"
        );
    }
}

#[test]
fn a_federation_issuer_without_its_table_fails_to_load() {
    let refused = section(&issuer("federation", "")).resolve(&[]);
    assert!(
        matches!(refused, Err(ConfigError::Federation { .. })),
        "{refused:?}"
    );
}

#[test]
fn a_preset_is_selected_and_every_key_is_set_over_it() -> Outcome {
    let resolved = section(&profiled(
        "persons",
        "preset = \"entra\"",
        r#"person_key = "sub"
client_claims = ["appid", "azp"]
guest = [{ claim = "acct", value = "1" }]
scope_claim = { claim = "scp", form = "array" }"#,
    ))
    .resolve(&[])?;
    let profile = &resolved.issuers.first().ok_or("one issuer")?.profile;
    assert_eq!("sub", profile.person_key, "the issuer's key wins");
    assert_eq!(
        Some(String::from("tid")),
        profile.tenant_claim,
        "the preset's stays"
    );
    assert_eq!(
        vec![String::from("appid"), String::from("azp")],
        profile.client_claims
    );
    assert_eq!(
        vec![Marker::Claim {
            claim: String::from("acct"),
            value: String::from("1")
        }],
        profile.guest
    );
    assert_eq!(ScopeForm::Array, profile.scope_claim.form);
    assert_eq!(vec![String::from("JWT")], profile.token_types);
    Ok(())
}

#[test]
fn the_okta_and_keycloak_presets_fail_to_load_until_the_deployment_sets_their_gaps() {
    for text in [
        issuer("persons", "preset = \"okta\""),
        issuer("machines", "preset = \"keycloak\""),
    ] {
        assert!(
            matches!(section(&text).resolve(&[]), Err(ConfigError::Issuer { .. })),
            "{text}"
        );
    }
    assert!(
        section(&profiled(
            "persons",
            "preset = \"okta\"",
            "token_types = [\"JWT\"]"
        ))
        .resolve(&[])
        .is_ok(),
        "okta with its token types"
    );
    assert!(
        section(&profiled(
            "machines",
            "preset = \"keycloak\"",
            "app_only = [{ subjects = [\"service-account-sub\"] }]"
        ))
        .resolve(&[])
        .is_ok(),
        "keycloak with its service accounts"
    );
}

// NOTE: no specification governs adapters: our own design, in which a profile naming an
// adapter whose feature this build leaves out fails to load.
#[cfg(not(feature = "idp-entra"))]
#[test]
fn an_adapter_whose_feature_is_not_compiled_in_fails_to_load() {
    let refused = section(&profiled(
        "persons",
        "preset = \"entra\"",
        "adapter = \"idp-entra\"",
    ))
    .resolve(&[]);
    assert!(
        matches!(refused, Err(ConfigError::Issuer { .. })),
        "{refused:?}"
    );
}

// NOTE: no specification governs adapters: our own design, in which the compiled adapter
// loads and a name no feature compiles in fails in every build.
#[test]
fn only_a_compiled_adapter_loads() {
    let unknown = section(&profiled(
        "persons",
        "preset = \"entra\"",
        "adapter = \"idp-unknown\"",
    ))
    .resolve(&[]);
    assert!(
        matches!(unknown, Err(ConfigError::Issuer { .. })),
        "{unknown:?}"
    );
    let compiled = section(&profiled(
        "persons",
        "preset = \"entra\"",
        "adapter = \"idp-entra\"",
    ))
    .resolve(&[]);
    assert_eq!(
        cfg!(feature = "idp-entra"),
        compiled.is_ok(),
        "{compiled:?}"
    );
}

#[test]
fn a_marker_in_two_forms_fails_to_parse() {
    let extra = "app_only = [{ absent_claim = \"uid\", sub_is_client = true }]";
    assert!(
        toml::from_str::<AuthSection>(&profiled("persons", "", extra)).is_err(),
        "{extra}"
    );
}

#[test]
fn a_product_role_list_names_persons_issuers_only() -> Outcome {
    let resolved = section(&format!(
        "{}{}",
        issuer("persons", ""),
        "[issuer.machines]\nissuer = \"https://machines.example.org\"\nkind = \"machines\"\naudience = [\"a\"]\n"
    ))
    .resolve(&[])?;
    assert_eq!(
        vec![String::from("https://as.example.org")],
        resolved.role_issuers("authz.admin_issuers", &[String::from("i2")])?,
        "a name reads as its issuer's identifier"
    );
    let refused = resolved.role_issuers("authz.admin_issuers", &[String::from("machines")]);
    assert!(
        matches!(
            &refused,
            Err(ConfigError::RoleIssuer {
                kind: IssuerKind::Machines,
                ..
            })
        ),
        "{refused:?}"
    );
    Ok(())
}

// NOTE: no specification governs the configuration model: our own design (#730),
// a key that names an issuer by an unknown name is refused, listing the known ones.
#[test]
fn an_unknown_issuer_name_is_refused_listing_the_known_names() -> Outcome {
    let resolved = section(&issuer("persons", "")).resolve(&[])?;
    let refused = resolved
        .role_issuers("authz.admin_issuers", &[String::from("other")])
        .expect_err("an unknown name");
    let ConfigError::UnknownIssuer { key, name, known } = &refused else {
        panic!("an unknown issuer, got {refused:?}");
    };
    assert_eq!("authz.admin_issuers", *key);
    assert_eq!("other", name);
    assert_eq!(&vec![String::from("i2")], known);
    assert!(refused.to_string().contains("\"i2\""), "{refused}");
    let described = section(&format!(
        "described_issuer = \"nope\"\n{}",
        issuer("persons", "")
    ))
    .resolve(&[]);
    assert!(
        matches!(
            described,
            Err(ConfigError::UnknownIssuer {
                key: "auth.described_issuer",
                ..
            })
        ),
        "described_issuer names an issuer by its name"
    );
    Ok(())
}

// NOTE: no specification governs the configuration model: our own design (#730),
// a name addressable from the environment.
#[test]
fn an_issuer_name_outside_the_name_form_is_refused() {
    for name in ["Smart", "1st", "a-b", "\"a.b\"", "\"\""] {
        let text = format!(
            "[issuer.{name}]\nissuer = \"https://as.example.org\"\nkind = \"persons\"\naudience = [\"a\"]\n"
        );
        let refused = section(&text).resolve(&[]);
        assert!(
            matches!(refused, Err(ConfigError::IssuerName { .. })),
            "{name}: {refused:?}"
        );
    }
    assert!(
        section(&issuer("persons", "").replace("i2", "smart_2"))
            .resolve(&[])
            .is_ok()
    );
}

#[test]
fn a_federation_issuer_contributes_no_role_by_default() {
    let settings = ferrohealth_smart::resource::Settings::new(
        "https://fed.example.org",
        "a",
        IssuerKind::Federation,
    );
    assert!(settings.role_claims.is_empty(), "no role claim");
    let mut refused = settings;
    refused.role_claims = vec![String::from("roles")];
    assert!(
        refused.validate().is_err(),
        "a role claim on a federation issuer"
    );
}

#[cfg(feature = "fetch")]
#[test]
fn one_jwt_issuer_and_one_introspection_issuer_load_together() -> Outcome {
    let resolved = section(&format!(
        "{}{}",
        issuer("persons", ""),
        r#"[issuer.i5]
issuer = "https://introspected.example.org"
kind = "machines"
audience = ["a"]
mode = "introspection"
[issuer.i5.introspection.client]
client_id = "ferro-rs"
client_secret = "synthetic-secret"
"#
    ))
    .resolve(&[])?;
    assert_eq!(1, resolved.issuers.len(), "the JWT issuer");
    assert_eq!(1, resolved.introspection.len(), "the introspection issuer");
    assert_eq!(
        Some(IssuerKind::Machines),
        resolved.introspection.first().map(|settings| settings.kind)
    );
    Ok(())
}
