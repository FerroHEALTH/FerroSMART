// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `[auth]` schema of the caller model: every issuer a
//! `[auth.issuer.<name>]` table, a SMART authorization server unless it
//! declares `kind = "federation"`, with its own settings, and every removed
//! key refused as an unknown key.

use std::error::Error as StdError;

use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::kind::IssuerKind;

type Outcome = Result<(), Box<dyn StdError>>;

/// A SMART issuer table with `extra` keys.
fn issuer(extra: &str) -> String {
    format!("[issuer.i2]\nissuer = \"https://as.example.org\"\naudience = [\"a\"]\n{extra}\n")
}

/// A SMART issuer table with `extra` keys and the profile keys `keys`.
fn profiled(extra: &str, keys: &str) -> String {
    format!("{}[issuer.i2.profile]\n{keys}\n", issuer(extra))
}

/// A federation issuer table named `name`.
fn federation(name: &str) -> String {
    format!(
        "[issuer.{name}]\nissuer = \"https://{name}.example.org\"\nkind = \"federation\"\n\
         audience = [\"a\"]\n[issuer.{name}.federation]\ncontact_point = false\n\
         countries = [\"NL\"]\nissuing_authorities = [\"CIBG\"]\n\
         provider_identifier_prefixes = [\"urn:oid:2.16.528.1.1007.3.3.\"]\n"
    )
}

/// Returns the section `text` reads to.
fn section(text: &str) -> AuthSection {
    toml::from_str(text).expect("the section parses")
}

#[test]
fn an_issuer_without_kind_is_a_smart_issuer() -> Outcome {
    let resolved = section(&issuer("")).resolve(&[])?;
    assert_eq!(
        Some(&IssuerKind::Smart),
        resolved.kinds.get("https://as.example.org")
    );
    Ok(())
}

#[test]
fn every_retired_key_and_form_is_an_unknown_key_at_load() {
    let smart = issuer("");
    let mut retired = vec![
        String::from("issuer = \"https://as.example.org\""),
        format!("scopeless_subjects = [\"https://as.example.org#svc\"]\n{smart}"),
        issuer("token_profile = \"rfc9068\""),
        issuer("acting_for_claim = \"act.sub\""),
        issuer("client_tokens = \"claim_absent\""),
        issuer("scopeless_subjects = [\"svc\"]"),
        issuer("preset = \"ferrosmart\""),
        issuer("profile_file = \"/etc/ferro/profile.toml\""),
        issuer("kind = \"persons\""),
        issuer("kind = \"patients\""),
        issuer("kind = \"machines\""),
        issuer("kind = \"smart\""),
        format!("{smart}[idp.entra]\nbase_url = \"https://graph.microsoft.com/v1.0\"\n"),
    ];
    for key in [
        "first_party_clients = [\"portal\"]",
        "delegates = [{ client = \"app\" }]",
        "audience_delegates = true",
        "issuer_client_is_person = true",
        "person_key = \"sub\"",
        "tenant_claim = \"tid\"",
        "client_claims = [\"azp\"]",
        "app_only = [{ sub_is_client = true }]",
        "guest = [{ claim = \"acct\", value = \"1\" }]",
        "impersonation_marker = \"impersonator\"",
        "expect = { ver = \"2.0\" }",
        "user_claims = [\"oid\"]",
        "person_equality = [\"iss\", \"sub\"]",
        "unstable_claims = [\"upn\"]",
        "representation = { claim = \"represents\" }",
        "act_represents_patient = true",
        "fhir_user_patient = true",
        "patient_context = true",
        "party_identifier_type = \"pairwise\"",
        "scope_claim = { claim = \"scp\", form = \"array\" }",
        "app_only_scope_claim = { claim = \"roles\", form = \"array\" }",
        "adapter = \"idp-entra\"",
    ] {
        retired.push(profiled("", key));
    }
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
        retired.push(format!("{key}\n{smart}"));
    }
    for text in retired {
        assert!(
            toml::from_str::<AuthSection>(&text).is_err(),
            "{text} is no key or form of the section"
        );
    }
}

#[test]
fn a_product_role_list_names_smart_issuers_only() -> Outcome {
    let resolved = section(&format!("{}{}", issuer(""), federation("other"))).resolve(&[])?;
    assert_eq!(
        vec![String::from("https://as.example.org")],
        resolved.role_issuers("authz.admin_issuers", &[String::from("i2")])?,
        "a name reads as its issuer's identifier"
    );
    let refused = resolved.role_issuers("authz.admin_issuers", &[String::from("other")]);
    assert!(
        matches!(
            &refused,
            Err(ConfigError::RoleIssuer {
                kind: IssuerKind::Federation,
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
    let resolved = section(&issuer("")).resolve(&[])?;
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
    let described = section(&format!("described_issuer = \"nope\"\n{}", issuer(""))).resolve(&[]);
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
        let text =
            format!("[issuer.{name}]\nissuer = \"https://as.example.org\"\naudience = [\"a\"]\n");
        let refused = section(&text).resolve(&[]);
        assert!(
            matches!(refused, Err(ConfigError::IssuerName { .. })),
            "{name}: {refused:?}"
        );
    }
    assert!(
        section(&issuer("").replace("i2", "smart_2"))
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
        issuer(""),
        r#"[issuer.i5]
issuer = "https://introspected.example.org"
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
        Some(IssuerKind::Smart),
        resolved.introspection.first().map(|settings| settings.kind)
    );
    Ok(())
}
