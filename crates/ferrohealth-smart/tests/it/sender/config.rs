// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The configuration of sender-constrained tokens: the per-issuer
//! `sender_constraint` key and the surface's `[auth.dpop]` table.

use std::sync::Arc;
use std::time::Duration;

use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::sender::SenderConstraint;
use ferrohealth_smart::sender::proof::ProofCheck;
use ferrohealth_smart::sender::proof::ProofSettingsError;
use ferrohealth_smart::sender::replay::MemoryReplayStore;

/// Returns the section `text` describes.
fn section(text: &str) -> AuthSection {
    toml::from_str(text).expect("the section parses")
}

/// One `persons` issuer table, with `extra` keys.
fn issuer(extra: &str) -> String {
    format!("[issuer.i1]\nissuer = \"https://as.example.org\"\naudience = [\"a\"]\n{extra}\n")
}

#[test]
fn an_issuer_requires_a_sender_constraint_when_it_says_so() {
    let required = section(&issuer("sender_constraint = \"required\""))
        .resolve(&[])
        .expect("the section resolves");
    assert_eq!(
        Some(SenderConstraint::Required),
        required
            .issuers
            .first()
            .map(|settings| settings.sender_constraint)
    );
    let default = section(&issuer(""))
        .resolve(&[])
        .expect("the section resolves");
    assert_eq!(
        Some(SenderConstraint::None),
        default
            .issuers
            .first()
            .map(|settings| settings.sender_constraint),
        "no constraint unless the issuer sets one"
    );
    assert!(
        toml::from_str::<AuthSection>(&issuer("sender_constraint = \"optional\"")).is_err(),
        "a value outside none and required does not parse"
    );
}

#[test]
fn the_dpop_table_names_the_window_and_the_product_the_external_url() {
    let resolved = section(&format!("[dpop]\nmax_age = \"30s\"\n{}", issuer("")))
        .resolve(&[])
        .expect("the section resolves");
    let dpop = resolved.dpop.expect("the table resolves");
    let settings = dpop.settings(
        "https://ehr.example.org/fhir"
            .parse()
            .expect("the product's URL"),
    );
    assert_eq!(
        "https://ehr.example.org/fhir",
        settings.external_url.as_str()
    );
    assert_eq!(Duration::from_secs(30), settings.max_age);
    assert_eq!(Duration::from_secs(10), settings.clock_skew);
    assert!(
        section(&issuer(""))
            .resolve(&[])
            .expect("resolves")
            .dpop
            .is_none(),
        "no table, no DPoP"
    );
}

#[test]
fn the_dpop_table_takes_no_external_url() {
    let outcome = toml::from_str::<AuthSection>(&format!(
        "[dpop]\nexternal_url = \"https://ehr.example.org\"\n{}",
        issuer("")
    ));
    let error = outcome.expect_err("the key is unknown");
    assert!(
        error.to_string().contains("unknown field `external_url`"),
        "{error}"
    );
}

#[test]
fn a_dpop_table_that_breaks_a_rule_refuses_the_start() {
    for (table, expected) in [
        (
            "max_age = \"0s\"",
            ProofSettingsError::MaxAge {
                max_age: Duration::ZERO,
            },
        ),
        ("algorithms = []", ProofSettingsError::NoAlgorithm),
    ] {
        let outcome = section(&format!("[dpop]\n{table}\n{}", issuer(""))).resolve(&[]);
        assert!(
            matches!(&outcome, Err(ConfigError::Dpop { source }) if *source == expected),
            "{table}: {outcome:?}"
        );
    }
}

#[test]
fn a_dpop_table_naming_a_symmetric_algorithm_is_refused() {
    // NOTE: RFC 9449 §4.2 and §11.6, a proof is never signed with a MAC, so no
    // `[dpop]` table can name one.
    for symmetric in ["HS256", "HS384", "HS512", "none"] {
        let outcome = toml::from_str::<AuthSection>(&format!(
            "[dpop]\nalgorithms = [\"{symmetric}\"]\n{}",
            issuer("")
        ));
        let error = outcome.expect_err("no algorithm has the name");
        assert!(
            error
                .to_string()
                .contains("signature algorithm is not one of"),
            "{symmetric}: {error}"
        );
    }
}

#[test]
fn an_external_url_that_breaks_the_url_rule_is_refused_by_the_check() {
    let dpop = section(&format!("[dpop]\n{}", issuer("")))
        .resolve(&[])
        .expect("the section resolves")
        .dpop
        .expect("the table resolves");
    for url in [
        "https://ehr.example.org/?q",
        "https://ehr.example.org/#f",
        "https://user:pw@ehr.example.org",
        "ftp://ehr.example.org",
    ] {
        let outcome = ProofCheck::new(
            dpop.settings(url.parse().expect("a URL")),
            Arc::new(MemoryReplayStore::new()),
        );
        assert!(
            matches!(outcome, Err(ProofSettingsError::ExternalUrl)),
            "{url}: {outcome:?}"
        );
    }
}
