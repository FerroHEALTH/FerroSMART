// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! An upstream entry's shape (#733): the table present names the protocol,
//! a preset fills what an OpenID Connect table leaves out and a key the
//! table sets wins, and the two operator commands, `ferrosmart subject` and
//! `ferrosmart upstream registration`, read the entry as the server does.

use std::process::ExitCode;

use clap::Parser as _;
use ferrosmart::cli::Cli;
use ferrosmart::config::Config;
use ferrosmart::config::error::Error;
use ferrosmart::upstream::preset::Preset;
use ferrosmart::upstream::registration::{Registration, subject};
use ferrosmart::upstream::{Authentication, OidcUpstream, Protocol, Upstream, pairwise};

use crate::support::{ASSURANCE, Keys, config, upstream_assertion};

/// The issuer of every case.
const ISSUER: &str = "https://smart.example.org";
/// The upstream issuer of every OpenID Connect case.
const UPSTREAM: &str = "https://idp.example.org/realms/hospital";

/// One OpenID Connect entry named `idp` with `entry` among its keys and
/// `oidc` in its table, a fresh assertion key under `keys`, and the role
/// `clinician`.
fn oidc(keys: &Keys, entry: &str, oidc: &str) -> String {
    format!(
        "[ferrosmart]\nissuer = {ISSUER:?}\n\
         [[ferrosmart.upstream]]\nname = \"idp\"\n{entry}\n{ASSURANCE}\
         [ferrosmart.upstream.oidc]\nissuer = {UPSTREAM:?}\nclient_id = \"ferrosmart\"\n{oidc}\n\
         {}\
         [[ferrosmart.role]]\nname = \"clinician\"\nscopes = [\"user/Patient.rs\"]\n",
        upstream_assertion(keys.dir.path())
    )
}

/// The one provider `text` resolves to.
fn resolved(text: &str, keys: &Keys) -> Upstream {
    config(text, keys)
        .resolve()
        .expect("resolves")
        .upstreams
        .into_iter()
        .next()
        .expect("a provider")
}

/// The OpenID Connect settings of `upstream`.
fn oidc_upstream(upstream: &Upstream) -> &OidcUpstream {
    match &upstream.protocol {
        Protocol::Oidc(oidc) => Some(oidc),
        Protocol::Saml(_) | Protocol::Wallet(_) => None,
    }
    .expect("the provider speaks OpenID Connect")
}

/// The scopes and trusted audiences of an OpenID Connect provider.
fn oidc_of(upstream: &Upstream) -> (Vec<String>, Vec<String>) {
    let oidc = oidc_upstream(upstream);
    (oidc.scopes.clone(), oidc.trusted_audiences.clone())
}

/// The algorithm the provider's client assertions are signed with.
fn algorithm_of(upstream: &Upstream) -> jsonwebtoken::Algorithm {
    match &oidc_upstream(upstream).authentication {
        Authentication::PrivateKeyJwt(keys) => Some(keys.signer.algorithm()),
        Authentication::ClientSecretBasic(_) => None,
    }
    .expect("private_key_jwt")
}

/// The words of a list of strings.
fn strings(words: &[&str]) -> Vec<String> {
    words.iter().map(|&word| word.to_owned()).collect()
}

// NOTE: no specification governs the entry: our own design, the table present
// names the protocol, and `protocol` is an unknown key (#733).
#[test]
fn the_table_present_names_the_protocol_and_protocol_is_unknown() {
    let keys = Keys::new();
    let plain = oidc(&keys, "", "");
    let upstream = resolved(&plain, &keys);
    assert!(matches!(upstream.protocol, Protocol::Oidc(_)));
    let with_protocol = oidc(&keys, "protocol = \"oidc\"", "");
    assert!(
        matches!(
            Config::from_sources(Some(&with_protocol), &std::collections::BTreeMap::new()),
            Err(Error::Load(_))
        ),
        "`protocol` is no key"
    );
    let neither =
        format!("[ferrosmart]\nissuer = {ISSUER:?}\n[[ferrosmart.upstream]]\nname = \"idp\"\n");
    let both = plain.replace(
        "[[ferrosmart.role]]",
        "[ferrosmart.upstream.saml]\nentity_id = \"https://idp.example.org/saml\"\n[[ferrosmart.role]]",
    );
    for text in [neither, both] {
        assert!(
            matches!(config(&text, &keys).resolve(), Err(Error::Upstream { .. })),
            "{text}"
        );
    }
}

// NOTE: no specification governs the presets: our own design (#733), each the
// tested setup of docs/architecture.md §13.16 and §13.18 to §13.20.
#[test]
fn each_preset_fills_what_the_table_leaves_out() {
    let keys = Keys::new();
    for (preset, scopes, fhir_user, roles, algorithm) in [
        (
            "keycloak",
            &["openid"][..],
            "fhir_user",
            "roles",
            jsonwebtoken::Algorithm::RS256,
        ),
        (
            "entra",
            &["openid", "profile"][..],
            "extn.fhirUser",
            "roles",
            jsonwebtoken::Algorithm::PS256,
        ),
        (
            "okta",
            &["openid", "profile"][..],
            "fhir_user",
            "groups",
            jsonwebtoken::Algorithm::RS256,
        ),
        (
            "zitadel",
            &["openid", "profile"][..],
            "fhirUser",
            "urn:zitadel:iam:org:project:roles",
            jsonwebtoken::Algorithm::RS256,
        ),
    ] {
        let upstream = resolved(&oidc(&keys, &format!("preset = {preset:?}"), ""), &keys);
        assert_eq!(
            (strings(scopes), Vec::new()),
            oidc_of(&upstream),
            "{preset}"
        );
        assert_eq!(
            Some(fhir_user),
            upstream.fhir_user_claim.as_deref(),
            "{preset}"
        );
        assert_eq!(strings(&[roles]), upstream.role_claims, "{preset}");
        assert_eq!(algorithm, algorithm_of(&upstream), "{preset}");
    }
    let none = resolved(&oidc(&keys, "", ""), &keys);
    assert_eq!((strings(&["openid"]), Vec::new()), oidc_of(&none));
    assert_eq!(None, none.fhir_user_claim);
    assert_eq!(ferrohealth_smart::roles::default_claims(), none.role_claims);
    assert_eq!(jsonwebtoken::Algorithm::RS256, algorithm_of(&none));
}

#[test]
fn a_key_the_table_sets_wins_over_the_preset() {
    let keys = Keys::new();
    let text = oidc(
        &keys,
        "preset = \"entra\"",
        "scopes = [\"openid\", \"email\"]\nfhir_user_claim = \"\"\n\
         role_claims = [\"wids\"]\ntrusted_audiences = [\"api://hospital\"]",
    )
    .replace(
        "[ferrosmart.upstream.oidc.private_key_jwt.keys]",
        "[ferrosmart.upstream.oidc.private_key_jwt]\nalgorithm = \"RS384\"\n\
         [ferrosmart.upstream.oidc.private_key_jwt.keys]",
    );
    let upstream = resolved(&text, &keys);
    assert_eq!(
        (strings(&["openid", "email"]), strings(&["api://hospital"])),
        oidc_of(&upstream)
    );
    assert_eq!(None, upstream.fhir_user_claim, "an empty claim names none");
    assert_eq!(strings(&["wids"]), upstream.role_claims);
    assert_eq!(jsonwebtoken::Algorithm::RS384, algorithm_of(&upstream));
}

#[test]
fn a_preset_is_refused_on_a_saml_entry_and_an_unknown_one_at_load() {
    let keys = Keys::new();
    let saml = format!(
        "[ferrosmart]\nissuer = {ISSUER:?}\n[[ferrosmart.upstream]]\nname = \"idp\"\n\
         preset = \"keycloak\"\n[ferrosmart.upstream.saml]\nentity_id = \"https://idp.example.org/saml\"\n"
    );
    assert!(matches!(
        config(&saml, &keys).resolve(),
        Err(Error::Upstream { .. })
    ));
    let unknown = oidc(&keys, "preset = \"acme\"", "");
    assert!(matches!(
        Config::from_sources(Some(&unknown), &std::collections::BTreeMap::new()),
        Err(Error::Load(_))
    ));
}

#[test]
fn every_preset_names_itself_and_reads() {
    for preset in Preset::ALL {
        let defaults = preset.defaults().expect("the preset reads");
        assert!(defaults.scopes.is_some(), "{}", preset.name());
        assert!(
            preset
                .source()
                .contains("SPDX-License-Identifier: BUSL-1.1")
        );
    }
}

// NOTE: docs/architecture.md §13.6 item 9, the pairwise sub of the issuer exactly
// as configured, so a trailing slash is another subject (#733).
#[test]
fn the_subject_is_the_pairwise_sub_under_the_configured_issuer() {
    let keys = Keys::new();
    let text = oidc(&keys, "", "");
    let section = config(&text, &keys).ferrosmart;
    let printed = subject(&section, "idp", "248289761001").expect("a subject");
    assert_eq!(pairwise(UPSTREAM, "248289761001"), printed);
    assert_ne!(
        pairwise(&format!("{UPSTREAM}/"), "248289761001"),
        printed,
        "the issuer is taken exactly"
    );
    let refused = subject(&section, "staff", "248289761001").expect_err("no such entry");
    assert!(
        matches!(&refused, Error::NoUpstream { name, known } if name == "staff" && known == "idp"),
        "{refused:?}"
    );
    let saml = format!(
        "[ferrosmart]\nissuer = {ISSUER:?}\n[[ferrosmart.upstream]]\nname = \"national\"\n\
         [ferrosmart.upstream.saml]\nentity_id = \"https://idp.example.org/saml\"\n"
    );
    let section = config(&saml, &keys).ferrosmart;
    assert_eq!(
        pairwise("https://idp.example.org/saml", "person-1"),
        subject(&section, "national", "person-1").expect("a subject")
    );
}

#[test]
fn the_registration_names_what_the_provider_is_configured_with() {
    let keys = Keys::new();
    let text = oidc(&keys, "preset = \"entra\"", "").replace(
        "[ferrosmart.upstream.oidc.private_key_jwt.keys]",
        "[ferrosmart.upstream.oidc.private_key_jwt]\n\
         certificate_file = \"/run/secrets/upstream-assertion.crt\"\n\
         [ferrosmart.upstream.oidc.private_key_jwt.keys]\nkid = \"upstream-1\"",
    );
    let section = config(&text, &keys).ferrosmart;
    let registration = Registration::of(&section, "idp").expect("a registration");
    for (key, value) in [
        ("issuer", UPSTREAM),
        ("client id", "ferrosmart"),
        ("grant", "authorization code, PKCE S256"),
        ("redirect URI", "https://smart.example.org/callback"),
        (
            "post-logout redirect URI",
            "https://smart.example.org/logout/return",
        ),
        (
            "back-channel logout URI",
            "https://smart.example.org/backchannel-logout",
        ),
        ("client authentication", "private_key_jwt, signed PS256"),
        ("JWK Set URL", "https://smart.example.org/upstream-jwks"),
        ("certificate", "/run/secrets/upstream-assertion.crt"),
        ("key id", "upstream-1"),
        ("scopes", "openid profile"),
        ("fhirUser claim", "extn.fhirUser, in the ID Token"),
        ("role claims", "roles, in the ID Token"),
        ("roles", "clinician"),
    ] {
        assert_eq!(Some(value), registration.get(key), "{key}");
    }
    let printed = registration.to_string();
    assert!(
        printed.starts_with("Register FerroSMART at the provider `idp` (OpenID Connect) with:\n"),
        "{printed}"
    );
    assert!(
        printed.contains("  redirect URI              https://smart.example.org/callback\n"),
        "{printed}"
    );

    let secret = format!(
        "[ferrosmart]\nissuer = {ISSUER:?}\n[[ferrosmart.upstream]]\nname = \"idp\"\n\
         [ferrosmart.upstream.oidc]\nissuer = {UPSTREAM:?}\nclient_id = \"ferrosmart\"\n\
         [ferrosmart.upstream.oidc.client_secret_basic]\nsecret_file = \"/run/secrets/upstream\"\n"
    );
    let section = config(&secret, &keys).ferrosmart;
    let registration = Registration::of(&section, "idp").expect("a registration");
    assert_eq!(
        Some("client_secret_basic, the secret the provider issues"),
        registration.get("client authentication")
    );
    assert_eq!(None, registration.get("JWK Set URL"), "no key to read");
    assert!(
        !registration.to_string().contains("/run/secrets/upstream"),
        "the secret's file is never printed"
    );
}

#[test]
fn a_saml_registration_names_the_service_provider_and_the_attributes() {
    let keys = Keys::new();
    let text = format!(
        "[ferrosmart]\nissuer = {ISSUER:?}\n[[ferrosmart.upstream]]\nname = \"national\"\n\
         [ferrosmart.upstream.saml]\nentity_id = \"https://idp.example.org/saml\"\n\
         name_id_format = \"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\"\n\
         [ferrosmart.upstream.saml.claims]\nroles = \"urn:oid:1.3.6.1.4.1.5923.1.1.1.7\"\n"
    );
    let section = config(&text, &keys).ferrosmart;
    let registration = Registration::of(&section, "national").expect("a registration");
    assert_eq!("SAML 2.0", registration.protocol);
    for (key, value) in [
        ("identity provider", "https://idp.example.org/saml"),
        (
            "service provider entity ID",
            "https://smart.example.org/saml/metadata",
        ),
        (
            "assertion consumer service",
            "https://smart.example.org/saml/acs, HTTP-POST and HTTP-Artifact",
        ),
        (
            "name ID format",
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        ),
        ("attributes", "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"),
    ] {
        assert_eq!(Some(value), registration.get(key), "{key}");
    }
    assert!(matches!(
        Registration::of(&section, "idp"),
        Err(Error::NoUpstream { .. })
    ));
}

// NOTE: no specification governs the command line: our own design (#733).
#[tokio::test]
async fn both_commands_run_from_the_configuration_alone() {
    let keys = Keys::new();
    let path = keys.dir.path().join("ferrosmart.toml");
    std::fs::write(&path, oidc(&keys, "preset = \"keycloak\"", "")).expect("written");
    let path = path.display().to_string();
    for args in [
        vec![
            "ferrosmart",
            "--config",
            &path,
            "subject",
            "--upstream",
            "idp",
            "--sub",
            "s-1",
        ],
        vec![
            "ferrosmart",
            "--config",
            &path,
            "upstream",
            "registration",
            "idp",
        ],
    ] {
        let cli = Cli::try_parse_from(&args).expect("parses");
        let code = ferrosmart::command::dispatch(cli).await.expect("runs");
        assert_eq!(ExitCode::SUCCESS, code, "{args:?}");
    }
    for args in [
        vec![
            "ferrosmart",
            "--config",
            &path,
            "subject",
            "--upstream",
            "staff",
            "--sub",
            "s-1",
        ],
        vec![
            "ferrosmart",
            "--config",
            &path,
            "subject",
            "--upstream",
            "idp",
            "--sub",
            "",
        ],
        vec![
            "ferrosmart",
            "--config",
            &path,
            "upstream",
            "registration",
            "staff",
        ],
    ] {
        let cli = Cli::try_parse_from(&args).expect("parses");
        assert!(
            ferrosmart::command::dispatch(cli).await.is_err(),
            "{args:?}"
        );
    }
}
