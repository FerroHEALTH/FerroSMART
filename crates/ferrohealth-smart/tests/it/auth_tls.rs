// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! `[auth.tls]`: an issuer behind a private certificate authority is read
//! over the TLS the product's reader built from the table, the crate reads
//! no TLS file itself, and the retired `auth.ca_file` is refused naming its
//! replacement.

use ferrohealth_config::tls::TlsClientSection;
use ferrohealth_smart::config::AuthMode;
use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::config::IntrospectionSection;
use ferrohealth_smart::config::IssuerEntry;
use ferrohealth_smart::config::credentials::OauthSection;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::resource::ResourceServer;
use ferrohealth_smart::resource::introspection::Introspector;
use jsonwebtoken::Algorithm;
use secrecy::SecretString;

use crate::support::AUDIENCE;
use crate::support::ec_key;
use crate::support::temp_file;
use crate::tls::PemTls;
use crate::tls::start_issuer;

/// The `tls` table trusting the roots of `ca_file`, when given.
fn roots(ca_file: Option<std::path::PathBuf>) -> TlsClientSection {
    TlsClientSection {
        trust_roots_file: ca_file,
        ..TlsClientSection::default()
    }
}

/// An `[auth]` section trusting `issuer`, with `auth.tls` over `ca_file`.
fn section(issuer: &str, ca_file: Option<std::path::PathBuf>) -> AuthSection {
    AuthSection {
        issuer: std::collections::BTreeMap::from([(String::from("i1"), entry(issuer))]),
        tls: roots(ca_file),
        ..AuthSection::default()
    }
}

/// The `persons` issuer table of `issuer`.
fn entry(issuer: &str) -> IssuerEntry {
    IssuerEntry {
        issuer: ferrohealth_secret::secret_url::SecretUrl::new(issuer),
        kind: Some(IssuerKind::Smart),
        audience: vec![AUDIENCE.to_owned()],
        ..IssuerEntry::default()
    }
}

#[tokio::test]
async fn an_issuer_behind_a_private_authority_is_read_over_the_built_tls() {
    let key = ec_key("auth-tls", Algorithm::ES256);
    let issuer = start_issuer(key.jwk.clone()).await;
    let ca = temp_file("ca.pem", issuer.ca_pem.as_bytes());

    let trusted = section(&issuer.issuer, Some(ca))
        .resolve_with_tls(&PemTls, &[])
        .expect("resolves");
    let settings = trusted.issuers.into_iter().next().expect("one issuer");
    assert!(settings.tls.presented.is_some());
    ResourceServer::discover(settings)
        .await
        .expect("the metadata and the key set are read over TLS from the private authority");

    let untrusted = section(&issuer.issuer, None)
        .resolve(&[])
        .expect("resolves");
    let settings = untrusted.issuers.into_iter().next().expect("one issuer");
    assert!(
        ResourceServer::discover(settings).await.is_err(),
        "without the roots the private authority is not trusted"
    );
}

#[test]
fn a_tls_table_naming_material_needs_the_product_s_builder() {
    let ca = temp_file("unbuilt-ca.pem", b"roots");
    let err = section("https://idp.example", Some(ca))
        .resolve(&[])
        .expect_err("refused");
    assert!(
        matches!(err, ConfigError::TlsNotBuilt { key: "auth.tls" }),
        "{err:?}"
    );
}

/// How the introspection call authenticates in [`introspecting`].
#[derive(Clone, Copy, Debug)]
enum Credential {
    /// `auth.introspection.client`.
    Client,
    /// `auth.introspection.bearer`.
    Bearer,
}

/// An `[auth]` section introspecting tokens of `issuer` under `credential`,
/// whose grant's `tls` trusts `grant_ca_file` when given.
fn introspecting(
    issuer: &str,
    credential: Credential,
    grant_ca_file: Option<std::path::PathBuf>,
) -> AuthSection {
    let grant = OauthSection {
        token_endpoint: ferrohealth_secret::secret_url::SecretUrl::new(format!(
            "{issuer}{}",
            crate::support::TOKEN_PATH
        )),
        client_id: String::from("ferro-rs"),
        client_secret: Some(SecretString::from("synthetic-secret")),
        tls: roots(grant_ca_file),
        ..OauthSection::default()
    };
    let (client, bearer) = match credential {
        Credential::Client => (Some(grant), None),
        Credential::Bearer => (None, Some(grant)),
    };
    AuthSection {
        issuer: std::collections::BTreeMap::from([(
            String::from("i2"),
            IssuerEntry {
                mode: AuthMode::Introspection,
                introspection: Some(IntrospectionSection {
                    endpoint: ferrohealth_secret::secret_url::SecretUrl::new(format!(
                        "{issuer}/introspect"
                    )),
                    client,
                    bearer,
                    ..IntrospectionSection::default()
                }),
                ..entry(issuer)
            },
        )]),
        ..section(issuer, None)
    }
}

#[tokio::test]
async fn introspection_reads_an_issuer_behind_a_private_authority_over_the_grant_s_tls() {
    let key = ec_key("auth-tls-introspection", Algorithm::ES256);
    let issuer = start_issuer(key.jwk.clone()).await;
    let other = start_issuer(key.jwk.clone()).await;
    let ca = temp_file("introspection-ca.pem", issuer.ca_pem.as_bytes());
    let other_ca = temp_file("introspection-other-ca.pem", other.ca_pem.as_bytes());
    for credential in [Credential::Client, Credential::Bearer] {
        let read = |grant_ca_file| {
            let resolved = introspecting(&issuer.issuer, credential, grant_ca_file)
                .resolve_with_tls(&PemTls, &[])
                .expect("resolves");
            Introspector::discover(
                resolved
                    .introspection
                    .into_iter()
                    .next()
                    .expect("introspection settings"),
            )
        };
        read(Some(ca.clone())).await.unwrap_or_else(|e| {
            panic!("{credential:?}: the metadata is read over the grant's TLS: {e}")
        });
        assert!(
            read(None).await.is_err(),
            "{credential:?}: without the roots the private authority is not trusted"
        );
        assert!(
            read(Some(other_ca.clone())).await.is_err(),
            "{credential:?}: the grant's roots name another authority"
        );
    }
}

#[test]
fn the_retired_ca_file_is_an_unknown_key() {
    let read = toml::from_str::<AuthSection>(
        "ca_file = \"/run/ca.pem\"\n[issuer.i1]\nissuer = \"https://idp.example\"\naudience = [\"a\"]\n",
    );
    assert!(read.is_err(), "ca_file is no key of the section");
}

#[test]
fn a_table_the_builder_refuses_refuses_the_start_by_its_key() {
    let missing = std::env::temp_dir().join("ferrohealth-smart-no-such-ca.pem");
    let err = section("https://idp.example", Some(missing))
        .resolve_with_tls(&PemTls, &[])
        .expect_err("refused");
    assert!(
        matches!(&err, ConfigError::TlsBuild { key, .. } if key == "auth.tls"),
        "{err:?}"
    );
    assert!(err.to_string().contains("auth.tls"), "{err}");
}
