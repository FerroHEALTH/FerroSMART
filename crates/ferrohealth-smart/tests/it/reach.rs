// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! `client::Reach` on the HTTP engine: a host reached at the address an
//! override names, the client certificate presented in the handshake
//! (RFC 8705 §2), and a server below the TLS floor refused.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ferrohealth_smart::client::{PresentedTls, Reach, Tls};
use ferrohealth_smart::jws::algorithm::Algorithm;
use ferrohealth_smart::metadata::Http;

use crate::support::ec_key;
use crate::tls::{start, start_issuer_at};

/// The time one call may take.
const TIMEOUT: Duration = Duration::from_secs(5);

/// A host name no resolver answers (RFC 6761 §6.4).
const HOST: &str = "provider.invalid";

/// The configuration a product builds over the trust roots of `ca_pem`,
/// with no client certificate.
fn trusting(ca_pem: &str) -> Tls {
    Tls {
        presented: Some(crate::tls::presented_pem(ca_pem, None).expect("the roots read")),
        ..Tls::default()
    }
}

/// The loopback address of the issuer `issuer` listens on.
fn address_of(issuer: &str) -> SocketAddr {
    let port = url::Url::parse(issuer)
        .expect("a URL")
        .port()
        .expect("a port");
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[tokio::test]
async fn an_override_reaches_the_named_host_at_its_address() {
    let key = ec_key("reach-resolve", Algorithm::Es256);
    let issuer = start_issuer_at(key.jwk.clone(), HOST, rustls::DEFAULT_VERSIONS).await;
    let tls = trusting(&issuer.ca_pem);

    let reach = Reach::default().with_resolve(HOST, address_of(&issuer.issuer));
    let metadata = Http::reaching(TIMEOUT, &tls, &reach)
        .expect("the engine builds")
        .discover(&issuer.issuer)
        .await
        .expect(
            "the metadata is read at the overridden address, its certificate checked for the host",
        );
    assert_eq!(metadata.issuer, issuer.issuer);

    let unresolved = Http::reaching(TIMEOUT, &tls, &Reach::default()).expect("the engine builds");
    assert!(
        unresolved.discover(&issuer.issuer).await.is_err(),
        "without the override the host name resolves nowhere"
    );
}

#[tokio::test]
async fn the_client_certificate_is_presented_to_the_provider() {
    let endpoint = start("unused").await;
    let tls = Tls {
        presented: Some(
            crate::tls::presented_pem(
                &endpoint.ca_pem,
                Some((&endpoint.client_certificate_pem, &endpoint.client_key_pem)),
            )
            .expect("the identity reads"),
        ),
        ..Tls::default()
    };
    let issuer = endpoint.url.trim_end_matches("/token").to_owned();
    let http = Http::reaching(TIMEOUT, &tls, &Reach::default()).expect("the engine builds");
    // The endpoint answers every request with a token, so discovery itself fails; what
    // the case reads is the handshake.
    drop(http.discover(&issuer).await);
    let seen = endpoint.seen();
    assert!(!seen.is_empty(), "the endpoint was reached");
    assert!(
        seen.iter().all(|request| request.certificate),
        "every request presented the client certificate"
    );
}

#[tokio::test]
async fn a_provider_below_the_built_configuration_s_floor_is_refused() {
    use rustls::pki_types::pem::PemObject as _;
    let key = ec_key("reach-floor", Algorithm::Es256);
    let issuer = start_issuer_at(key.jwk.clone(), "localhost", &[&rustls::version::TLS12]).await;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(
            rustls::pki_types::CertificateDer::from_pem_slice(issuer.ca_pem.as_bytes())
                .expect("the root"),
        )
        .expect("the root is added");
    let only_13 = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3")
    .with_root_certificates(roots)
    .with_no_client_auth();
    let floor = Tls {
        presented: Some(PresentedTls::new(Arc::new(only_13), None)),
        ..Tls::default()
    };
    assert!(
        Http::reaching(TIMEOUT, &floor, &Reach::default())
            .expect("the engine builds")
            .discover(&issuer.issuer)
            .await
            .is_err(),
        "a TLS 1.2 server is refused under a configuration of TLS 1.3 alone"
    );
    Http::reaching(TIMEOUT, &trusting(&issuer.ca_pem), &Reach::default())
        .expect("the engine builds")
        .discover(&issuer.issuer)
        .await
        .expect("the same server is read under a configuration that speaks TLS 1.2");
}
