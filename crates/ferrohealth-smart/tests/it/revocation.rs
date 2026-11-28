// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! `config::ServerTls` over a table naming `trust_roots_file`: the
//! connection's endpoint kept cleared for revocation, so a chain its CRL
//! holds good connects, and one it revokes, or one no clearing covers, does
//! not.
//!
//! The root and the server certificate it signs are generated when the case
//! runs; the server certificate names the root's CRL, which a `wiremock`
//! stub serves. No specification governs the harness: our own design.

use std::sync::Arc;
use std::time::Duration;

use ferrohealth_smart::config::TlsBuilder as _;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CrlDistributionPoint,
    DnType, IsCa, Issuer, KeyIdMethod, KeyPair, RevocationReason, RevokedCertParams, SerialNumber,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The serial number of the server certificate.
const SERIAL: u64 = 0x2a;

/// A TLS server for `127.0.0.1` under a root whose CRL a stub serves.
struct Front {
    /// The endpoint the server listens at.
    url: url::Url,
    /// The root, in PEM, in a file a `trust_roots_file` names.
    roots: tempfile::NamedTempFile,
    /// The stub that serves the root's CRL.
    _crl: MockServer,
}

/// Returns the year, month and day `days` from today.
fn day(days: i64) -> (i32, u8, u8) {
    let date = jiff::Zoned::now()
        .date()
        .checked_add(jiff::Span::new().days(days))
        .expect("a date");
    (
        i32::from(date.year()),
        u8::try_from(date.month()).expect("a month"),
        u8::try_from(date.day()).expect("a day"),
    )
}

/// Starts a front whose CRL revokes the server certificate when `revoked`.
async fn front(revoked: bool) -> Front {
    let crl = MockServer::start().await;
    let root_key = KeyPair::generate().expect("a key");
    let mut root = CertificateParams::new(Vec::<String>::new()).expect("params");
    root.distinguished_name
        .push(DnType::CommonName, "revocation test root");
    root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ((fy, fm, fd), (uy, um, ud)) = (day(-1), day(30));
    let from = rcgen::date_time_ymd(fy, fm, fd);
    let until = rcgen::date_time_ymd(uy, um, ud);
    root.not_before = from;
    root.not_after = until;
    let root_certificate = root.self_signed(&root_key).expect("the root");
    let issuer = Issuer::new(root, root_key);

    let server_key = KeyPair::generate().expect("a key");
    let mut server = CertificateParams::new(vec![String::from("127.0.0.1")]).expect("params");
    server.serial_number = Some(SerialNumber::from(SERIAL));
    server.not_before = from;
    server.not_after = until;
    server.crl_distribution_points = vec![CrlDistributionPoint {
        uris: vec![format!("{}/root.crl", crl.uri())],
    }];
    let server_certificate = server.signed_by(&server_key, &issuer).expect("the server");

    let revoked_certs = if revoked {
        vec![RevokedCertParams {
            serial_number: SerialNumber::from(SERIAL),
            revocation_time: from,
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        }]
    } else {
        Vec::new()
    };
    let list = CertificateRevocationListParams {
        this_update: from,
        next_update: until,
        crl_number: SerialNumber::from(1_u64),
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&issuer)
    .expect("the CRL");
    Mock::given(method("GET"))
        .and(path("/root.crl"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(list.der().to_vec()))
        .mount(&crl)
        .await;

    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("the versions")
    .with_no_client_auth()
    .with_single_cert(
        vec![server_certificate.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
    )
    .expect("the server configuration");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = listener.local_addr().expect("an address").port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move { acceptor.accept(stream).await });
        }
    });
    let mut roots = tempfile::NamedTempFile::new().expect("a file");
    std::io::Write::write_all(&mut roots, root_certificate.pem().as_bytes()).expect("written");
    Front {
        url: url::Url::parse(&format!("https://127.0.0.1:{port}")).expect("a URL"),
        roots,
        _crl: crl,
    }
}

/// Returns whether a handshake over `presented` reaches `front` within
/// `within`, trying again while the clearing has not answered.
async fn connects(
    front: &Front,
    presented: &ferrohealth_smart::client::PresentedTls,
    within: Duration,
) -> bool {
    let connector = TlsConnector::from(Arc::clone(presented.config()));
    let name = ServerName::try_from("127.0.0.1").expect("a name");
    let host = front.url.socket_addrs(|| None).expect("an address");
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let stream = tokio::net::TcpStream::connect(host.as_slice())
            .await
            .expect("the front answers");
        if connector.connect(name.clone(), stream).await.is_ok() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Builds the table that trusts `front`'s root, for connections to
/// `endpoints`.
fn presented(front: &Front, endpoints: &[url::Url]) -> ferrohealth_smart::client::PresentedTls {
    let section = ferrohealth_config::tls::TlsClientSection {
        trust_roots_file: Some(front.roots.path().to_path_buf()),
        ..ferrohealth_config::tls::TlsClientSection::default()
    };
    ferrohealth_smart::config::ServerTls
        .build("test.tls", &section, endpoints)
        .expect("the configuration")
}

// NOTE: the trust_roots_file policy of ferrohealth-server 0.14: a chain to its root
// connects once its endpoint is cleared by the CRL (RFC 5280 §5), which ServerTls keeps.
#[tokio::test]
async fn a_chain_its_crl_holds_good_connects_once_cleared() {
    let front = front(false).await;
    let presented = presented(&front, std::slice::from_ref(&front.url));
    assert!(connects(&front, &presented, Duration::from_secs(10)).await);
    assert_eq!(None, presented.unchecked_roots());
}

// NOTE: the same policy fails closed: a revoked chain, and a chain to that root no
// clearing covers, never connect.
#[tokio::test]
async fn a_revoked_or_uncleared_chain_does_not_connect() {
    let revoked = front(true).await;
    let presented_revoked = presented(&revoked, std::slice::from_ref(&revoked.url));
    assert!(!connects(&revoked, &presented_revoked, Duration::from_secs(3)).await);
    let good = front(false).await;
    let uncleared = presented(&good, &[]);
    assert!(!connects(&good, &uncleared, Duration::from_secs(3)).await);
}
