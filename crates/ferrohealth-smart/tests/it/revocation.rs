// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! `config::ServerTls` over a table naming `trust_roots_file`: the
//! connection's endpoint kept cleared for revocation, so a chain its CRL
//! holds good connects, and one it revokes, or one no clearing covers, does
//! not, the key set a metadata document places on another host under the
//! same root included.
//!
//! The root and the server certificate it signs are generated when the case
//! runs; the server certificate names the root's CRL, which a `wiremock`
//! stub serves. No specification governs the harness: our own design.

use std::sync::Arc;
use std::time::Duration;

use ferrohealth_secret::secret_url::SecretUrl;
use ferrohealth_smart::config::AuthSection;
use ferrohealth_smart::config::IssuerEntry;
use ferrohealth_smart::config::TlsBuilder as _;
use ferrohealth_smart::jws::algorithm::Algorithm;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::metadata::DiscoveryError;
use ferrohealth_smart::resource::ResourceError;
use ferrohealth_smart::resource::ResourceServer;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CrlDistributionPoint,
    DnType, IsCa, Issuer, KeyIdMethod, KeyPair, RevocationReason, RevokedCertParams, SerialNumber,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The serial number of the server certificate the root's CRL revokes.
const SERIAL: u64 = 0x2a;

/// The serial number of a server certificate the root's CRL never revokes.
const HELD_SERIAL: u64 = 0x2b;

/// A root whose CRL a stub serves.
struct Root {
    /// The root's issuer, which signs the server certificates.
    issuer: Issuer<'static, KeyPair>,
    /// The root, in PEM, in a file a `trust_roots_file` names.
    roots: tempfile::NamedTempFile,
    /// The stub that serves the root's CRL.
    crl: MockServer,
}

/// A TLS server for `127.0.0.1` under a root whose CRL a stub serves.
struct Front {
    /// The endpoint the server listens at.
    url: url::Url,
    /// The root of its certificate.
    root: Root,
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

/// Makes `params` valid from yesterday for 30 days, as every certificate
/// and the CRL are.
fn validity(params: &mut CertificateParams) {
    let ((fy, fm, fd), (uy, um, ud)) = (day(-1), day(30));
    params.not_before = rcgen::date_time_ymd(fy, fm, fd);
    params.not_after = rcgen::date_time_ymd(uy, um, ud);
}

impl Root {
    /// Starts a root whose CRL revokes the certificate [`SERIAL`] when
    /// `revoked`.
    async fn new(revoked: bool) -> Self {
        let crl = MockServer::start().await;
        let root_key = KeyPair::generate().expect("a key");
        let mut root = CertificateParams::new(Vec::<String>::new()).expect("params");
        root.distinguished_name
            .push(DnType::CommonName, "revocation test root");
        root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        validity(&mut root);
        let (from, until) = (root.not_before, root.not_after);
        let root_certificate = root.self_signed(&root_key).expect("the root");
        let issuer = Issuer::new(root, root_key);
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
        let mut roots = tempfile::NamedTempFile::new().expect("a file");
        std::io::Write::write_all(&mut roots, root_certificate.pem().as_bytes()).expect("written");
        Self { issuer, roots, crl }
    }

    /// Starts a server for `127.0.0.1` whose certificate under the root
    /// carries `serial`, answering each path `pages` names for its URL with
    /// its JSON body, and `404` for any other.
    async fn serve(
        &self,
        serial: u64,
        pages: impl FnOnce(&str) -> Vec<(&'static str, String)>,
    ) -> url::Url {
        let server_key = KeyPair::generate().expect("a key");
        let mut server = CertificateParams::new(vec![String::from("127.0.0.1")]).expect("params");
        server.serial_number = Some(SerialNumber::from(serial));
        validity(&mut server);
        server.crl_distribution_points = vec![CrlDistributionPoint {
            uris: vec![format!("{}/root.crl", self.crl.uri())],
        }];
        let server_certificate = server
            .signed_by(&server_key, &self.issuer)
            .expect("the server");
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
        let base = format!("https://127.0.0.1:{port}");
        let pages = Arc::new(pages(&base));
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let pages = Arc::clone(&pages);
                tokio::spawn(async move {
                    if let Ok(stream) = acceptor.accept(stream).await {
                        answer(stream, &pages).await;
                    }
                });
            }
        });
        url::Url::parse(&base).expect("a URL")
    }
}

/// Answers the one request `stream` carries from `pages`.
async fn answer(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    pages: &[(&'static str, String)],
) {
    let mut head = Vec::new();
    let mut chunk = [0_u8; 4096];
    while !String::from_utf8_lossy(&head).contains("\r\n\r\n") {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => head.extend_from_slice(chunk.get(..read).unwrap_or_default()),
        }
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let asked = text.split_whitespace().nth(1).unwrap_or_default();
    let (status, body) = pages
        .iter()
        .find(|(page, _)| *page == asked)
        .map_or(("404 Not Found", "{}"), |(_, body)| {
            ("200 OK", body.as_str())
        });
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    if stream.write_all(response.as_bytes()).await.is_ok() {
        drop(stream.shutdown().await);
    }
}

/// Starts a front whose CRL revokes the server certificate when `revoked`.
async fn front(revoked: bool) -> Front {
    let root = Root::new(revoked).await;
    let url = root.serve(SERIAL, |_| Vec::new()).await;
    Front { url, root }
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
        trust_roots_file: Some(front.root.roots.path().to_path_buf()),
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

// NOTE: RFC 8414 §2, `jwks_uri` may name another host than the issuer; under the same
// trust_roots_file policy its chain is cleared before the key set is read.
#[tokio::test]
async fn a_key_set_on_another_host_is_read_only_once_cleared() {
    for revoked in [false, true] {
        let root = Root::new(revoked).await;
        let key = crate::support::ec_key("revocation", Algorithm::Es256);
        let keys = serde_json::json!({ "keys": [key.jwk] }).to_string();
        let key_host = root
            .serve(SERIAL, |_| vec![(crate::support::JWKS_PATH, keys)])
            .await;
        let jwks_uri = key_host.join(crate::support::JWKS_PATH).expect("a URL");
        let issuer = root
            .serve(HELD_SERIAL, |base| {
                let metadata = serde_json::json!({ "issuer": base, "jwks_uri": jwks_uri.as_str() });
                vec![(
                    "/.well-known/oauth-authorization-server",
                    metadata.to_string(),
                )]
            })
            .await;
        let section = AuthSection {
            issuer: std::collections::BTreeMap::from([(
                String::from("i1"),
                IssuerEntry {
                    issuer: SecretUrl::new(issuer.as_str().trim_end_matches('/')),
                    kind: Some(IssuerKind::Smart),
                    audience: vec![crate::support::AUDIENCE.to_owned()],
                    ..IssuerEntry::default()
                },
            )]),
            tls: ferrohealth_config::tls::TlsClientSection {
                trust_roots_file: Some(root.roots.path().to_path_buf()),
                ..ferrohealth_config::tls::TlsClientSection::default()
            },
            ..AuthSection::default()
        };
        let settings = section
            .resolve_with_tls(&ferrohealth_smart::config::ServerTls, &[])
            .expect("resolves")
            .issuers
            .into_iter()
            .next()
            .expect("one issuer");
        match ResourceServer::discover(settings).await {
            Ok(_) => assert!(!revoked, "a revoked key set host is never read"),
            Err(ResourceError::Discovery(DiscoveryError::Transport { url, .. })) => {
                assert!(revoked, "a key set host its CRL holds good is read");
                assert_eq!(
                    jwks_uri, url,
                    "the metadata is read and the key set refused"
                );
            }
            Err(other) => panic!("revoked {revoked}: {other:?}"),
        }
    }
}
