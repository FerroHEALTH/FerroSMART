// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The TLS 1.3 key exchange of FerroSMART's listener and of every client it
//! builds: each agrees on X25519MLKEM768 (RFC 10024) with a peer that offers
//! it, and on X25519 with a classical-only peer (RFC 8446 §4.2.7).
//!
//! The peer offers only the groups a case names, and records the group of
//! each connection after its first flight; its certificate is trusted by no
//! root, so each call ends after the key exchange.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use rustls::crypto::{CryptoProvider, SupportedKxGroup, aws_lc_rs};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, NamedGroup, ServerConfig, ServerConnection};

/// How long a case waits for a connection to be recorded.
const RECORD_WAIT: Duration = Duration::from_secs(10);

/// A TLS 1.3 peer on a loopback port that offers only the groups it was
/// started with, and records the group of each connection.
struct KxPeer {
    /// Its address.
    address: SocketAddr,
    /// The group of each connection, in order.
    agreed: Arc<Mutex<Vec<Option<NamedGroup>>>>,
}

impl KxPeer {
    /// Starts a peer that offers `groups`.
    fn start(groups: Vec<&'static dyn SupportedKxGroup>) -> Self {
        let key = rcgen::KeyPair::generate().expect("a key");
        let certificate = rcgen::CertificateParams::new(vec![String::from("localhost")])
            .expect("parameters")
            .self_signed(&key)
            .expect("a certificate");
        let provider = CryptoProvider {
            kx_groups: groups,
            ..aws_lc_rs::default_provider()
        };
        let config = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("TLS 1.3")
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(certificate.der().to_vec())],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                )
                .expect("the certificate serves"),
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let address = listener.local_addr().expect("an address");
        let agreed = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&agreed);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let group = serve(&config, stream);
                record
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(group);
            }
        });
        Self { address, agreed }
    }

    /// Returns the URL of the peer.
    fn url(&self) -> url::Url {
        url::Url::parse(&format!("https://{}/", self.address)).expect("a URL")
    }

    /// Returns the group of the first connection, waiting until it is
    /// recorded.
    fn first(&self) -> Option<NamedGroup> {
        let deadline = Instant::now() + RECORD_WAIT;
        loop {
            if let Some(group) = self
                .agreed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .first()
            {
                return *group;
            }
            assert!(Instant::now() < deadline, "no connection reached the peer");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// Drives one connection and returns the group it agreed on.
fn serve(config: &Arc<ServerConfig>, mut stream: TcpStream) -> Option<NamedGroup> {
    let mut connection = ServerConnection::new(Arc::clone(config)).ok()?;
    stream.set_read_timeout(Some(RECORD_WAIT)).ok()?;
    stream.set_write_timeout(Some(RECORD_WAIT)).ok()?;
    let mut handshake = Ok((0, 0));
    while connection.is_handshaking() && handshake.is_ok() {
        handshake = connection.complete_io(&mut stream);
    }
    let group = connection
        .negotiated_key_exchange_group()
        .map(SupportedKxGroup::name);
    if handshake.is_ok() {
        let mut tls = rustls::Stream::new(&mut connection, &mut stream);
        let mut request = [0_u8; 4096];
        if tls.read(&mut request).is_ok() {
            let answered = tls.write_all(b"HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n");
            drop(answered);
        }
    }
    group
}

/// The groups of a peer that offers both, and of a classical-only one.
fn peers() -> [(KxPeer, NamedGroup); 2] {
    [
        (
            KxPeer::start(vec![
                aws_lc_rs::kx_group::X25519,
                aws_lc_rs::kx_group::X25519MLKEM768,
            ]),
            NamedGroup::X25519MLKEM768,
        ),
        (
            KxPeer::start(vec![aws_lc_rs::kx_group::X25519]),
            NamedGroup::X25519,
        ),
    ]
}

#[tokio::test]
async fn the_default_http_client_prefers_x25519mlkem768() {
    // NOTE: the client of a client's JWK Set, of the FHIR server and of the
    // wallet's trusted list is reqwest's default, over rustls's default provider.
    for (peer, expected) in peers() {
        let client = reqwest::Client::new();
        assert!(
            client.get(peer.url()).send().await.is_err(),
            "an untrusted peer"
        );
        assert_eq!(Some(expected), peer.first());
    }
}

#[tokio::test]
async fn the_upstream_openid_client_prefers_x25519mlkem768() {
    for (peer, expected) in peers() {
        let http =
            ferrohealth_smart::metadata::Http::new(Duration::from_secs(10)).expect("the engine");
        assert!(http.get(peer.url()).await.is_err(), "an untrusted peer");
        assert_eq!(Some(expected), peer.first());
    }
}

#[tokio::test]
async fn the_saml_and_audit_feed_tls_prefers_x25519mlkem768() {
    use ferrohealth_smart::config::TlsBuilder as _;
    for (peer, expected) in peers() {
        let presented = ferrohealth_smart::config::ServerTls
            .build(
                "ferrosmart.saml.tls",
                &ferrohealth_config::tls::TlsClientSection::default(),
            )
            .expect("the TLS of the SAML client");
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(presented.config()));
        let stream = tokio::net::TcpStream::connect(peer.address)
            .await
            .expect("the peer answers");
        let name = ServerName::try_from("localhost").expect("a name");
        assert!(
            connector.connect(name, stream).await.is_err(),
            "an untrusted peer"
        );
        assert_eq!(Some(expected), peer.first());
    }
    for (peer, expected) in peers() {
        let section: ferrohealth_smart::config::endpoint::EndpointSection = toml::from_str(
            &format!("url = {:?}\n[retry]\nmax_attempts = 1", peer.url().as_str()),
        )
        .expect("an endpoint");
        let client = ferrohealth_smart::client::outbound::OutboundClient::build(
            &section,
            "ferrosmart.audit.feed",
            &ferrohealth_smart::config::ServerTls,
        )
        .expect("the audit feed's client");
        let sent = client
            .send(&http::Method::GET, &peer.url(), |request| request)
            .await;
        assert!(sent.is_err(), "an untrusted peer");
        assert_eq!(Some(expected), peer.first());
    }
}

#[test]
fn the_default_provider_of_the_database_client_offers_x25519mlkem768_first() {
    // NOTE: sqlx builds its rustls client from the default provider, whose first group
    // rustls's prefer-post-quantum feature makes X25519MLKEM768.
    let provider = aws_lc_rs::default_provider();
    let first = provider.kx_groups.first().map(|group| group.name());
    assert_eq!(Some(NamedGroup::X25519MLKEM768), first);
    assert!(
        provider
            .kx_groups
            .iter()
            .any(|group| group.name() == NamedGroup::X25519),
        "a classical-only server is still reached"
    );
}

#[tokio::test]
async fn the_listener_agrees_on_x25519mlkem768_and_still_on_x25519() {
    let dir = tempfile::tempdir().expect("a directory");
    let key = rcgen::KeyPair::generate().expect("a key");
    let certificate = rcgen::CertificateParams::new(vec![String::from("localhost")])
        .expect("parameters")
        .self_signed(&key)
        .expect("a certificate");
    let certificate_file = dir.path().join("server.pem");
    let key_file = dir.path().join("server.key");
    std::fs::write(&certificate_file, certificate.pem()).expect("written");
    std::fs::write(&key_file, key.serialize_pem()).expect("written");
    let section: ferrohealth_server::section::TlsSection = toml::from_str(&format!(
        "certificate_file = {:?}\nkey_file = {:?}",
        certificate_file.display().to_string(),
        key_file.display().to_string()
    ))
    .expect("a TLS section");
    let served = ferrohealth_server::tls::ReloadableTls::new(&section)
        .expect("the listener's TLS")
        .current();
    let acceptor = tokio_rustls::TlsAcceptor::from(served);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let address = listener.local_addr().expect("an address");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let accepted = acceptor.accept(stream).await;
            drop(accepted);
        }
    });
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate.der().to_vec()))
        .expect("the root");
    for (group, expected) in [
        (
            aws_lc_rs::kx_group::X25519MLKEM768,
            NamedGroup::X25519MLKEM768,
        ),
        (aws_lc_rs::kx_group::X25519, NamedGroup::X25519),
    ] {
        let provider = CryptoProvider {
            kx_groups: vec![group],
            ..aws_lc_rs::default_provider()
        };
        let config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("the listener answers");
        let name = ServerName::try_from("localhost").expect("a name");
        let mut tls = connector
            .connect(name, stream)
            .await
            .expect("the handshake completes");
        let (_, connection) = tls.get_ref();
        assert_eq!(
            Some(expected),
            connection
                .negotiated_key_exchange_group()
                .map(SupportedKxGroup::name)
        );
        let closed = tokio::io::AsyncWriteExt::shutdown(&mut tls).await;
        drop(closed);
    }
}
