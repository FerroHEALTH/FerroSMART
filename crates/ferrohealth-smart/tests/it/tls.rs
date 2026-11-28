// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A token endpoint over TLS that requires a client certificate (RFC 8705
//! §2), for the mutual-TLS cases.
//!
//! The certificate authority, the server certificate and the client
//! certificate are generated when the case runs and live only in memory.

use std::sync::Arc;
use std::sync::Mutex;

use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::Issuer;
use rcgen::KeyPair;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::server::WebPkiClientVerifier;
use tokio::io::AsyncReadExt as _;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// One token request the endpoint answered.
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    /// Whether the client presented a certificate in the handshake.
    pub(crate) certificate: bool,
    /// The form-encoded request body.
    pub(crate) body: String,
}

/// The material of one case and the endpoint that requires it.
pub(crate) struct MutualTls {
    /// The token endpoint URL.
    pub(crate) url: String,
    /// The certificate authority every certificate chains to, in PEM.
    pub(crate) ca_pem: String,
    /// The client certificate, in PEM.
    pub(crate) client_certificate_pem: String,
    /// The client certificate's private key, in PEM.
    pub(crate) client_key_pem: String,
    /// Every request the endpoint answered.
    pub(crate) seen: Arc<Mutex<Vec<Seen>>>,
}

impl MutualTls {
    /// Returns every request the endpoint answered.
    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .expect("the record is not poisoned")
            .clone()
    }
}

/// Returns the validity of a certificate: from yesterday for thirty days,
/// inside every platform verifier's limits.
fn validity(params: &mut CertificateParams) {
    let today = jiff::Zoned::now().date();
    let from = today.yesterday().expect("a date");
    let until = today
        .checked_add(jiff::Span::new().days(30))
        .expect("a date");
    let ymd = |date: jiff::civil::Date| {
        rcgen::date_time_ymd(
            i32::from(date.year()),
            u8::try_from(date.month()).expect("a month"),
            u8::try_from(date.day()).expect("a day"),
        )
    };
    params.not_before = ymd(from);
    params.not_after = ymd(until);
}

/// Starts a token endpoint on loopback that requires a client certificate
/// chaining to a fresh certificate authority, and answers every request
/// with the access token `token`.
pub(crate) async fn start(token: &str) -> MutualTls {
    let ca_key = KeyPair::generate().expect("a key pair");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("parameters");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    validity(&mut ca_params);
    let ca_certificate = ca_params.self_signed(&ca_key).expect("the authority signs");
    let issuer = Issuer::new(ca_params, ca_key);

    let server_key = KeyPair::generate().expect("a key pair");
    let mut server_params =
        CertificateParams::new(vec![String::from("localhost")]).expect("parameters");
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    validity(&mut server_params);
    let server_certificate = server_params
        .signed_by(&server_key, &issuer)
        .expect("the server certificate signs");

    let client_key = KeyPair::generate().expect("a key pair");
    let mut client_params =
        CertificateParams::new(vec![String::from("ferrofed.invalid")]).expect("parameters");
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    validity(&mut client_params);
    let client_certificate = client_params
        .signed_by(&client_key, &issuer)
        .expect("the client certificate signs");

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = RootCertStore::empty();
    roots
        .add(ca_certificate.der().clone())
        .expect("the authority is a root");
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
            .build()
            .expect("a client verifier");
    let chain: Vec<CertificateDer<'static>> = vec![server_certificate.der().clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der()));
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the protocol versions")
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .expect("the server certificate");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = listener.local_addr().expect("an address").port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let answer = serde_json::json!({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 300,
    })
    .to_string();
    drop(tokio::spawn(serve(
        listener,
        acceptor,
        Arc::clone(&seen),
        answer,
    )));
    MutualTls {
        url: format!("https://localhost:{port}/token"),
        ca_pem: ca_certificate.pem(),
        client_certificate_pem: client_certificate.pem(),
        client_key_pem: client_key.serialize_pem(),
        seen,
    }
}

/// Answers every connection on `listener` that completes the handshake.
async fn serve(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    seen: Arc<Mutex<Vec<Seen>>>,
    answer: String,
) {
    while let Ok((tcp, _peer)) = listener.accept().await {
        let acceptor = acceptor.clone();
        let seen = Arc::clone(&seen);
        let answer = answer.clone();
        drop(tokio::spawn(async move {
            let Ok(mut stream) = acceptor.accept(tcp).await else {
                return;
            };
            let certificate = stream
                .get_ref()
                .1
                .peer_certificates()
                .is_some_and(|chain| !chain.is_empty());
            let Some(body) = read_request(&mut stream).await else {
                return;
            };
            seen.lock()
                .expect("the record is not poisoned")
                .push(Seen { certificate, body });
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{answer}",
                answer.len()
            );
            if stream.write_all(response.as_bytes()).await.is_ok() {
                drop(stream.shutdown().await);
            }
        }));
    }
}

/// Returns the body of the one HTTP/1.1 request on `stream`.
async fn read_request(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Option<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(chunk.get(..read)?);
        let text = String::from_utf8_lossy(&buffer).into_owned();
        if let Some(end) = text.find("\r\n\r\n") {
            let length = text
                .get(..end)?
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            let start = end + 4;
            if buffer.len() >= start + length {
                let body = buffer.get(start..start + length)?;
                return Some(String::from_utf8_lossy(body).into_owned());
            }
        }
    }
}

/// An authorization server on loopback over TLS, its certificate chaining to
/// a fresh certificate authority no platform trusts.
pub(crate) struct PrivateIssuer {
    /// The issuer identifier, `https://<host>:<port>`.
    pub(crate) issuer: String,
    /// The certificate authority its certificate chains to, in PEM.
    pub(crate) ca_pem: String,
}

/// Starts an authorization server answering its RFC 8414 metadata and the
/// key set holding `jwk`, with no client certificate asked.
pub(crate) async fn start_issuer(jwk: serde_json::Value) -> PrivateIssuer {
    start_issuer_at(jwk, "localhost", rustls::DEFAULT_VERSIONS).await
}

/// Starts the authorization server of [`start_issuer`] under the host name
/// `host`, on loopback, speaking only the TLS `versions`.
pub(crate) async fn start_issuer_at(
    jwk: serde_json::Value,
    host: &str,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> PrivateIssuer {
    let ca_key = KeyPair::generate().expect("a key pair");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("parameters");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    validity(&mut ca_params);
    let ca_certificate = ca_params.self_signed(&ca_key).expect("the authority signs");
    let issuer_ca = Issuer::new(ca_params, ca_key);
    let server_key = KeyPair::generate().expect("a key pair");
    let mut server_params = CertificateParams::new(vec![host.to_owned()]).expect("parameters");
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    validity(&mut server_params);
    let server_certificate = server_params
        .signed_by(&server_key, &issuer_ca)
        .expect("the server certificate signs");
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let chain: Vec<CertificateDer<'static>> = vec![server_certificate.der().clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der()));
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .expect("the protocol versions")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("the server certificate");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = listener.local_addr().expect("an address").port();
    let issuer = format!("https://{host}:{port}");
    let metadata = serde_json::json!({
        "issuer": issuer,
        "jwks_uri": format!("{issuer}{}", crate::support::JWKS_PATH),
        "token_endpoint": format!("{issuer}{}", crate::support::TOKEN_PATH),
    })
    .to_string();
    let keys = serde_json::json!({ "keys": [jwk] }).to_string();
    drop(tokio::spawn(serve_issuer(
        listener, acceptor, metadata, keys,
    )));
    PrivateIssuer {
        issuer,
        ca_pem: ca_certificate.pem(),
    }
}

/// Answers the metadata at its RFC 8414 location and the key set at
/// `JWKS_PATH`, and `404` for anything else.
async fn serve_issuer(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    metadata: String,
    keys: String,
) {
    while let Ok((tcp, _peer)) = listener.accept().await {
        let acceptor = acceptor.clone();
        let metadata = metadata.clone();
        let keys = keys.clone();
        drop(tokio::spawn(async move {
            let Ok(mut stream) = acceptor.accept(tcp).await else {
                return;
            };
            let mut head = Vec::new();
            let mut chunk = [0u8; 4096];
            while !String::from_utf8_lossy(&head).contains("\r\n\r\n") {
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(read) => head.extend_from_slice(chunk.get(..read).unwrap_or_default()),
                }
            }
            let text = String::from_utf8_lossy(&head).into_owned();
            let path = text
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_owned();
            let (status, body) = if path == "/.well-known/oauth-authorization-server" {
                ("200 OK", metadata)
            } else if path == crate::support::JWKS_PATH {
                ("200 OK", keys)
            } else {
                ("404 Not Found", String::from("{}"))
            };
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            if stream.write_all(response.as_bytes()).await.is_ok() {
                drop(stream.shutdown().await);
            }
        }));
    }
}

/// The configuration a product builds over the PEM trust roots `ca_pem`,
/// presenting the PEM `identity` (certificate, key) when one is given, as
/// `ferrohealth-server`'s `TlsClient::client_config` would.
pub(crate) fn presented_pem(
    ca_pem: &str,
    identity: Option<(&str, &str)>,
) -> Result<ferrohealth_smart::client::PresentedTls, Box<dyn std::error::Error + Send + Sync>> {
    use rustls::pki_types::pem::PemObject as _;
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots.add(certificate?)?;
    }
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots);
    let Some((certificate, key)) = identity else {
        return Ok(ferrohealth_smart::client::PresentedTls::new(
            Arc::new(builder.with_no_client_auth()),
            None,
        ));
    };
    let certificate = CertificateDer::from_pem_slice(certificate.as_bytes())?;
    let key = PrivateKeyDer::from_pem_slice(key.as_bytes())?;
    let config = builder.with_client_auth_cert(vec![certificate.clone()], key)?;
    Ok(ferrohealth_smart::client::PresentedTls::new(
        Arc::new(config),
        Some(certificate),
    ))
}

/// A product's reader of a `tls` table in the tests: the PEM files it names
/// read into [`presented_pem`]; the identity file holds the certificate and
/// then the key.
#[derive(Debug, Default)]
pub(crate) struct PemTls;

impl ferrohealth_smart::config::TlsBuilder for PemTls {
    fn build(
        &self,
        _key: &str,
        section: &ferrohealth_config::tls::TlsClientSection,
        _endpoints: &[url::Url],
    ) -> Result<ferrohealth_smart::client::PresentedTls, Box<dyn std::error::Error + Send + Sync>>
    {
        let roots = match &section.trust_roots_file {
            Some(path) => std::fs::read_to_string(path)?,
            None => String::new(),
        };
        let identity = match &section.client_identity_file {
            Some(path) => Some(std::fs::read_to_string(path)?),
            None => None,
        };
        let split = identity.as_deref().map(|pem| {
            let at = pem.find("-----BEGIN PRIVATE KEY-----").unwrap_or(pem.len());
            pem.split_at(at)
        });
        presented_pem(&roots, split)
    }
}

/// The configuration a product builds over the PEM trust roots `ca_pem`,
/// presenting `identity`, a PEM certificate followed by its key.
pub(crate) fn presented_identity(
    ca_pem: &str,
    identity: &str,
) -> Result<ferrohealth_smart::client::PresentedTls, Box<dyn std::error::Error + Send + Sync>> {
    let at = identity
        .find("-----BEGIN PRIVATE KEY-----")
        .ok_or("the identity holds a PKCS #8 key")?;
    presented_pem(ca_pem, Some(identity.split_at(at)))
}

/// A product's reader of a `tls` table in the tests that hands back one
/// configuration it built already.
#[derive(Debug)]
pub(crate) struct Built(pub(crate) ferrohealth_smart::client::PresentedTls);

impl ferrohealth_smart::config::TlsBuilder for Built {
    fn build(
        &self,
        _key: &str,
        _section: &ferrohealth_config::tls::TlsClientSection,
        _endpoints: &[url::Url],
    ) -> Result<ferrohealth_smart::client::PresentedTls, Box<dyn std::error::Error + Send + Sync>>
    {
        Ok(self.0.clone())
    }
}
