// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The remote decision point over a product's own HTTP client: the client's
//! TLS reaches the point, and a call is tried again under the endpoint's
//! `retry` table when the point was not reached or answered a `5xx`.
//!
//! No specification governs the retry rule: our own design (#401).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use ferrohealth_authz::engine::AuthzError;
use ferrohealth_authz::engine::PolicyEngine;
use ferrohealth_authz::remote::Binding;
use ferrohealth_authz::remote::RemotePdp;
use ferrohealth_authz::remote::RemoteSettings;
use ferrohealth_authz::request::Attr;
use ferrohealth_authz::request::Request;
use ferrohealth_authz::request::Subject;
use ferrohealth_config::units;
use ferrohealth_smart::client::outbound::OutboundClient;
use ferrohealth_smart::config::endpoint::EndpointSection;
use ferrohealth_smart::config::endpoint::RetrySection;
use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::IsCa;
use rcgen::Issuer;
use rcgen::KeyPair;
use rustls::ServerConfig;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::PrivatePkcs8KeyDer;
use tokio::io::AsyncReadExt as _;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use url::Url;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::header;
use wiremock::matchers::method;
use wiremock::matchers::path;

fn settings(server: &str) -> RemoteSettings {
    RemoteSettings {
        server: Url::parse(&format!("{server}/pdp/")).expect("a URL"),
        bindings: BTreeMap::from([(
            String::from("Composition"),
            Binding {
                policy: String::from("composition"),
                parameters: vec![String::from("patient")],
            },
        )]),
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(2),
    }
}

fn retry(max_attempts: u32, initial_ms: u64, max_ms: u64) -> RetrySection {
    RetrySection {
        max_attempts,
        initial_backoff: units::Duration::from_millis(initial_ms),
        max_backoff: units::Duration::from_millis(max_ms),
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("a client")
}

fn pdp(server: &MockServer, retry: RetrySection) -> RemotePdp {
    RemotePdp::with_client(settings(&server.uri()), client(), retry, None).expect("a point")
}

async fn decide(pdp: &RemotePdp) -> Result<bool, AuthzError> {
    let subject = Subject::new("dr-a");
    let request = Request::new(&subject, "composition.read", "Composition")
        .with_attribute("patient", Attr::One(String::from("p-1")))
        .expect("a request");
    pdp.decide(&request)
        .await
        .map(|decision| decision.is_permit())
}

async fn calls(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .expect("the server records requests")
        .len()
}

#[tokio::test]
async fn a_server_error_is_tried_again_until_the_point_decides() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/pdp/composition"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(2)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/pdp/composition"))
        .respond_with(ResponseTemplate::new(200))
        .with_priority(2)
        .mount(&server)
        .await;
    let pdp = pdp(&server, retry(3, 10, 20));
    assert!(
        decide(&pdp).await.expect("decides"),
        "the third try permits"
    );
    assert_eq!(calls(&server).await, 3);
}

#[tokio::test]
async fn a_server_error_on_every_try_is_no_decision_after_max_attempts() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/pdp/composition"))
        .respond_with(ResponseTemplate::new(502))
        .mount(&server)
        .await;
    let pdp = pdp(&server, retry(3, 10, 20));
    assert!(matches!(decide(&pdp).await, Err(AuthzError::Remote(_))));
    assert_eq!(calls(&server).await, 3);
}

#[tokio::test]
async fn a_timed_out_try_is_tried_again() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/pdp/composition"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/pdp/composition"))
        .respond_with(ResponseTemplate::new(200))
        .with_priority(2)
        .mount(&server)
        .await;
    let mut settings = settings(&server.uri());
    settings.request_timeout = Duration::from_millis(200);
    let pdp = RemotePdp::with_client(settings, client(), retry(2, 10, 10), None).expect("a point");
    assert!(
        decide(&pdp).await.expect("decides"),
        "the second try permits"
    );
    assert_eq!(calls(&server).await, 2);
}

#[tokio::test]
async fn a_client_error_and_a_redirect_are_tried_once() {
    for status in [403, 302] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/pdp/composition"))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        let pdp = pdp(&server, retry(3, 10, 20));
        let outcome = decide(&pdp).await;
        if status == 403 {
            assert!(!outcome.expect("a 4xx decides"), "a 4xx denies");
        } else {
            assert!(matches!(outcome, Err(AuthzError::Remote(_))), "{outcome:?}");
        }
        assert_eq!(calls(&server).await, 1, "{status} is tried once");
    }
}

#[tokio::test]
async fn the_backoff_doubles_up_to_its_bound() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/pdp/composition"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let pdp = pdp(&server, retry(4, 100, 150));
    let started = Instant::now();
    assert!(matches!(decide(&pdp).await, Err(AuthzError::Remote(_))));
    assert_eq!(calls(&server).await, 4);
    // The waits are 100 ms, then 200 ms capped at 150 ms, then 150 ms.
    assert!(
        started.elapsed() >= Duration::from_millis(400),
        "waited {:?}",
        started.elapsed()
    );
}

#[test]
fn a_retry_table_the_section_refuses_is_refused() {
    for refused in [retry(0, 10, 20), retry(2, 30, 20)] {
        assert!(matches!(
            RemotePdp::with_client(settings("http://127.0.0.1:9"), client(), refused, None),
            Err(AuthzError::Remote(_))
        ));
    }
}

/// A decision point on loopback over TLS, its certificate issued by a fresh
/// authority, answering every call `200`; returns its URL and the
/// authority's certificate.
async fn tls_point() -> (String, reqwest::Certificate) {
    let ca_key = KeyPair::generate().expect("a key pair");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("parameters");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_certificate = ca_params.self_signed(&ca_key).expect("the authority signs");
    let issuer = Issuer::new(ca_params, ca_key);
    let server_key = KeyPair::generate().expect("a key pair");
    let server_certificate = CertificateParams::new(vec![String::from("localhost")])
        .expect("parameters")
        .signed_by(&server_key, &issuer)
        .expect("the server certificate signs");
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der()));
    let config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("the protocol versions")
    .with_no_client_auth()
    .with_single_cert(vec![server_certificate.der().clone()], key)
    .expect("the server certificate");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = listener.local_addr().expect("an address").port();
    drop(tokio::spawn(async move {
        while let Ok((stream, _peer)) = listener.accept().await {
            let Ok(mut stream) = acceptor.accept(stream).await else {
                continue;
            };
            let mut seen = Vec::new();
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = stream.read(&mut buffer).await {
                if read == 0 {
                    break;
                }
                seen.extend_from_slice(buffer.get(..read).unwrap_or_default());
                if complete(&seen) {
                    break;
                }
            }
            let answer = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
            drop(stream.write_all(answer).await);
            drop(stream.shutdown().await);
        }
    }));
    let authority = reqwest::Certificate::from_der(ca_certificate.der()).expect("a certificate");
    (format!("https://localhost:{port}"), authority)
}

/// Whether `seen` holds a whole request: its head and the body its
/// `content-length` announces.
fn complete(seen: &[u8]) -> bool {
    let text = String::from_utf8_lossy(seen);
    let Some((head, body)) = text.split_once("\r\n\r\n") else {
        return false;
    };
    let length = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    body.len() >= length
}

#[tokio::test]
async fn the_callers_client_carries_its_tls_to_the_point() {
    let (url, authority) = tls_point().await;
    let trusting = reqwest::Client::builder()
        .tls_certs_only([authority])
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("a client");
    let pdp =
        RemotePdp::with_client(settings(&url), trusting, retry(1, 10, 10), None).expect("a point");
    assert!(
        decide(&pdp).await.expect("decides"),
        "the point the client trusts permits"
    );
    let own = RemotePdp::new(settings(&url), None).expect("a point");
    assert!(
        matches!(decide(&own).await, Err(AuthzError::Remote(_))),
        "the crate's own client does not trust the point's authority"
    );
}

/// A product's reader of a `tls` table in the tests: a configuration with
/// no roots, since every case reaches its point over `http`.
#[derive(Debug)]
struct NoTls;

impl ferrohealth_smart::config::TlsBuilder for NoTls {
    fn build(
        &self,
        _key: &str,
        _section: &ferrohealth_config::tls::TlsClientSection,
        _endpoints: &[Url],
    ) -> Result<ferrohealth_smart::client::PresentedTls, Box<dyn std::error::Error + Send + Sync>>
    {
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        Ok(ferrohealth_smart::client::PresentedTls::new(
            Arc::new(config),
            None,
        ))
    }
}

fn outbound(server: &MockServer, extra: &str) -> OutboundClient {
    let endpoint: EndpointSection = toml::from_str(&format!(
        "url = \"{}/pdp/\"\n[retry]\nmax_attempts = 3\ninitial_backoff = \"10ms\"\nmax_backoff = \"20ms\"\n{extra}",
        server.uri()
    ))
    .expect("the table parses");
    OutboundClient::build(&endpoint, "authz.abac.remote.endpoint", &NoTls).expect("a client")
}

fn bindings() -> BTreeMap<String, Binding> {
    settings("http://unused.invalid").bindings
}

#[tokio::test]
async fn a_point_from_the_outbound_client_sends_its_basic_credential_and_retries() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/pdp/composition"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/pdp/composition"))
        // NOTE: RFC 7617 §2, base64 of "Qz7-pep:Qz7-pass".
        .and(header("authorization", "Basic UXo3LXBlcDpRejctcGFzcw=="))
        .respond_with(ResponseTemplate::new(200))
        .with_priority(2)
        .mount(&server)
        .await;
    let client = outbound(
        &server,
        "[credentials]\nuser = \"Qz7-pep\"\npassword = \"Qz7-pass\"\n",
    );
    let pdp = RemotePdp::from_outbound(bindings(), &client).expect("a point");
    assert!(
        decide(&pdp).await.expect("decides"),
        "the second try permits"
    );
    assert_eq!(calls(&server).await, 2);
}

#[tokio::test]
async fn a_point_from_the_outbound_client_carries_its_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "Qz7-token", "token_type": "Bearer", "expires_in": 300
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/pdp/composition"))
        .and(header("authorization", "Bearer Qz7-token"))
        .respond_with(ResponseTemplate::new(403))
        .expect(1)
        .mount(&server)
        .await;
    let client = outbound(
        &server,
        &format!(
            "[credentials.oauth]\ntoken_endpoint = \"{}/token\"\nclient_id = \"Qz7-pep\"\nclient_secret = \"Qz7-secret\"\n",
            server.uri()
        ),
    );
    let pdp = RemotePdp::from_outbound(bindings(), &client).expect("a point");
    assert!(!decide(&pdp).await.expect("decides"), "a 403 denies");
}
