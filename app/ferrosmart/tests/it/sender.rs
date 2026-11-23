// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Sender-constrained tokens at issuance: a `DPoP` proof at the token
//! endpoint (RFC 9449 §5) and the client certificate of a mutual-TLS
//! connection (RFC 8705 §3), each bound into the token's `cnf`.

use std::sync::Arc;

use axum::body::Body;
use base64::Engine as _;
use ferrohealth_server::tls::PeerCertificates;
use ferrohealth_smart::client::dpop::{DpopKey, Role};
use ferrosmart::store::grant::Access;
use http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt as _;
use rustls::pki_types::CertificateDer;
use serde_json::{Value, json};
use sqlx::Connection as _;
use tower::ServiceExt as _;

use crate::introspection::{Answer, ISSUER, Server};
use crate::support::from_client;

/// Returns a fresh P-256 `DPoP` key.
fn dpop_key() -> DpopKey {
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("a key");
    DpopKey::from_pem(pair.serialize_pem().as_bytes()).expect("a DPoP key")
}

/// Returns a proof of `key` for a token request.
fn proof(key: &DpopKey) -> String {
    let url = url::Url::parse(&format!("{ISSUER}/token")).expect("a URL");
    key.proof(&Method::POST, &url, Role::Authorization, None)
        .expect("a proof")
}

/// Returns a self-signed client certificate in DER form.
fn certificate() -> Vec<u8> {
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("a key");
    rcgen::CertificateParams::new(vec![String::from("export.example.org")])
        .expect("params")
        .self_signed(&pair)
        .expect("a certificate")
        .der()
        .to_vec()
}

/// Returns the base64url SHA-256 of `der` (RFC 8705 §3.1).
fn thumbprint(der: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, der))
}

/// Posts `form` to the token endpoint with `dpop` as the `DPoP` header and
/// `certificate` as the connection's client certificate.
async fn post(
    server: &Server,
    form: &[(String, String)],
    dpop: Option<&str>,
    certificate: Option<&[u8]>,
) -> Answer {
    let body: String = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form)
        .finish();
    let mut request =
        Request::post("/token").header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(dpop) = dpop {
        request = request.header("DPoP", dpop);
    }
    let mut request = request.body(Body::from(body)).expect("a request");
    if let Some(der) = certificate {
        let chain: Arc<[CertificateDer<'static>]> =
            Arc::from(vec![CertificateDer::from(der.to_vec())]);
        request.extensions_mut().insert(PeerCertificates(chain));
    }
    let response = server
        .app
        .clone()
        .oneshot(from_client(request))
        .await
        .expect("an answer");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("the body")
        .to_bytes();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Returns the client credentials form of `export`.
fn backend(server: &Server) -> Vec<(String, String)> {
    let mut form = server.credentials("export");
    form.extend([
        (
            String::from("grant_type"),
            String::from("client_credentials"),
        ),
        (String::from("scope"), String::from("system/Patient.rs")),
    ]);
    form
}

/// Returns the claims of the JWT `token`, unverified.
fn claims(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("a JWT");
    serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("base64url"),
    )
    .expect("JSON")
}

/// Runs `statement` against the case's database.
async fn execute(server: &Server, statement: &str) {
    let mut connection = sqlx::PgConnection::connect(&server.database_url())
        .await
        .expect("connects");
    sqlx::query(sqlx::AssertSqlSafe(statement.to_owned()))
        .execute(&mut connection)
        .await
        .expect("executes");
}

// NOTE: RFC 9449 §5, a valid proof gets a token of type DPoP whose `cnf.jkt` is
// the proof key's thumbprint (§6.1), and introspection carries it (§6.2).
#[tokio::test]
async fn a_dpop_proof_binds_the_token_to_its_key() {
    let server = Server::start().await;
    let key = dpop_key();
    let (status, _, body) = post(&server, &backend(&server), Some(&proof(&key)), None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    assert_eq!(json!("DPoP"), body["token_type"]);
    let token = body["access_token"].as_str().expect("a token");
    assert_eq!(json!({"jkt": key.thumbprint()}), claims(token)["cnf"]);
    assert_eq!(
        json!({"jkt": key.thumbprint()}),
        server.introspect(token).await["cnf"]
    );
    let (status, _, body) = post(&server, &backend(&server), None, None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    assert_eq!(json!("bearer"), body["token_type"], "no proof, no binding");
    let token = body["access_token"].as_str().expect("a token");
    assert_eq!(Value::Null, claims(token)["cnf"]);
    server.stop().await;
}

// NOTE: RFC 9449 §4.3 and §11.1, a proof is checked against this request and used
// once; a failed check is `invalid_dpop_proof` (§5).
#[tokio::test]
async fn a_replayed_or_misdirected_proof_is_refused() {
    let server = Server::start().await;
    let key = dpop_key();
    let used = proof(&key);
    let (status, _, _) = post(&server, &backend(&server), Some(&used), None).await;
    assert_eq!(StatusCode::OK, status);
    let elsewhere = key
        .proof(
            &Method::POST,
            &url::Url::parse(&format!("{ISSUER}/introspect")).expect("a URL"),
            Role::Authorization,
            None,
        )
        .expect("a proof");
    for presented in [used.as_str(), elsewhere.as_str(), "not.a.proof"] {
        let (status, _, body) = post(&server, &backend(&server), Some(presented), None).await;
        assert_eq!(StatusCode::BAD_REQUEST, status, "{body}");
        assert_eq!(json!("invalid_dpop_proof"), body["error"]);
    }
    server.stop().await;
}

// NOTE: RFC 9449 §5.2, a client registered with `dpop_bound_access_tokens` sends
// a proof with every token request.
#[tokio::test]
async fn a_client_bound_to_dpop_is_refused_a_request_without_a_proof() {
    let server = Server::start().await;
    execute(
        &server,
        "UPDATE client SET dpop_bound_access_tokens = true WHERE client_id = 'export'",
    )
    .await;
    let (status, _, body) = post(&server, &backend(&server), None, None).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{body}");
    assert_eq!(json!("invalid_request"), body["error"]);
    let (status, _, body) = post(&server, &backend(&server), Some(&proof(&dpop_key())), None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    server.stop().await;
}

// NOTE: RFC 9449 §5, a public client's refresh token is bound to the key of the
// proof it was issued with, and used only with a proof of that key.
#[tokio::test]
async fn a_public_clients_refresh_token_is_used_with_its_key_alone() {
    let server = Server::start().await;
    let key = dpop_key();
    let grant = server
        .grant(
            "app",
            Some(Access::Offline),
            None,
            &json!({"patient": "123"}),
        )
        .await;
    execute(
        &server,
        &format!(
            "UPDATE authorization_grant SET dpop_jkt = '{}' WHERE id = '{grant}'",
            key.thumbprint()
        ),
    )
    .await;
    let token = server.refresh(&grant, 3600).await;
    let form = vec![
        (String::from("grant_type"), String::from("refresh_token")),
        (String::from("refresh_token"), token),
        (String::from("client_id"), String::from("app")),
    ];
    for other in [None, Some(proof(&dpop_key()))] {
        let (status, _, body) = post(&server, &form, other.as_deref(), None).await;
        assert_eq!(StatusCode::BAD_REQUEST, status, "{body}");
        assert_eq!(json!("invalid_grant"), body["error"]);
    }
    let (status, _, body) = post(&server, &form, Some(&proof(&key)), None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    assert_eq!(json!("DPoP"), body["token_type"]);
    let access = body["access_token"].as_str().expect("a token");
    assert_eq!(json!({"jkt": key.thumbprint()}), claims(access)["cnf"]);
    server.stop().await;
}

// NOTE: RFC 8705 §3.1, a certificate-bound token carries the client certificate's
// `x5t#S256`; §3.4 leaves a connection without one to the server, which refuses.
#[tokio::test]
async fn a_client_bound_to_its_certificate_gets_a_certificate_bound_token() {
    let server = Server::start().await;
    execute(
        &server,
        "UPDATE client SET tls_client_certificate_bound_access_tokens = true \
         WHERE client_id = 'export'",
    )
    .await;
    let (status, _, body) = post(&server, &backend(&server), None, None).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{body}");
    assert_eq!(json!("invalid_request"), body["error"]);
    let der = certificate();
    let (status, _, body) = post(&server, &backend(&server), None, Some(&der)).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    assert_eq!(json!("bearer"), body["token_type"]);
    let token = body["access_token"].as_str().expect("a token");
    let bound = json!({"x5t#S256": thumbprint(&der)});
    assert_eq!(bound, claims(token)["cnf"]);
    assert_eq!(bound, server.introspect(token).await["cnf"]);
    server.stop().await;
}

// NOTE: RFC 9449 §5.1, the algorithms the token endpoint takes a proof in; RFC
// 8705 §3.3, certificate-bound tokens only over a listener that asks for a
// certificate.
#[tokio::test]
async fn the_metadata_names_the_proof_algorithms() {
    let server = Server::start().await;
    let path = server.settings().metadata_path();
    let (status, _, metadata) = server.call(Method::GET, &path, None, None).await;
    assert_eq!(StatusCode::OK, status);
    let algorithms = metadata["dpop_signing_alg_values_supported"]
        .as_array()
        .expect("a list");
    assert!(algorithms.contains(&json!("ES256")), "{algorithms:?}");
    assert_eq!(
        json!(false),
        metadata["tls_client_certificate_bound_access_tokens"]
    );
    server.stop().await;
}
