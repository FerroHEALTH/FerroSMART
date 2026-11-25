// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The client half of sender-constrained tokens: the `DPoP` proof of every
//! token request and resource request (RFC 9449 §4.2, §7.1), the nonces of
//! §8 and §9 answered once and kept per origin and role, the `DPoP` token
//! type (§5), and the certificate binding of RFC 8705 §3 checked before a
//! token is kept.

use std::error::Error as StdError;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use ferrohealth_smart::client::CallError;
use ferrohealth_smart::client::ClientCredentials;
use ferrohealth_smart::client::Endpoint;
use ferrohealth_smart::client::TokenError;
use ferrohealth_smart::client::assertion::AssertionKey;
use ferrohealth_smart::client::binding::IssuedToken;
use ferrohealth_smart::client::cache::TokenSource;
use ferrohealth_smart::client::dpop;
use ferrohealth_smart::client::dpop::DpopKey;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::config::credentials::OauthSection;
use http::Method;
use secrecy::SecretString;
use serde_json::Value;
use serde_json::json;
use url::Url;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::Request;
use wiremock::ResponseTemplate;
use wiremock::matchers::method;
use wiremock::matchers::path;

use crate::support::ec_key;
use crate::support::temp_file;

/// The token endpoint path every stub serves.
const TOKEN_PATH: &str = "/oauth/token";

/// The resource path the calls reach.
const RESOURCE_PATH: &str = "/fhir/Patient";

/// The example token of RFC 9449 §7.1, Figure 13.
const TOKEN: &str = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";

type TestResult = Result<(), Box<dyn StdError>>;

/// Returns a `DPoP` key on the curve of `alg`.
fn dpop_key(alg: ferrohealth_smart::jws::algorithm::Algorithm) -> Arc<DpopKey> {
    Arc::new(DpopKey::from_pem(&ec_key("dpop", alg).pem).expect("the DPoP key reads"))
}

/// Returns a grant against the token endpoint of `server`, bound to `key`.
fn grant(server: &MockServer, key: &Arc<DpopKey>) -> Result<ClientCredentials, Box<dyn StdError>> {
    let mut config = ClientCredentials::new(
        Endpoint::Token(format!("{}{TOKEN_PATH}", server.uri()).parse()?),
        String::from("bridge"),
        SecretString::from("synthetic-secret"),
    )
    .with_dpop(Arc::clone(key));
    config.timeout = Duration::from_secs(5);
    Ok(config)
}

/// Returns the token response issuing `token` of `token_type`.
fn issued(token: &str, token_type: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "access_token": token, "token_type": token_type, "expires_in": 300
    }))
}

/// Returns the verified header and claims of the `DPoP` proof `request`
/// carries, its signature checked with the key its header names.
fn proof_of(request: &Request) -> (ferrohealth_smart::jws::compact::Header, Value) {
    let proof = request
        .headers
        .get("dpop")
        .and_then(|value| value.to_str().ok())
        .expect("the request carries a DPoP proof");
    let jws = ferrohealth_smart::jws::compact::decode(proof).expect("the proof reads");
    let header = jws.header().clone();
    let jwk = header.jwk.as_ref().expect("the proof names its key");
    let claims = jws
        .verify_claims(jwk)
        .expect("the proof verifies with its own key");
    (header, Value::Object(claims))
}

/// Returns the requests `server` received on `route`.
async fn on(server: &MockServer, route: &str) -> Vec<Request> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|request| request.url.path() == route)
        .collect()
}

#[tokio::test]
async fn every_token_request_carries_a_proof_and_takes_a_dpop_token() -> TestResult {
    for alg in [
        ferrohealth_smart::jws::algorithm::Algorithm::Es256,
        ferrohealth_smart::jws::algorithm::Algorithm::Es384,
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(TOKEN_PATH))
            .respond_with(issued(TOKEN, "DPoP"))
            .mount(&server)
            .await;
        let key = dpop_key(alg);
        let source = TokenSource::new(grant(&server, &key)?)?;
        let token = source.token().await.map_err(|error| error.to_string())?;
        assert_eq!(format!("DPoP {TOKEN}"), token.header().to_str()?);
        let requests = on(&server, TOKEN_PATH).await;
        let (header, claims) = proof_of(requests.first().ok_or("one request")?);
        // NOTE: RFC 9449 §4.2, the header and the claims of a token request's proof.
        assert_eq!(Some("dpop+jwt"), header.typ.as_deref());
        assert_eq!(alg, header.alg);
        assert_eq!(json!("POST"), claims["htm"]);
        assert_eq!(
            json!(format!("{}{TOKEN_PATH}", server.uri())),
            claims["htu"]
        );
        assert!(claims["jti"].as_str().is_some_and(|jti| !jti.is_empty()));
        assert!(claims["iat"].is_i64());
        assert!(
            claims.get("ath").is_none(),
            "a token request presents no token"
        );
        assert!(claims.get("nonce").is_none());
        assert_eq!(
            key.thumbprint(),
            header.jwk.as_ref().ok_or("a key")?.thumbprint()
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_resource_proof_carries_the_token_hash_and_no_query() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(issued(TOKEN, "dpop"))
        .mount(&server)
        .await;
    let source = TokenSource::new(grant(
        &server,
        &dpop_key(ferrohealth_smart::jws::algorithm::Algorithm::Es256),
    )?)?;
    let token = source.token().await.map_err(|error| error.to_string())?;
    let url: Url = "https://resource.example.org/fhir/Patient?name=x#frag".parse()?;
    let issued: &IssuedToken = token.as_ref().as_ref();
    let proof = issued
        .proof(&Method::GET, &url)?
        .ok_or("a DPoP token proves")?;
    let payload = proof.split('.').nth(1).ok_or("a JWS")?;
    let claims: Value =
        serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload)?)?;
    // NOTE: RFC 9449 §4.2 and §7.1, htu has no query or fragment and ath hashes
    // the token, here the Figure 13 token and its Figure 14 ath.
    assert_eq!(
        json!("https://resource.example.org/fhir/Patient"),
        claims["htu"]
    );
    assert_eq!(json!("GET"), claims["htm"]);
    assert_eq!(
        json!("fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"),
        claims["ath"]
    );
    assert_eq!(
        TOKEN,
        secrecy::ExposeSecret::expose_secret(issued.access_token())
    );
    Ok(())
}

#[tokio::test]
async fn a_token_endpoint_nonce_demand_is_answered_once_with_a_fresh_assertion() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .and(|request: &Request| proof_of(request).1.get("nonce").is_none())
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("DPoP-Nonce", "eyJ7S_zG.eyJH0-Z.HX4w-7v")
                .set_body_json(json!({
                    "error": "use_dpop_nonce",
                    "error_description": "Authorization server requires nonce in DPoP proof"
                })),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .and(|request: &Request| proof_of(request).1["nonce"] == json!("eyJ7S_zG.eyJH0-Z.HX4w-7v"))
        .respond_with(issued(TOKEN, "DPoP"))
        .mount(&server)
        .await;
    let key = dpop_key(ferrohealth_smart::jws::algorithm::Algorithm::Es256);
    let signing = ec_key(
        "client",
        ferrohealth_smart::jws::algorithm::Algorithm::Es256,
    );
    let mut config = ClientCredentials::with_private_key_jwt(
        Endpoint::Token(format!("{}{TOKEN_PATH}", server.uri()).parse()?),
        String::from("bridge"),
        AssertionKey::from_pem(
            &signing.pem,
            Some(ferrohealth_smart::jws::algorithm::Algorithm::Es256),
            None,
        )?,
    )
    .with_dpop(Arc::clone(&key));
    config.timeout = Duration::from_secs(5);
    let source = TokenSource::new(config)?;
    source.token().await.map_err(|error| error.to_string())?;
    let requests = on(&server, TOKEN_PATH).await;
    assert_eq!(2, requests.len(), "the demand is answered once");
    let assertion = |request: &Request| -> Option<String> {
        url::form_urlencoded::parse(&request.body)
            .find(|(name, _)| name == "client_assertion")
            .map(|(_, value)| value.into_owned())
    };
    let first = requests.first().and_then(assertion).ok_or("an assertion")?;
    let second = requests.get(1).and_then(assertion).ok_or("an assertion")?;
    assert_ne!(
        first, second,
        "each send signs its own assertion (RFC 7523 §3)"
    );
    let jti = |request: &Request| proof_of(request).1["jti"].clone();
    assert_ne!(
        requests.first().map(jti),
        requests.get(1).map(jti),
        "each proof has a fresh jti"
    );
    Ok(())
}

#[tokio::test]
async fn a_second_nonce_demand_is_the_refusal_it_is() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("DPoP-Nonce", "n-1")
                .set_body_json(json!({"error": "use_dpop_nonce"})),
        )
        .mount(&server)
        .await;
    let source = TokenSource::new(grant(
        &server,
        &dpop_key(ferrohealth_smart::jws::algorithm::Algorithm::Es256),
    )?)?;
    let error = source.token().await.expect_err("the second demand stands");
    assert!(matches!(
        error.as_ref(),
        TokenError::Refused { error: Some(oauth), .. } if oauth.error == dpop::USE_NONCE
    ));
    assert_eq!(2, on(&server, TOKEN_PATH).await.len(), "never a loop");
    Ok(())
}

#[tokio::test]
async fn a_bearer_token_is_refused_when_a_dpop_token_was_asked_for() -> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(issued(TOKEN, "Bearer"))
        .mount(&server)
        .await;
    let source = TokenSource::new(grant(
        &server,
        &dpop_key(ferrohealth_smart::jws::algorithm::Algorithm::Es256),
    )?)?;
    let error = source.token().await.expect_err("a bearer token is refused");
    assert!(matches!(
        error.as_ref(),
        TokenError::TokenType { found, expected: "DPoP" } if found == "Bearer"
    ));
    Ok(())
}

#[tokio::test]
async fn a_resource_nonce_demand_is_answered_once_and_kept_apart_from_the_token_endpoints()
-> TestResult {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(issued(TOKEN, "DPoP").insert_header("DPoP-Nonce", "as-nonce"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(RESOURCE_PATH))
        .and(|request: &Request| proof_of(request).1["nonce"] == json!("rs-nonce"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(RESOURCE_PATH))
        .respond_with(
            ResponseTemplate::new(401)
                .insert_header(
                    "WWW-Authenticate",
                    "DPoP error=\"use_dpop_nonce\", error_description=\"Resource server requires nonce in DPoP proof\"",
                )
                .insert_header("DPoP-Nonce", "rs-nonce"),
        )
        .mount(&server)
        .await;
    let source = TokenSource::new(grant(
        &server,
        &dpop_key(ferrohealth_smart::jws::algorithm::Algorithm::Es256),
    )?)?;
    let url: Url = format!("{}{RESOURCE_PATH}", server.uri()).parse()?;
    let client = reqwest::Client::new();
    let answered = source
        .send(&Method::GET, &url, |attempt| {
            let mut request = client
                .get(url.clone())
                .header(http::header::AUTHORIZATION, attempt.authorization().clone());
            if let Some(proof) = attempt.proof() {
                request = request.header(dpop::HEADER, proof.clone());
            }
            request.send()
        })
        .await?;
    assert_eq!(http::StatusCode::OK, answered.status());
    let resource = on(&server, RESOURCE_PATH).await;
    assert_eq!(2, resource.len(), "the demand is answered once");
    let first = proof_of(resource.first().ok_or("a request")?).1;
    // NOTE: RFC 9449 §9, the token endpoint's nonce never reaches a resource
    // server, even on one origin.
    assert!(first.get("nonce").is_none(), "{first}");
    assert_eq!(1, on(&server, TOKEN_PATH).await.len(), "the token stays");
    Ok(())
}

#[tokio::test]
async fn a_dpop_bound_source_refuses_a_call_that_cannot_prove() -> TestResult {
    let server = MockServer::start().await;
    let source = TokenSource::new(grant(
        &server,
        &dpop_key(ferrohealth_smart::jws::algorithm::Algorithm::Es256),
    )?)?;
    let outcome = source
        .call(|_header| async { Ok::<_, std::io::Error>(http::Response::new(())) })
        .await;
    assert!(matches!(outcome, Err(CallError::Unproven)));
    assert!(
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty()
    );
    Ok(())
}

/// A client certificate and its key, as the TLS identity of a grant, with the
/// certificate's RFC 8705 §3.1 thumbprint.
fn identity() -> (String, String) {
    let key = rcgen::KeyPair::generate().expect("a key");
    let certificate = rcgen::CertificateParams::new(vec![String::from("client.example.org")])
        .expect("the parameters")
        .self_signed(&key)
        .expect("a certificate");
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, certificate.der());
    let thumbprint = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref());
    let pem = format!("{}{}", certificate.pem(), key.serialize_pem());
    (pem, thumbprint)
}

/// Returns a JWT access token carrying `claims`, unsigned for the client,
/// which reads but never verifies it.
fn jwt(claims: &Value) -> String {
    let encode =
        |value: &Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string());
    format!(
        "{}.{}.c2ln",
        encode(&json!({"alg": "ES256"})),
        encode(claims)
    )
}

#[tokio::test]
async fn a_certificate_bound_grant_refuses_a_token_bound_to_another_certificate() -> TestResult {
    let (identity, ours) = identity();
    let theirs = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
    let cases: [(Value, bool, &str); 5] = [
        (
            json!({"access_token": "opaque", "token_type": "Bearer"}),
            true,
            "no stated binding",
        ),
        (
            json!({"access_token": "opaque", "token_type": "Bearer", "cnf": {"x5t#S256": ours}}),
            true,
            "the response names the certificate",
        ),
        (
            json!({"access_token": "opaque", "token_type": "Bearer", "cnf": {"x5t#S256": theirs}}),
            false,
            "the response names another",
        ),
        (
            json!({"access_token": jwt(&json!({"cnf": {"x5t#S256": theirs}})), "token_type": "Bearer"}),
            false,
            "the claim names another",
        ),
        (
            json!({"access_token": jwt(&json!({"cnf": {"jkt": "abc"}})), "token_type": "Bearer"}),
            false,
            "a DPoP confirmation",
        ),
    ];
    for (response, kept, why) in cases {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(TOKEN_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&server)
            .await;
        let mut config = ClientCredentials::with_presented_tls(
            Endpoint::Token(format!("{}{TOKEN_PATH}", server.uri()).parse()?),
            String::from("bridge"),
            crate::tls::presented_identity("", &identity).map_err(|error| error.to_string())?,
            true,
        )
        .with_certificate_binding();
        config.timeout = Duration::from_secs(5);
        let outcome = TokenSource::new(config)?.token().await;
        if kept {
            assert!(outcome.is_ok(), "{why}: {outcome:?}");
        } else {
            assert!(
                matches!(
                    outcome.as_ref().map_err(AsRef::as_ref),
                    Err(TokenError::CertificateMismatch)
                ),
                "{why}: {outcome:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn a_certificate_binding_needs_a_presented_certificate() -> TestResult {
    let config = ClientCredentials::new(
        Endpoint::Token("https://as.example.org/token".parse()?),
        String::from("bridge"),
        SecretString::from("synthetic-secret"),
    )
    .with_certificate_binding();
    assert!(matches!(
        config.validate(),
        Err(TokenError::Credential { what }) if what.contains("certificate binding")
    ));
    Ok(())
}

#[test]
fn the_oauth_table_binds_a_grant_to_a_dpop_key_or_its_certificate() -> TestResult {
    let key = temp_file(
        "dpop.pem",
        &ec_key("dpop", ferrohealth_smart::jws::algorithm::Algorithm::Es384).pem,
    );
    let section = |text: &str| -> Result<OauthSection, toml::de::Error> { toml::from_str(text) };
    let base = "token_endpoint = \"https://as.example.org/token\"\nclient_id = \"bridge\"\nclient_secret = \"synthetic-secret\"\n";
    let bound = section(&format!(
        "{base}dpop_key_file = {:?}\n",
        key.display().to_string()
    ))?
    .resolve()?;
    let dpop = bound.dpop_key().ok_or("a DPoP key")?;
    assert_eq!(
        ferrohealth_smart::jws::algorithm::Algorithm::Es384,
        dpop.algorithm()
    );
    let both = section(&format!(
        "{base}dpop_key_file = {:?}\ncertificate_bound = true\n",
        key.display().to_string()
    ))?;
    assert!(matches!(both.resolve(), Err(ConfigError::Exclusive { .. })));
    assert!(
        both.problems("cdr.credentials.oauth")
            .iter()
            .any(|problem| problem.contains("dpop_key_file"))
    );
    let unpresented = section(&format!("{base}certificate_bound = true\n"))?;
    assert!(matches!(
        unpresented.resolve(),
        Err(ConfigError::Missing { .. })
    ));
    assert!(
        unpresented
            .problems("cdr.credentials.oauth")
            .iter()
            .any(|problem| problem.contains("certificate_bound"))
    );
    Ok(())
}
