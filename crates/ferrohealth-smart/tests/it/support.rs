// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The stub authorization server and the signing keys of the cases.
//!
//! Every signing key is generated when the case runs and lives only in
//! memory: no key, real or synthetic, is committed.

use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
use aws_lc_rs::signature::ECDSA_P384_SHA384_FIXED_SIGNING;
use aws_lc_rs::signature::ECDSA_P521_SHA512_FIXED_SIGNING;
use aws_lc_rs::signature::EcdsaKeyPair;
use aws_lc_rs::signature::Ed25519KeyPair;
use aws_lc_rs::signature::ML_DSA_44_SIGNING;
use aws_lc_rs::signature::ML_DSA_65_SIGNING;
use aws_lc_rs::signature::ML_DSA_87_SIGNING;
use aws_lc_rs::signature::PqdsaKeyPair;
use aws_lc_rs::signature::RsaKeyPair;
use base64::Engine as _;
use ferrohealth_smart::jws::algorithm::Algorithm;
use ferrohealth_smart::jws::compact::Header;
use ferrohealth_smart::jws::jwk::Jwk;
use ferrohealth_smart::jws::key::PrivateKey;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::resource::ResourceServer;
use ferrohealth_smart::resource::Settings;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers;

/// The audience every token of these cases is addressed to.
pub(crate) const AUDIENCE: &str = "http://ferro.invalid/fhir";

/// The client every synthetic token names, first-party on the stub issuer.
pub(crate) const CLIENT: &str = "synthetic-client";

/// The path the stub serves the key set at.
pub(crate) const JWKS_PATH: &str = "/jwks";

/// The token endpoint the stub's metadata names.
pub(crate) const TOKEN_PATH: &str = "/token";

/// One signing key, generated for the case.
pub(crate) struct SigningKey {
    /// The `kid` the key is published and used under.
    pub(crate) kid: String,
    /// The algorithm it signs with.
    pub(crate) alg: Algorithm,
    /// The private half.
    pub(crate) signing: ferrohealth_smart::jws::key::SigningKey,
    /// The public half as a JWK.
    pub(crate) jwk: serde_json::Value,
    /// The private half as PKCS#8 PEM, for a client assertion key.
    pub(crate) pem: Vec<u8>,
}

/// Returns a fresh ECDSA key for `alg` (ES256 or ES384) published as `kid`.
pub(crate) fn ec_key(kid: &str, alg: Algorithm) -> SigningKey {
    let curve = match alg {
        Algorithm::Es384 => &ECDSA_P384_SHA384_FIXED_SIGNING,
        _ => &ECDSA_P256_SHA256_FIXED_SIGNING,
    };
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(curve, &SystemRandom::new()).expect("a key pair");
    key(kid, alg, pkcs8.as_ref())
}

/// Returns a fresh P-521 private key in PKCS#8 PEM, a curve no ES256 or
/// ES384 key is on.
pub(crate) fn p521_pem() -> Vec<u8> {
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P521_SHA512_FIXED_SIGNING, &SystemRandom::new())
            .expect("a key pair");
    pem(pkcs8.as_ref())
}

/// Returns a fresh RSA key for `alg` (RS256 to PS512) published as `kid`.
pub(crate) fn rsa_key(kid: &str, alg: Algorithm) -> SigningKey {
    let pair = RsaKeyPair::generate(KeySize::Rsa2048).expect("a key pair");
    let pkcs8 = pair.as_der().expect("PKCS#8");
    key(kid, alg, pkcs8.as_ref())
}

/// Returns a fresh Ed25519 key published as `kid`.
pub(crate) fn ed_key(kid: &str) -> SigningKey {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8v1(&SystemRandom::new()).expect("a key pair");
    key(kid, Algorithm::EdDsa, pkcs8.as_ref())
}

/// Returns a fresh ML-DSA key of `alg`'s parameter set (RFC 9964 §5)
/// published as `kid`, its PEM the PKCS#8 form of RFC 9881 §6.
pub(crate) fn ml_dsa_key(kid: &str, alg: Algorithm) -> SigningKey {
    let parameters = match alg {
        Algorithm::MlDsa44 => &ML_DSA_44_SIGNING,
        Algorithm::MlDsa87 => &ML_DSA_87_SIGNING,
        _ => &ML_DSA_65_SIGNING,
    };
    let pair = PqdsaKeyPair::generate(parameters).expect("a key pair");
    let pkcs8 = pair.to_pkcs8v1().expect("PKCS#8");
    key(kid, alg, pkcs8.as_ref())
}

/// Returns the PKCS#8 key `pkcs8` signing with `alg`, with its public JWK.
fn key(kid: &str, alg: Algorithm, pkcs8: &[u8]) -> SigningKey {
    let private = PrivateKey::from_pkcs8(pkcs8).expect("the key reads");
    let signing =
        ferrohealth_smart::jws::key::SigningKey::new(private, alg).expect("the key signs alg");
    let jwk = signing
        .public_jwk()
        .clone()
        .with_kid(kid)
        .with_signature_use()
        .to_value();
    SigningKey {
        kid: kid.to_owned(),
        alg,
        signing,
        jwk,
        pem: pem(pkcs8),
    }
}

/// Returns `der` as a PKCS#8 PEM document.
fn pem(der: &[u8]) -> Vec<u8> {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut text = String::from("-----BEGIN PRIVATE KEY-----\n");
    for line in body.as_bytes().chunks(64) {
        text.push_str(&String::from_utf8_lossy(line));
        text.push('\n');
    }
    text.push_str("-----END PRIVATE KEY-----\n");
    text.into_bytes()
}

/// Returns the header of the compact JWS `token`.
pub(crate) fn header(token: &str) -> Header {
    ferrohealth_smart::jws::compact::decode(token)
        .expect("the JWS reads")
        .header()
        .clone()
}

/// Returns the claims of the compact JWS `token` once its signature
/// verifies with the public JWK `jwk` under the header's algorithm.
pub(crate) fn verified(
    token: &str,
    jwk: &serde_json::Value,
) -> serde_json::Map<String, serde_json::Value> {
    let key = Jwk::try_from(jwk).expect("the JWK reads");
    ferrohealth_smart::jws::compact::decode(token)
        .expect("the JWS reads")
        .verify_claims(&key)
        .expect("the signature verifies")
}

/// The stub authorization server.
pub(crate) struct Issuer {
    /// The server, kept alive for the case.
    pub(crate) server: MockServer,
}

impl Issuer {
    /// Starts an issuer whose RFC 8414 metadata names the key set holding
    /// `keys`.
    pub(crate) async fn start(keys: &[&SigningKey]) -> Self {
        let issuer = Self::bare().await;
        issuer
            .mount_metadata("/.well-known/oauth-authorization-server")
            .await;
        issuer.mount_keys(keys, None).await;
        issuer
    }

    /// Starts an issuer that serves nothing yet.
    pub(crate) async fn bare() -> Self {
        Self {
            server: MockServer::start().await,
        }
    }

    /// Returns the issuer identifier.
    pub(crate) fn uri(&self) -> String {
        self.server.uri()
    }

    /// Returns the metadata document this issuer answers with.
    pub(crate) fn metadata(&self) -> serde_json::Value {
        let uri = self.uri();
        serde_json::json!({
            "issuer": uri,
            "jwks_uri": format!("{uri}{JWKS_PATH}"),
            "authorization_endpoint": format!("{uri}/authorize"),
            "token_endpoint": format!("{uri}{TOKEN_PATH}"),
            "token_endpoint_auth_methods_supported": ["private_key_jwt", "client_secret_basic"],
            "grant_types_supported": ["authorization_code", "client_credentials"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "introspection_endpoint": format!("{uri}/introspect"),
            "scopes_supported": ["openid", "system/*.rs"]
        })
    }

    /// Mounts the metadata document at `path`.
    pub(crate) async fn mount_metadata(&self, path: &str) {
        self.mount_document(path, self.metadata()).await;
    }

    /// Mounts `document` as the JSON answer of `path`.
    pub(crate) async fn mount_document(&self, path: &str, document: serde_json::Value) {
        Mock::given(matchers::method("GET"))
            .and(matchers::path(path))
            .respond_with(ResponseTemplate::new(200).set_body_json(document))
            .mount(&self.server)
            .await;
    }

    /// Mounts the key set holding `keys`, answered `times` times when given.
    pub(crate) async fn mount_keys(&self, keys: &[&SigningKey], times: Option<u64>) {
        let set: Vec<serde_json::Value> = keys.iter().map(|key| key.jwk.clone()).collect();
        let mock = Mock::given(matchers::method("GET"))
            .and(matchers::path(JWKS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": set
            })));
        match times {
            Some(times) => mock.up_to_n_times(times).mount(&self.server).await,
            None => mock.mount(&self.server).await,
        }
    }

    /// Mounts a key set location that answers `500`.
    pub(crate) async fn mount_failing_keys(&self) {
        Mock::given(matchers::method("GET"))
            .and(matchers::path(JWKS_PATH))
            .respond_with(ResponseTemplate::new(500))
            .mount(&self.server)
            .await;
    }

    /// Returns how many times `path` was read.
    pub(crate) async fn reads(&self, path: &str) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|request| request.url.path() == path)
            .count()
    }

    /// Returns the settings of a resource server for this issuer, reading
    /// the key set again on every unknown `kid`.
    pub(crate) fn settings(&self) -> Settings {
        let mut settings = persons(self.uri(), AUDIENCE);
        settings.jwks_refresh_interval = Duration::ZERO;
        settings
    }

    /// Returns the claims of a valid token granting `scope`.
    pub(crate) fn claims(&self, scope: &str) -> serde_json::Value {
        let now = now();
        serde_json::json!({
            "iss": self.uri(),
            "aud": AUDIENCE,
            "sub": "synthetic-client-sub",
            "client_id": CLIENT,
            "iat": now,
            "exp": now + 300,
            "jti": "synthetic-jti-1",
            "scope": scope
        })
    }
}

/// Returns the settings of a SMART issuer, whose tokens set the launch
/// context's patient.
pub(crate) fn persons(issuer: impl Into<String>, audience: impl Into<String>) -> Settings {
    Settings::new(issuer, audience, IssuerKind::Smart)
}

/// Returns the current time in seconds.
pub(crate) fn now() -> i64 {
    jiff::Timestamp::now().as_second()
}

/// Returns `claims` signed by `key` with `typ` of `at+jwt`.
pub(crate) fn mint(key: &SigningKey, claims: &serde_json::Value) -> String {
    let mut header = Header::new(key.alg);
    header.kid = Some(key.kid.clone());
    header.typ = Some(String::from("at+jwt"));
    mint_with(key, &header, claims)
}

/// Returns `claims` signed by `key` under `header`.
pub(crate) fn mint_with(key: &SigningKey, header: &Header, claims: &serde_json::Value) -> String {
    ferrohealth_smart::jws::compact::encode(header, claims, &key.signing).expect("the token signs")
}

/// Returns the resource server `settings` describe.
pub(crate) async fn server(settings: Settings) -> Arc<ResourceServer> {
    Arc::new(
        ResourceServer::discover(settings)
            .await
            .expect("the authorization server is discovered"),
    )
}

/// Returns a new file under the temporary directory holding `content`, its
/// name ending in `name`.
///
/// Each call creates its own file, so two calls with one `name` in one
/// process never share a path; the file outlives the case.
pub(crate) fn temp_file(name: &str, content: &[u8]) -> std::path::PathBuf {
    let mut file = tempfile::Builder::new()
        .prefix("ferrohealth-smart-")
        .suffix(&format!("-{name}"))
        .tempfile()
        .expect("the temporary file is created");
    std::io::Write::write_all(&mut file, content).expect("the temporary file is written");
    let (_, path) = file.keep().expect("the temporary file is kept");
    path
}

#[test]
fn two_temporary_files_of_one_name_are_two_files() {
    let first = temp_file("same.pem", b"first");
    let second = temp_file("same.pem", b"second");
    assert_ne!(first, second);
    assert!(first.to_string_lossy().ends_with("-same.pem"));
    assert_eq!(
        std::fs::read(&first).expect("the first file reads"),
        b"first"
    );
    assert_eq!(
        std::fs::read(&second).expect("the second file reads"),
        b"second"
    );
}
