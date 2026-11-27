// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! ML-DSA (RFC 9964) at FerroSMART: ML-DSA-65 token signing keys beside
//! the RSA ones, published and named in discovery, a resource server set
//! to ML-DSA-65 getting access tokens it verifies through
//! ferrohealth-smart, the ID Token following the client's registration,
//! and client assertions and signed launches by a client's `AKP` key.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use ferrohealth_smart::client::assertion::AssertionKey;
use ferrohealth_smart::jws::algorithm::Algorithm;
use ferrosmart::config::error::Error;
use ferrosmart::server::{AppState, router};
use ferrosmart::store::Store;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use crate::support::{
    Database, Keys, RESOURCE, audit, config, ec_key, from_client, ml_dsa_key, rsa_key,
};

/// The issuer every case configures.
const ISSUER: &str = "https://smart.example.org";

/// The token endpoint of [`ISSUER`].
const TOKEN_URL: &str = "https://smart.example.org/token";

/// The `[ferrosmart.keys]` table of one RSA and one ML-DSA-65 key in `keys`.
fn both(keys: &Keys) -> String {
    let rsa = rsa_key(keys.dir.path(), "rsa.pem");
    let pq = ml_dsa_key(keys.dir.path(), "ml-dsa-65.pem");
    format!(
        "[ferrosmart.keys]\nprivate_key_files = [{:?}, {:?}]\n",
        rsa.display().to_string(),
        pq.display().to_string()
    )
}

/// The `[ferrosmart.keys]` table of [`both`] with a P-256, an Ed25519 and a
/// PS256 RSA key beside them.
fn every(keys: &Keys) -> String {
    let path = |path: std::path::PathBuf| path.display().to_string();
    format!(
        "[ferrosmart.keys]\nprivate_key_files = [{:?}, {:?}, {:?}, {:?}]\nps256_private_key_files = [{:?}]\n",
        path(rsa_key(keys.dir.path(), "rsa.pem")),
        path(ml_dsa_key(keys.dir.path(), "ml-dsa-65.pem")),
        path(crate::support::p256_key(keys.dir.path(), "p256.pem")),
        path(crate::support::ed25519_key(keys.dir.path(), "ed25519.pem")),
        path(rsa_key(keys.dir.path(), "ps256.pem")),
    )
}

/// A running server whose client `export` has its tokens signed with
/// `algorithm`, and whose EHR client `ehr` signs launches with an
/// ML-DSA-65 key.
struct Server {
    /// The state.
    state: Arc<AppState>,
    /// The application.
    app: Router,
    /// The EHR's ML-DSA-65 key.
    ehr: AssertionKey,
    /// The client's assertion key.
    client: AssertionKey,
    /// The keys, kept for the case's length.
    keys: Keys,
    /// The database.
    database: Database,
    /// The store.
    store: Store,
}

impl Server {
    async fn start(algorithm: &str) -> Self {
        Self::with_client(algorithm, ec_key).await
    }

    /// Starts the server of [`Server::start`] whose resource server takes
    /// access tokens signed `resource_algorithm`.
    async fn for_resource(algorithm: &str, resource_algorithm: &str) -> Self {
        Self::build(algorithm, ec_key, Some(resource_algorithm)).await
    }

    /// Starts the server of [`Server::start`] with `export`'s key written
    /// by `write`.
    async fn with_client(
        algorithm: &str,
        write: fn(&std::path::Path, &str) -> std::path::PathBuf,
    ) -> Self {
        Self::build(algorithm, write, None).await
    }

    /// Starts the server of [`Server::with_client`] whose resource server
    /// names `resource_algorithm`, when there is one.
    async fn build(
        algorithm: &str,
        write: fn(&std::path::Path, &str) -> std::path::PathBuf,
        resource_algorithm: Option<&str>,
    ) -> Self {
        Self::build_signing(algorithm, write, resource_algorithm, false, both).await
    }

    /// Starts the server of [`Server::start`] whose client `export` signs
    /// its assertions PS256 with an RSA key.
    async fn with_ps256_client() -> Self {
        Self::build_signing("RS256", rsa_key, None, true, both).await
    }

    /// Starts the server of [`Server::build`], `export` signing PS256 when
    /// `ps256`.
    async fn build_signing(
        algorithm: &str,
        write: fn(&std::path::Path, &str) -> std::path::PathBuf,
        resource_algorithm: Option<&str>,
        ps256: bool,
        pool: fn(&Keys) -> String,
    ) -> Self {
        let keys = Keys::new();
        let resource = resource_algorithm.map_or_else(String::new, |named| {
            format!(
                "[[ferrosmart.resource]]\nbase = {RESOURCE:?}\naccess_token_signing_alg = {named:?}\n"
            )
        });
        let read = |path: std::path::PathBuf, kid: &str| {
            let pem = std::fs::read(path).expect("the key reads");
            AssertionKey::from_pem(&pem, None, Some(kid.to_owned())).expect("a client key")
        };
        let mut client = read(write(keys.dir.path(), "client.pem"), "client-1");
        if ps256 {
            client = client
                .with_algorithm(Algorithm::Ps256)
                .expect("an RSA key signs PS256");
        }
        let ehr = read(ml_dsa_key(keys.dir.path(), "ehr.pem"), "ehr-1");
        let set = crate::support::inline(&json!({"keys": [client.public_jwk()]}));
        let ehr_set = crate::support::inline(&json!({"keys": [ehr.public_jwk()]}));
        let database = Database::create().await;
        let text = format!(
            "[ferrosmart]\nissuer = {ISSUER:?}\n{}[ferrosmart.database]\nurl = {:?}\n{resource}\
             [[client]]\nclient_id = \"export\"\ntoken_endpoint_auth_method = \"private_key_jwt\"\njwks = {set}\n\
             scope = [\"system/Observation.rs\"]\ngrant_types = [\"client_credentials\"]\n\
             id_token_signed_response_alg = {algorithm:?}\n\
             [[client]]\nclient_id = \"ehr\"\ntoken_endpoint_auth_method = \"private_key_jwt\"\njwks = {ehr_set}\n\
             scope = [\"system/launch.c\"]\ngrant_types = [\"client_credentials\"]\n\
             [[client]]\nclient_id = \"app\"\ntoken_endpoint_auth_method = \"none\"\n\
             redirect_uris = [\"https://app.example.org/callback\"]\ngrant_types = [\"authorization_code\"]",
            pool(&keys),
            secrecy::ExposeSecret::expose_secret(&database.url)
        );
        let text = crate::support::reach_every_base(&text);
        let settings = config(&text, &keys).resolve().expect("resolves");
        let store = Store::connect(&settings.database_url, 2)
            .await
            .expect("connects");
        store.migrate().await.expect("migrates");
        settings
            .keys
            .refresh(&store, jiff::Timestamp::now().as_second())
            .await
            .expect("the keys rotate in");
        let audit = audit(&settings);
        let state = Arc::new(AppState::new(settings, store.clone(), audit));
        crate::support::apply(&state, &crate::support::clients(&text)).await;
        Self {
            app: router(Arc::clone(&state)),
            state,
            ehr,
            client,
            keys,
            database,
            store,
        }
    }

    /// Sends `request` and returns the status and the body.
    async fn send(&self, request: Request<Body>) -> (StatusCode, Vec<u8>) {
        let response = self
            .app
            .clone()
            .oneshot(from_client(request))
            .await
            .expect("an answer");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("the body")
            .to_bytes();
        (status, bytes.to_vec())
    }

    /// Returns the access token the client credentials grant issues.
    async fn token(&self) -> String {
        let (status, body) = self.grant(&Self::assertion(&self.client)).await;
        assert_eq!(StatusCode::OK, status, "{body}");
        body.get("access_token")
            .and_then(Value::as_str)
            .expect("a token")
            .to_owned()
    }

    /// Returns a client assertion of `export` signed by `key`.
    fn assertion(key: &AssertionKey) -> String {
        let now = jiff::Timestamp::now().as_second();
        key.sign(
            "JWT",
            &json!({"iss": "export", "sub": "export", "aud": TOKEN_URL, "exp": now + 60, "jti": unique()}),
        )
        .expect("signs")
    }

    /// Posts the client credentials grant with `assertion` and returns the
    /// status and the body.
    async fn grant(&self, assertion: &str) -> (StatusCode, Value) {
        let body: String = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "client_credentials"),
                ("scope", "system/Observation.rs"),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", assertion),
            ])
            .finish();
        let request = Request::post("/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .expect("a request");
        let (status, bytes) = self.send(request).await;
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// Returns the JWK Set FerroSMART publishes.
    async fn jwks(&self) -> Value {
        let (status, bytes) = self
            .send(
                Request::get("/jwks")
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await;
        assert_eq!(StatusCode::OK, status, "the JWK Set is served");
        serde_json::from_slice(&bytes).expect("a JWK Set")
    }

    async fn stop(self) {
        self.database.drop(self.store).await;
    }
}

/// Returns an id no other assertion of the run carries.
fn unique() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "jti-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

#[tokio::test]
async fn an_ml_dsa_client_assertion_authenticates_and_a_disagreeing_alg_is_refused() {
    let server = Server::with_client("RS256", ml_dsa_key).await;
    assert_eq!(Algorithm::MlDsa65, server.client.algorithm());
    let (status, body) = server.grant(&Server::assertion(&server.client)).await;
    assert_eq!(StatusCode::OK, status, "RFC 9964 §5: {body}");
    let dir = tempfile::tempdir().expect("a directory");
    let forged = crate::support::ml_dsa_key_of(
        dir.path(),
        "forged.pem",
        &aws_lc_rs::signature::ML_DSA_44_SIGNING,
    );
    let pem = std::fs::read(forged).expect("the key reads");
    let other_set = AssertionKey::from_pem(&pem, None, Some(String::from("client-1")))
        .expect("an ML-DSA-44 key");
    let (status, body) = server.grant(&Server::assertion(&other_set)).await;
    assert_eq!(
        StatusCode::BAD_REQUEST,
        status,
        "an ML-DSA-44 assertion under the ML-DSA-65 key's kid: {body}"
    );
    assert_eq!("invalid_client", body["error"]);
    server.stop().await;
}

#[tokio::test]
async fn an_ml_dsa_signed_launch_is_redeemed() {
    let server = Server::start("RS256").await;
    let now = jiff::Timestamp::now().as_second();
    let jwt = server
        .ehr
        .sign(
            "launch+jwt",
            &json!({
                "iss": "ehr", "aud": ISSUER, "exp": now + 120, "iat": now, "jti": unique(),
                "client_id": "app", "resource": RESOURCE, "patient": "123"
            }),
        )
        .expect("signs");
    assert_eq!(
        Algorithm::MlDsa65,
        ferrohealth_smart::jws::compact::decode(&jwt)
            .expect("a JWS")
            .header()
            .alg
    );
    let from = crate::support::CLIENT_ADDRESS.parse().expect("an address");
    let context =
        ferrosmart::launch::redeem(&server.state, "app", &jwt, RESOURCE, "openid launch", from)
            .await
            .expect("the ML-DSA-65 launch is redeemed");
    assert_eq!(Some("123"), context.patient.as_deref());
    server.stop().await;
}

#[tokio::test]
async fn a_resource_server_set_to_ml_dsa_65_gets_tokens_it_verifies() {
    let server = Server::for_resource("RS256", "ML-DSA-65").await;
    let jwks = server.jwks().await;
    let algorithms: Vec<&str> = jwks["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .map(|key| key["alg"].as_str().expect("an alg"))
        .collect();
    assert_eq!(
        vec!["RS256", "ML-DSA-65"],
        algorithms,
        "both keys are published"
    );
    let akp = &jwks["keys"][1];
    assert_eq!("AKP", akp["kty"], "RFC 9964 §3");
    assert!(akp.get("priv").is_none(), "RFC 9964 §3: no private member");
    let token = server.token().await;
    let header = ferrohealth_smart::jws::compact::decode(&token)
        .expect("a JWS")
        .header()
        .clone();
    assert_eq!(
        Algorithm::MlDsa65,
        header.alg,
        "the resource server's algorithm, whatever the client's registration"
    );
    let refused = crate::support::read_at_resource_server(
        &jwks,
        ISSUER,
        RESOURCE,
        ferrohealth_smart::kind::IssuerKind::Smart,
        &ferrohealth_smart::profile::ProfileKeys::default(),
        &token,
    )
    .await;
    assert!(
        refused.is_err(),
        "a resource server that names no ML-DSA refuses it"
    );
    let caller = read_with_ml_dsa(&jwks, &token).await.expect("admitted");
    assert_eq!(Some("export"), caller.client_id());
    server.stop().await;
}

// NOTE: RFC 9068 §2.1 and OpenID Connect Core 1.0 §2, the access token follows the
// resource server that verifies it; the client's registration chooses the ID Token's.
#[tokio::test]
async fn an_ml_dsa_65_client_gets_rs256_access_tokens_for_a_resource_server_that_names_none() {
    let server = Server::start("ML-DSA-65").await;
    let token = server.token().await;
    let header = ferrohealth_smart::jws::compact::decode(&token)
        .expect("a JWS")
        .header()
        .clone();
    assert_eq!(Algorithm::Rs256, header.alg);
    server.stop().await;
}

#[tokio::test]
async fn an_rs256_client_beside_ml_dsa_keys_still_gets_rs256_tokens() {
    let server = Server::start("RS256").await;
    let token = server.token().await;
    let header = ferrohealth_smart::jws::compact::decode(&token)
        .expect("a JWS")
        .header()
        .clone();
    assert_eq!(Algorithm::Rs256, header.alg, "RFC 9068 §2.1");
    server.stop().await;
}

/// Returns the caller a resource server that accepts ML-DSA-65 beside the
/// defaults reads `token` as.
async fn read_with_ml_dsa(
    jwks: &Value,
    token: &str,
) -> Result<ferrohealth_smart::resource::Caller, ferrohealth_smart::resource::Rejection> {
    use ferrohealth_smart::resource::{ResourceServer, Settings};
    let dir = tempfile::tempdir().expect("a directory");
    let path = dir.path().join("ferrosmart-jwks.json");
    std::fs::write(&path, jwks.to_string()).expect("written");
    let mut settings = Settings::new(ISSUER, RESOURCE, ferrohealth_smart::kind::IssuerKind::Smart);
    settings.algorithms.push(Algorithm::MlDsa65);
    settings.jwks_file = Some(path);
    ResourceServer::discover(settings)
        .await
        .expect("the resource server starts")
        .authenticate(token)
        .await
}

#[test]
fn discovery_names_ml_dsa_65_beside_rs256() {
    let keys = Keys::new();
    let settings = config(
        &format!("[ferrosmart]\nissuer = {ISSUER:?}\n{}", both(&keys)),
        &keys,
    )
    .resolve()
    .expect("resolves");
    let metadata = ferrosmart::discovery::metadata(&settings, true);
    let document = ferrosmart::discovery::openid_configuration(&metadata, &settings.keys);
    assert_eq!(
        json!(["RS256", "ML-DSA-65"]),
        document["id_token_signing_alg_values_supported"],
        "OpenID Connect Discovery 1.0 §3, RS256 included"
    );
}

#[test]
fn a_pool_without_an_rsa_key_or_with_another_key_type_is_refused() {
    let keys = Keys::new();
    let pq = ml_dsa_key(keys.dir.path(), "only.pem");
    let text = format!(
        "[ferrosmart]\nissuer = {ISSUER:?}\n[ferrosmart.keys]\nprivate_key_files = [{:?}]",
        pq.display().to_string()
    );
    assert!(
        matches!(config(&text, &keys).resolve(), Err(Error::NoRs256Key)),
        "RFC 9068 §2.1: RS256 is always signed"
    );
    let ec = ec_key(keys.dir.path(), "ec.pem");
    let text = format!(
        "[ferrosmart]\nissuer = {ISSUER:?}\n[ferrosmart.keys]\nprivate_key_files = [{:?}, {:?}]",
        keys.current.display().to_string(),
        ec.display().to_string()
    );
    assert!(matches!(
        config(&text, &keys).resolve(),
        Err(Error::TokenKeyType { .. })
    ));
}

#[test]
fn a_resource_server_naming_an_algorithm_no_key_signs_is_refused() {
    let keys = Keys::new();
    let text = format!(
        "[ferrosmart]\nissuer = {ISSUER:?}\n[[ferrosmart.resource]]\nbase = {RESOURCE:?}\n\
         access_token_signing_alg = \"ML-DSA-65\"\n"
    );
    assert!(matches!(
        config(&text, &keys).resolve(),
        Err(Error::Resource { .. })
    ));
    let text = format!(
        "[ferrosmart]\nissuer = {ISSUER:?}\n{}[[ferrosmart.resource]]\nbase = {RESOURCE:?}\n\
         access_token_signing_alg = \"ML-DSA-65\"\n",
        both(&keys)
    );
    let settings = config(&text, &keys).resolve().expect("resolves");
    assert_eq!(Algorithm::MlDsa65, settings.token_algorithm(RESOURCE));
    assert_eq!(Algorithm::Rs256, settings.token_algorithm(ISSUER));
}

#[tokio::test]
async fn a_registration_naming_an_unknown_or_unheld_algorithm_is_refused() {
    let keys = Keys::new();
    let database = Database::create().await;
    let text = format!(
        "[ferrosmart]\nissuer = {ISSUER:?}\n[ferrosmart.database]\nurl = {:?}",
        secrecy::ExposeSecret::expose_secret(&database.url)
    );
    let settings = config(&text, &keys).resolve().expect("resolves");
    let store = Store::connect(&settings.database_url, 2)
        .await
        .expect("connects");
    store.migrate().await.expect("migrates");
    let audit = audit(&settings);
    let state = Arc::new(AppState::new(settings, store.clone(), audit));
    for (algorithm, refused) in [("ES256", "unknown"), ("ML-DSA-65", "no ML-DSA-65 key")] {
        let documents = crate::support::clients(&crate::support::reach_every_base(&format!(
            "[[client]]\nclient_id = \"app\"\ntoken_endpoint_auth_method = \"none\"\n\
             redirect_uris = [\"https://app.example.org/callback\"]\n\
             id_token_signed_response_alg = {algorithm:?}"
        )));
        let document = serde_json::from_value(documents[0].clone()).expect("a client document");
        let outcome = ferrosmart::admin::apply(&state, document).await;
        assert!(outcome.is_err(), "{refused}");
    }
    database.drop(store).await;
}

// NOTE: FAPI 2.0 Security Profile §5.4.1 admits PS256, ES256 and EdDSA client
// assertions; SMART App Launch 2.2.0 asks for at least one of RS384 and ES384 beside.
#[tokio::test]
async fn ps256_es256_and_eddsa_client_assertions_authenticate() {
    type Write = fn(&std::path::Path, &str) -> std::path::PathBuf;
    let writers: [(Write, Algorithm); 2] = [
        (crate::support::p256_key, Algorithm::Es256),
        (crate::support::ed25519_key, Algorithm::EdDsa),
    ];
    for (write, algorithm) in writers {
        let server = Server::with_client("RS256", write).await;
        assert_eq!(algorithm, server.client.algorithm());
        let (status, body) = server.grant(&Server::assertion(&server.client)).await;
        assert_eq!(StatusCode::OK, status, "{algorithm}: {body}");
        server.stop().await;
    }
    let server = Server::with_ps256_client().await;
    assert_eq!(Algorithm::Ps256, server.client.algorithm());
    let (status, body) = server.grant(&Server::assertion(&server.client)).await;
    assert_eq!(StatusCode::OK, status, "PS256: {body}");
    server.stop().await;
}

// NOTE: RFC 7518 §3.4 and §3.5, RFC 8037 §3.1: a P-256, an Ed25519 and a PS256 RSA
// key in the pool sign their algorithms, and discovery lists each.
#[tokio::test]
async fn a_resource_server_takes_tokens_in_each_algorithm_the_pool_signs() {
    for algorithm in ["ES256", "EdDSA", "PS256"] {
        let server = Server::build_signing("RS256", ec_key, Some(algorithm), false, every).await;
        let token = server.token().await;
        let header = ferrohealth_smart::jws::compact::decode(&token)
            .expect("a JWS")
            .header()
            .clone();
        assert_eq!(algorithm, header.alg.name());
        let jwks = server.jwks().await;
        let keys: Vec<ferrohealth_smart::jws::jwk::Jwk> = jwks["keys"]
            .as_array()
            .expect("keys")
            .iter()
            .map(|key| ferrohealth_smart::jws::jwk::Jwk::try_from(key).expect("a key"))
            .collect();
        let key = ferrohealth_smart::jws::jwk::select(&keys, header.kid.as_deref(), header.alg)
            .expect("the signing key is published");
        ferrohealth_smart::jws::compact::decode(&token)
            .expect("a JWS")
            .verify_claims(key)
            .expect("the token verifies");
        server.stop().await;
    }
}

// NOTE: RFC 10070 §3.2, it is NOT RECOMMENDED for servers to reject a client
// assertion that carries no explicit typ.
#[tokio::test]
async fn a_client_assertion_without_typ_authenticates() {
    use ferrohealth_smart::jws::compact::Header;
    use ferrohealth_smart::jws::key::{PrivateKey, SigningKey};
    let server = Server::with_client("RS256", crate::support::p256_key).await;
    let pem = std::fs::read(server.keys.dir.path().join("client.pem")).expect("the key reads");
    let key = SigningKey::new(
        PrivateKey::from_pem(&pem).expect("a P-256 key"),
        Algorithm::Es256,
    )
    .expect("a signing key");
    let mut header = Header::new(Algorithm::Es256);
    header.kid = Some(String::from("client-1"));
    let now = jiff::Timestamp::now().as_second();
    let untyped = ferrohealth_smart::jws::compact::encode(
        &header,
        &json!({"iss": "export", "sub": "export", "aud": TOKEN_URL, "exp": now + 60, "jti": unique()}),
        &key,
    )
    .expect("signs");
    let (status, body) = server.grant(&untyped).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    server.stop().await;
}
