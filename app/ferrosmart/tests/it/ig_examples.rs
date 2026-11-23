// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! SMART App Launch 2.2.0 §9, Examples, as test vectors against FerroSMART's
//! own code. Every value is read from the vendored page that publishes it,
//! so a re-vendored guide changes the vectors with it.
//!
//! What cannot be replayed, and why:
//! - the authorization codes and access tokens of the app launch and
//!   Backend Services examples are HS256 JWTs the sandbox signed with a key
//!   it does not publish, so no code exchange and no resource request is
//!   replayed;
//! - every example assertion expired years ago (`exp` 1422568860 and
//!   1633532134), so FerroSMART answers each with `invalid_client`, "has
//!   expired"; it checks the expiry after the key, the signature and the
//!   audience, so that answer shows the rest held;
//! - the authorization requests need a person to log in at an upstream
//!   provider; the request shape is held by the authorization cases.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use ferrosmart::server::{AppState, router};
use ferrosmart::store::Store;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt as _;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use crate::support::{Database, Keys, audit, config, from_client};

/// Client Authentication: Asymmetric, the worked example.
const ASYMMETRIC: &str = include_str!(
    "../../../../docs/specs/smart-app-launch/repository/input/pages/client-confidential-asymmetric.md"
);
/// The rendered notebook that signs the worked example with both keys.
const SIGNATURES: &str = include_str!(
    "../../../../docs/specs/smart-app-launch/repository/input/pages/authorization-example-jwks-and-signatures.md"
);
/// The public keys of the worked example, RS384.
const RS384_KEYS: &str = include_str!(
    "../../../../docs/specs/smart-app-launch/repository/input/images/RS384.public.json"
);
/// The public keys of the worked example, ES384.
const ES384_KEYS: &str = include_str!(
    "../../../../docs/specs/smart-app-launch/repository/input/images/ES384.public.json"
);
/// The app launch example with asymmetric client authentication.
const LAUNCH_ASYMMETRIC: &str = include_str!(
    "../../../../docs/specs/smart-app-launch/repository/input/pages/example-app-launch-asymmetric-auth.md"
);
/// The app launch example with symmetric client authentication.
const LAUNCH_SYMMETRIC: &str = include_str!(
    "../../../../docs/specs/smart-app-launch/repository/input/pages/example-app-launch-symmetric-auth.md"
);
/// The Backend Services example.
const BACKEND: &str = include_str!(
    "../../../../docs/specs/smart-app-launch/repository/input/pages/example-backend-services.md"
);
/// The worked ID Token example.
const ID_TOKEN: &str = include_str!(
    "../../../../docs/specs/smart-app-launch/repository/input/pages/worked_example_id_token.md"
);

/// FerroSMART configured as the authorization server an example names,
/// with the example's client registered.
struct Server {
    /// The application.
    app: Router,
    /// The store.
    store: Store,
    /// The database.
    database: Database,
    /// The keys, kept for the case's length.
    _keys: Keys,
    /// The path of the issuer, which every route is served under.
    base: String,
}

impl Server {
    /// Starts FerroSMART at `issuer` with the `[[client]]` table `client`.
    async fn start(issuer: &str, client: &str) -> Self {
        let keys = Keys::new();
        let database = Database::create().await;
        // NOTE: RFC 8414 §3, the routes of an issuer with a path are served under it.
        let base = url::Url::parse(issuer)
            .expect("an issuer URL")
            .path()
            .trim_end_matches('/')
            .to_owned();
        let text = format!(
            "[server]\nbase_path = {base:?}\n[ferrosmart]\nissuer = {issuer:?}\n\
             [ferrosmart.database]\nurl = {:?}\n{client}",
            secrecy::ExposeSecret::expose_secret(&database.url)
        );
        let settings = config(&crate::support::reach_every_base(&text), &keys)
            .resolve()
            .expect("resolves");
        let store = Store::connect(&settings.database_url, 2)
            .await
            .expect("connects");
        store.migrate().await.expect("migrates");
        let audit = audit(&settings);
        let state = Arc::new(AppState::new(settings, store.clone(), audit));
        crate::support::apply(
            &state,
            &crate::support::clients(&crate::support::reach_every_base(&text)),
        )
        .await;
        let app = router(state);
        Self {
            app,
            store,
            database,
            _keys: keys,
            base,
        }
    }

    /// Posts the form `pairs` to `path` with `authorization`, if any, and
    /// returns the status and the JSON body.
    async fn post(
        &self,
        path: &str,
        pairs: &[(&str, &str)],
        authorization: Option<&str>,
    ) -> (StatusCode, Value) {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        let mut request = Request::post(format!("{}{path}", self.base))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(authorization) = authorization {
            request = request.header(header::AUTHORIZATION, authorization);
        }
        let response = self
            .app
            .clone()
            .oneshot(from_client(
                request.body(Body::from(body)).expect("a request"),
            ))
            .await
            .expect("an answer");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("the body")
            .to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// Drops the database.
    async fn stop(self) {
        self.database.drop(self.store).await;
    }
}

/// Returns the first compact JWS of `text` that begins with `head`.
fn jws(text: &str, head: &str) -> String {
    let start = text.find(head).expect("the page carries the JWS");
    text.get(start..)
        .expect("a char boundary")
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect()
}

/// Returns the value of the form parameter `name` in the first request of
/// `text` that sends it.
fn form_value(text: &str, name: &str) -> String {
    let marker = format!("{name}=");
    let start = text.find(&marker).expect("the page sends the parameter") + marker.len();
    text.get(start..)
        .expect("a char boundary")
        .chars()
        .take_while(|c| !matches!(c, '&' | '\'' | '\n' | ' '))
        .collect()
}

/// Returns the string value of `"member": "…"` in the page `text` after
/// `after`.
fn member(text: &str, after: &str, name: &str) -> String {
    let rest = text
        .get(text.find(after).expect("the page carries the JWK")..)
        .expect("a char boundary");
    let marker = format!("\"{name}\": \"");
    let start = rest.find(&marker).expect("the JWK names the member") + marker.len();
    rest.get(start..)
        .and_then(|value| value.split('"').next())
        .expect("a value")
        .to_owned()
}

/// Returns the client assertion form of the client credentials grant.
fn grant(assertion: &str) -> Vec<(&str, &str)> {
    vec![
        ("grant_type", "client_credentials"),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", assertion),
        ("scope", "system/Patient.rs"),
    ]
}

/// Returns `jws` with its signature's first character changed.
fn tampered(jws: &str) -> String {
    let (signed, signature) = jws.rsplit_once('.').expect("a JWS");
    let first = if signature.starts_with('A') { 'B' } else { 'A' };
    format!(
        "{signed}.{first}{}",
        signature.get(1..).expect("a signature")
    )
}

/// Asserts that FerroSMART refuses `assertion` because it expired, which it
/// checks after the key, the signature and the audience, and refuses it
/// as unverified once its signature is changed.
async fn holds_but_expired(server: &Server, assertion: &str, case: &str) {
    let (status, body) = server.post("/token", &grant(assertion), None).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{case}: {body}");
    assert_eq!(Some(&json!("invalid_client")), body.get("error"), "{case}");
    assert_eq!(
        Some(&json!("the client_assertion has expired")),
        body.get("error_description"),
        "{case}: the key, the signature and the audience hold"
    );
    let (_, body) = server
        .post("/token", &grant(&tampered(assertion)), None)
        .await;
    assert_eq!(
        Some(&json!("the client_assertion does not verify")),
        body.get("error_description"),
        "{case}: a changed signature does not verify"
    );
}

// NOTE: SMART App Launch 2.2.0, Client Authentication: Asymmetric, Worked example,
// and the notebook's RS384 and ES384 signatures over the same claims.
#[tokio::test]
async fn the_worked_example_s_rs384_and_es384_assertions_verify() {
    let rs384: Value = serde_json::from_str(RS384_KEYS).expect("JSON");
    let es384: Value = serde_json::from_str(ES384_KEYS).expect("JSON");
    let mut keys = rs384["keys"].as_array().expect("keys").clone();
    keys.extend(es384["keys"].as_array().expect("keys").iter().cloned());
    let set = crate::support::inline(&json!({ "keys": keys }));
    let server = Server::start(
        "https://authorize.smarthealthit.org",
        &format!(
            "[[client]]\nclient_id = \"https://bili-monitor.example.com\"\n\
             kind = \"confidential_asymmetric\"\njwks = {set}\n\
             scopes = [\"system/Patient.rs\"]\ngrant_types = [\"client_credentials\"]"
        ),
    )
    .await;
    let worked = jws(ASYMMETRIC, "eyJhbGciOiJSUzM4NCIs");
    assert_eq!(
        worked,
        jws(SIGNATURES, "eyJhbGciOiJSUzM4NCIs"),
        "the page and the notebook sign the same token"
    );
    holds_but_expired(&server, &worked, "RS384").await;
    holds_but_expired(&server, &jws(SIGNATURES, "eyJhbGciOiJFUzM4NCIs"), "ES384").await;
    server.stop().await;
}

// NOTE: SMART App Launch 2.2.0, Example App Launch for Asymmetric Client Auth and
// Example Backend Services: the app's ES384 key registered as the page shows it.
#[tokio::test]
async fn the_app_launch_and_backend_examples_assertions_verify() {
    let jwk = json!({
        "kty": "EC",
        "crv": member(LAUNCH_ASYMMETRIC, "registered as:", "crv"),
        "x": member(LAUNCH_ASYMMETRIC, "registered as:", "x"),
        "y": member(LAUNCH_ASYMMETRIC, "registered as:", "y"),
        "kid": member(LAUNCH_ASYMMETRIC, "registered as:", "kid"),
        "alg": "ES384"
    });
    let launch = form_value(LAUNCH_ASYMMETRIC, "client_assertion");
    let claims: Value = jsonwebtoken::dangerous::insecure_decode_claims(&launch).expect("claims");
    let audience = claims["aud"].as_str().expect("an aud");
    let issuer = audience.strip_suffix("/token").expect("the token URL");
    let set = crate::support::inline(&json!({ "keys": [jwk] }));
    let server = Server::start(
        issuer,
        &format!(
            "[[client]]\nclient_id = \"demo_app_whatever\"\n\
             kind = \"confidential_asymmetric\"\njwks = {set}\n\
             scopes = [\"system/Patient.rs\"]\ngrant_types = [\"client_credentials\"]"
        ),
    )
    .await;
    holds_but_expired(&server, &launch, "the app launch").await;
    holds_but_expired(
        &server,
        &form_value(BACKEND, "client_assertion"),
        "Backend Services",
    )
    .await;
    server.stop().await;
}

// NOTE: SMART App Launch 2.2.0, Example App Launch for Symmetric Client Auth: the
// Basic credentials as the page sends them, read by FerroSMART's symmetric check.
#[tokio::test]
async fn the_symmetric_example_s_basic_credentials_authenticate() {
    let authorization = {
        let start = LAUNCH_SYMMETRIC
            .find("Authorization: Basic ")
            .expect("the page sends Basic");
        LAUNCH_SYMMETRIC
            .get(start + "Authorization: ".len()..)
            .expect("a char boundary")
            .split(['\'', '\n'])
            .next()
            .expect("a value")
            .trim()
            .to_owned()
    };
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        authorization.trim_start_matches("Basic "),
    )
    .expect("base64");
    let (client_id, secret) = std::str::from_utf8(&decoded)
        .expect("UTF-8")
        .split_once(':')
        .expect("id:secret");
    assert_eq!("demo_app_whatever", client_id);
    let hash = crate::introspection::phc(secret);
    let server = Server::start(
        "https://smart.example.org",
        &format!(
            "[[client]]\nclient_id = {client_id:?}\nkind = \"confidential_symmetric\"\n\
             secret_hash = {hash:?}\n\
             redirect_uris = [\"https://sharp-lake-word.glitch.me/graph.html\"]\n\
             scopes = [\"launch/patient\", \"patient/Observation.rs\"]\n\
             grant_types = [\"authorization_code\"]"
        ),
    )
    .await;
    // NOTE: RFC 7009 §2.2, an unknown token answers 200 to a client that authenticated.
    let (status, body) = server
        .post("/revoke", &[("token", "unknown")], Some(&authorization))
        .await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let (status, _) = server
        .post(
            "/revoke",
            &[("token", "unknown")],
            Some("Basic ZGVtb19hcHBfd2hhdGV2ZXI6d3Jvbmc="),
        )
        .await;
    assert_eq!(StatusCode::UNAUTHORIZED, status, "a wrong secret");
    server.stop().await;
}

// NOTE: SMART App Launch 2.2.0, Worked example of ID Token: the RS384 token verifies
// with the page's public key and reads as the page shows.
#[test]
fn the_worked_id_token_verifies_and_reads_as_the_page_shows() {
    let pem: String = {
        let start = ID_TOKEN
            .find("-----BEGIN PUBLIC KEY-----")
            .expect("the page prints the public key");
        let end = ID_TOKEN
            .get(start..)
            .and_then(|rest| rest.find("-----END PUBLIC KEY-----"))
            .expect("the key ends")
            + start
            + "-----END PUBLIC KEY-----".len();
        ID_TOKEN
            .get(start..end)
            .expect("char boundaries")
            .lines()
            .map(str::trim)
            .collect::<Vec<_>>()
            .join("\n")
    };
    let token = jws(ID_TOKEN, "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9");
    let key = DecodingKey::from_rsa_pem(pem.as_bytes()).expect("an RSA key");
    // NOTE: the example carries no exp, iat or nonce, which OpenID Connect Core 1.0
    // §2 requires, so FerroSMART's relying party would refuse it; the signature
    // and the claims are what it shows.
    let mut validation = Validation::new(Algorithm::RS384);
    validation.set_required_spec_claims::<&str>(&[]);
    validation.validate_exp = false;
    validation.set_audience(&["growth-chart-app-123"]);
    let claims: ferrohealth_smart::oidc::IdTokenClaims =
        jsonwebtoken::decode(&token, &key, &validation)
            .expect("the ID Token verifies with the page's key")
            .claims;
    assert_eq!("https://my-ehr.org/fhir", claims.issuer);
    assert_eq!("alice", claims.subject);
    assert_eq!(
        Some(&json!("https://my-ehr.org/fhir/Practitioner/123")),
        claims.other.get("fhirUser")
    );
}
