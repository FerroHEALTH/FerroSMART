// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The introspection endpoint through the whole stack against a real
//! PostgreSQL: RFC 7662 with SMART App Launch 2.2.0, Token Introspection,
//! and the access rule of `docs/architecture.md` §13.6 item 8. The server
//! these cases and the revocation cases share lives here.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use ferrohealth_smart::assurance::AssuranceLevel;
use ferrohealth_smart::client::assertion::AssertionKey;
use ferrosmart::authorize::sha256;
use ferrosmart::config::settings::Settings;
use ferrosmart::server::{AppState, router};
use ferrosmart::store::grant::{Access, NewGrant};
use ferrosmart::store::{IssuedToken, Store};
use http::{Request, StatusCode, header};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use crate::support::{
    Database, Keys, RESOURCE, audit, commit, config, ec_key, from_client, rsa_key,
};

/// When the person of every recorded grant logged in.
const LOGGED_IN: i64 = 1_790_000_000;

/// The issuer every case configures.
pub(crate) const ISSUER: &str = "https://smart.example.org";
/// The token endpoint of [`ISSUER`].
const TOKEN_URL: &str = "https://smart.example.org/token";
/// The assertion type of RFC 7523 §2.2.
const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// The answer of one request: the status, the headers and the JSON body.
pub(crate) type Answer = (StatusCode, http::HeaderMap, Value);

/// A running server over a fresh database with seven clients: `export`, a
/// Backend Services client; `rs`, a resource server that may introspect;
/// `portal`, a confidential app; `vault`, a confidential symmetric app;
/// `gateway`, a confidential symmetric client that may introspect; `app`,
/// a public one; and `admin`, the client of the admin API.
pub(crate) struct Server {
    /// The application.
    pub(crate) app: Router,
    /// The key both confidential clients sign their assertions with.
    client_key: AssertionKey,
    /// The server's own signing key, for tokens a case issues under a grant.
    signing_key: AssertionKey,
    /// The keys, kept for the case's length by every replica.
    keys: Arc<Keys>,
    /// The settings, which a replica starts on as well.
    settings: Settings,
    /// The database, owned by the first replica alone.
    database: Option<Database>,
    /// The store.
    pub(crate) store: Store,
}

impl Server {
    /// Starts the server.
    pub(crate) async fn start() -> Self {
        Self::start_with("").await
    }

    /// Starts the server with `extra` appended to its configuration, such
    /// as its own `[[ferrosmart.resource]]` tables, logging people in at
    /// the providers it configures.
    pub(crate) async fn start_with(extra: &str) -> Self {
        let keys = Keys::new();
        let pem = std::fs::read(ec_key(keys.dir.path(), "client.pem")).expect("the key reads");
        let client_key = AssertionKey::from_pem(
            &pem,
            Some(ferrohealth_smart::jws::algorithm::Algorithm::Es384),
            Some(String::from("client-1")),
        )
        .expect("a client key");
        let set = crate::support::inline(&json!({"keys": [client_key.public_jwk()]}));
        let own = std::fs::read(&keys.current).expect("the server key reads");
        let signing_key = AssertionKey::from_pem(
            &own,
            Some(ferrohealth_smart::jws::algorithm::Algorithm::Rs256),
            None,
        )
        .expect("the server's key");
        let database = Database::create().await;
        let text = format!(
            "[ferrosmart]\nissuer = {ISSUER:?}\n[ferrosmart.database]\nurl = {:?}\n\
             [[client]]\nclient_id = \"export\"\ntoken_endpoint_auth_method = \"private_key_jwt\"\njwks = {set}\n\
             scope = [\"system/Patient.rs\", \"system/Observation.rs\"]\ngrant_types = [\"client_credentials\"]\n\
             [[client]]\nclient_id = \"rs\"\ntoken_endpoint_auth_method = \"private_key_jwt\"\njwks = {set}\n\
             scope = [\"system/introspect\"]\ngrant_types = [\"client_credentials\"]\n\
             [[client]]\nclient_id = \"portal\"\ntoken_endpoint_auth_method = \"private_key_jwt\"\njwks = {set}\n\
             redirect_uris = [\"https://portal.example.org/callback\"]\n\
             grant_types = [\"authorization_code\", \"refresh_token\"]\n\
             [[client]]\nclient_id = \"vault\"\ntoken_endpoint_auth_method = \"client_secret_basic\"\n\
             redirect_uris = [\"https://vault.example.org/callback\"]\n\
             grant_types = [\"authorization_code\", \"refresh_token\"]\n\
             [[client]]\nclient_id = \"gateway\"\ntoken_endpoint_auth_method = \"client_secret_basic\"\n\
             redirect_uris = [\"https://gateway.example.org/callback\"]\n\
             scope = [\"system/introspect\"]\ngrant_types = [\"authorization_code\"]\n\
             [[client]]\nclient_id = \"app\"\ntoken_endpoint_auth_method = \"none\"\n\
             redirect_uris = [\"https://app.example.org/callback\"]\n\
             grant_types = [\"authorization_code\", \"refresh_token\"]\n\
             [[client]]\nclient_id = \"admin\"\ntoken_endpoint_auth_method = \"private_key_jwt\"\njwks = {set}\n\
             scope = [\"system/admin\"]\ngrant_types = [\"client_credentials\"]\n{extra}",
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
        let providers = crate::support::providers(&settings).await;
        let state =
            Arc::new(AppState::new(settings.clone(), store.clone(), audit).with_login(providers));
        crate::support::apply(
            &state,
            &crate::support::clients(&crate::support::reach_every_base(&text)),
        )
        .await;
        crate::support::set_secret(&store, "vault", VAULT_SECRET).await;
        crate::support::set_secret(&store, "gateway", GATEWAY_SECRET).await;
        let app = router(state);
        Self {
            app,
            client_key,
            signing_key,
            keys: Arc::new(keys),
            settings,
            database: Some(database),
            store,
        }
    }

    /// Starts a second replica of the server: the same settings and keys,
    /// its own connection pool and application state, over the same
    /// database, as `docs/architecture.md` §13.9 runs replicas.
    pub(crate) async fn replica(&self) -> Self {
        let store = Store::connect(&self.settings.database_url, 2)
            .await
            .expect("connects");
        let audit = audit(&self.settings);
        let app = router(Arc::new(AppState::new(
            self.settings.clone(),
            store.clone(),
            audit,
        )));
        Self {
            app,
            client_key: self.client_key.clone(),
            signing_key: self.signing_key.clone(),
            keys: Arc::clone(&self.keys),
            settings: self.settings.clone(),
            database: None,
            store,
        }
    }

    /// Returns a fresh assertion of the confidential client `client`.
    pub(crate) fn assertion(&self, client: &str) -> String {
        let now = jiff::Timestamp::now().as_second();
        let claims = json!({"iss": client, "sub": client, "aud": TOKEN_URL, "exp": now + 120, "jti": unique()});
        self.client_key.sign("JWT", &claims).expect("signs")
    }

    /// Returns the form fields that authenticate the confidential client
    /// `client`.
    pub(crate) fn credentials(&self, client: &str) -> Vec<(String, String)> {
        vec![
            (
                String::from("client_assertion_type"),
                String::from(JWT_BEARER),
            ),
            (String::from("client_assertion"), self.assertion(client)),
        ]
    }

    /// Posts `form` to `path`, with `bearer` as the `Authorization`.
    pub(crate) async fn post(
        &self,
        path: &str,
        form: &[(String, String)],
        bearer: Option<&str>,
    ) -> Answer {
        self.post_authorized(path, form, bearer.map(|token| format!("Bearer {token}")))
            .await
    }

    /// Posts `form` to `path`, with `authorization` as the whole
    /// `Authorization` header.
    pub(crate) async fn post_authorized(
        &self,
        path: &str,
        form: &[(String, String)],
        authorization: Option<String>,
    ) -> Answer {
        let body: String = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        let mut request =
            Request::post(path).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(value) = authorization {
            request = request.header(header::AUTHORIZATION, value);
        }
        let request = request.body(Body::from(body)).expect("a request");
        let response = self
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

    /// Sends `method` to `path` with the JSON `body`, and `bearer` as the
    /// access token.
    pub(crate) async fn call(
        &self,
        method: http::Method,
        path: &str,
        body: Option<&Value>,
        bearer: Option<&str>,
    ) -> Answer {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(token) = bearer {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = match body {
            Some(body) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        }
        .expect("a request");
        let response = self
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

    /// Returns an access token the client credentials grant issues to
    /// `client` for `scope` at `resource`.
    pub(crate) async fn token(&self, client: &str, scope: &str, resource: &str) -> String {
        let mut form = self.credentials(client);
        form.extend([
            (
                String::from("grant_type"),
                String::from("client_credentials"),
            ),
            (String::from("scope"), scope.to_owned()),
            (String::from("resource"), resource.to_owned()),
        ]);
        let (status, _, body) = self.post("/token", &form, None).await;
        assert_eq!(StatusCode::OK, status, "{body}");
        body.get("access_token")
            .and_then(Value::as_str)
            .expect("a token")
            .to_owned()
    }

    /// Returns what `rs`, authenticated by its assertion, learns of `token`.
    pub(crate) async fn introspect(&self, token: &str) -> Value {
        let mut form = self.credentials("rs");
        form.push((String::from("token"), token.to_owned()));
        let (status, headers, body) = self.post("/introspect", &form, None).await;
        assert_eq!(StatusCode::OK, status, "{body}");
        assert_eq!(
            Some("no-store"),
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            "an introspection answer is never cached"
        );
        body
    }

    /// Records a grant of `client` about the person `alice`, with the
    /// launch context `context`, and returns its id.
    pub(crate) async fn grant(
        &self,
        client: &str,
        access: Option<Access>,
        session: Option<&str>,
        context: &Value,
    ) -> String {
        let id = unique();
        self.store
            .create_grant(&NewGrant {
                id: &id,
                client_id: client,
                subject: "alice",
                fhir_user: Some("Practitioner/7"),
                audience: RESOURCE,
                scope: "openid fhirUser launch/patient patient/Observation.rs offline_access",
                context,
                auth_time: Some(LOGGED_IN),
                access,
                upstream_session: session,
                basis: None,
                roles: &[],
                acr: Some(AssuranceLevel::Substantial),
                dpop_jkt: None,
            })
            .await
            .expect("recorded");
        id
    }

    /// Records a refresh token of the grant `grant_id` lapsing `lifetime`
    /// seconds from now (negative for one already lapsed), and returns its
    /// value.
    pub(crate) async fn refresh(&self, grant_id: &str, lifetime: i64) -> String {
        let value = unique();
        let expires = jiff::Timestamp::now().as_second() + lifetime;
        self.store
            .issue_refresh(&sha256(&value), grant_id, expires)
            .await
            .expect("recorded");
        value
    }

    /// Signs and records an access token of `client` under the grant
    /// `grant_id`, as the code flow issues one, lapsing `lifetime` seconds
    /// from now.
    pub(crate) async fn access(
        &self,
        client: &str,
        grant_id: Option<&str>,
        lifetime: i64,
    ) -> String {
        let now = jiff::Timestamp::now().as_second();
        let jti = unique();
        let scope = "patient/Observation.rs";
        let claims = json!({
            "iss": ISSUER, "sub": "alice", "aud": RESOURCE, "exp": now + lifetime, "iat": now,
            "jti": jti, "client_id": client, "scope": scope,
        });
        let token = self.signing_key.sign("at+jwt", &claims).expect("signs");
        self.store
            .record_token(&IssuedToken {
                jti: &jti,
                client_id: client,
                subject: "alice",
                audience: RESOURCE,
                scope,
                issued_at: now,
                expires_at: now + lifetime,
                code_hash: None,
                grant_id,
            })
            .await
            .expect("recorded");
        token
    }

    /// Returns the settings every replica starts on.
    pub(crate) const fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Returns the URL of the case's database.
    pub(crate) fn database_url(&self) -> String {
        secrecy::ExposeSecret::expose_secret(&self.database.as_ref().expect("a database").url)
            .to_owned()
    }

    /// Drops the database.
    pub(crate) async fn stop(mut self) {
        if let Some(database) = self.database.take() {
            database.drop(self.store).await;
        }
    }
}

/// The secret of the confidential symmetric client `vault`.
pub(crate) const VAULT_SECRET: &str = "synthetic vault secret";

/// The secret of the confidential symmetric client `gateway`.
pub(crate) const GATEWAY_SECRET: &str = "synthetic gateway secret";

/// Returns the Argon2id PHC hash of `secret` at the OWASP floor.
pub(crate) fn phc(secret: &str) -> String {
    ferrosmart::clients::hash_secret(secret).expect("hashes")
}

/// Returns an id no other value of the run carries.
pub(crate) fn unique() -> String {
    let mut bytes = [0_u8; 16];
    aws_lc_rs::rand::fill(&mut bytes).expect("draws");
    bytes.iter().fold(String::new(), |mut id, byte| {
        use std::fmt::Write as _;
        write!(id, "{byte:02x}").expect("a String takes every write");
        id
    })
}

/// The answer RFC 7662 §2.2 fixes for a token that is not active: "the
/// authorization server MUST return an introspection response with the
/// 'active' field set to 'false'", and nothing else here.
pub(crate) fn inactive() -> Value {
    json!({ "active": false })
}

#[tokio::test]
async fn an_active_backend_services_token_answers_what_smart_requires() {
    let server = Server::start().await;
    let token = server.token("export", "system/Patient.rs", RESOURCE).await;
    let answer = server.introspect(&token).await;
    // NOTE: SMART App Launch 2.2.0, Token Introspection, Required fields.
    assert_eq!(json!(true), answer["active"]);
    assert_eq!(json!("system/Patient.rs"), answer["scope"]);
    assert_eq!(json!("export"), answer["client_id"]);
    let exp = answer["exp"].as_i64().expect("an exp");
    let iat = answer["iat"].as_i64().expect("an iat");
    assert_eq!(300, exp - iat, "consistent with expires_in");
    // NOTE: RFC 7662 §2.2, the optional members this server carries.
    assert_eq!(json!("export"), answer["sub"]);
    assert_eq!(json!(RESOURCE), answer["aud"]);
    assert_eq!(json!(ISSUER), answer["iss"]);
    server.stop().await;
}

#[tokio::test]
async fn a_token_issued_under_a_grant_carries_its_launch_context() {
    let server = Server::start().await;
    let context = json!({"patient": "123", "need_patient_banner": true, "smart_style_url": "https://smart.example.org/style.json"});
    let grant = server
        .grant("app", Some(Access::Offline), None, &context)
        .await;
    let token = server.access("app", Some(&grant), 300).await;
    let answer = server.introspect(&token).await;
    assert_eq!(json!(true), answer["active"]);
    assert_eq!(json!("app"), answer["client_id"]);
    // NOTE: SMART App Launch 2.2.0, Token Introspection, Conditional fields: the
    // launch context of the token response, and the ID Token's sub and fhirUser.
    assert_eq!(json!("123"), answer["patient"]);
    assert_eq!(json!(true), answer["need_patient_banner"]);
    assert_eq!(context["smart_style_url"], answer["smart_style_url"]);
    assert_eq!(json!("alice"), answer["sub"]);
    assert_eq!(json!(ISSUER), answer["iss"]);
    assert_eq!(json!("Practitioner/7"), answer["fhirUser"]);
    // NOTE: RFC 9470 §6.2, the login's acr and auth_time.
    assert_eq!(
        json!("http://eidas.europa.eu/LoA/substantial"),
        answer["acr"]
    );
    assert_eq!(json!(LOGGED_IN), answer["auth_time"]);
    server.stop().await;
}

#[tokio::test]
async fn an_active_refresh_token_answers_its_grant() {
    let server = Server::start().await;
    let grant = server
        .grant(
            "app",
            Some(Access::Offline),
            None,
            &json!({"patient": "123"}),
        )
        .await;
    let refresh = server.refresh(&grant, 3600).await;
    let answer = server.introspect(&refresh).await;
    assert_eq!(json!(true), answer["active"]);
    assert_eq!(json!("app"), answer["client_id"]);
    assert_eq!(
        json!("openid fhirUser launch/patient patient/Observation.rs offline_access"),
        answer["scope"]
    );
    assert_eq!(json!("123"), answer["patient"]);
    assert!(answer["exp"].is_i64());
    server.stop().await;
}

#[tokio::test]
async fn an_unknown_or_forged_token_is_inactive() {
    let server = Server::start().await;
    assert_eq!(inactive(), server.introspect("not-a-token").await);
    assert_eq!(inactive(), server.introspect(&unique()).await);
    // A well-formed access token signed by a key the server does not hold.
    let other = Keys::new();
    let foreign_key = AssertionKey::from_pem(
        &std::fs::read(rsa_key(other.dir.path(), "forger.pem")).expect("reads"),
        Some(ferrohealth_smart::jws::algorithm::Algorithm::Rs256),
        Some(String::from(server.signing_key.kid())),
    )
    .expect("a key");
    let token = server.token("export", "system/Patient.rs", RESOURCE).await;
    let claims = jsonwebtoken::dangerous::insecure_decode_claims::<Value>(&token).expect("claims");
    let forged = foreign_key.sign("at+jwt", &claims).expect("signs");
    assert_eq!(
        inactive(),
        server.introspect(&forged).await,
        "the jti alone is not enough"
    );
    server.stop().await;
}

#[tokio::test]
async fn an_expired_token_is_inactive() {
    let server = Server::start().await;
    let grant = server
        .grant("app", Some(Access::Offline), None, &json!({}))
        .await;
    let access = server.access("app", Some(&grant), -10).await;
    assert_eq!(inactive(), server.introspect(&access).await);
    let refresh = server.refresh(&grant, -10).await;
    assert_eq!(inactive(), server.introspect(&refresh).await);
    server.stop().await;
}

#[tokio::test]
async fn a_revoked_grant_s_tokens_are_inactive() {
    let server = Server::start().await;
    let grant = server
        .grant("app", Some(Access::Offline), None, &json!({}))
        .await;
    let access = server.access("app", Some(&grant), 300).await;
    let refresh = server.refresh(&grant, 3600).await;
    let mut tx = server.store.begin().await.expect("begins");
    assert!(tx.revoke_grant(&grant).await.expect("revoked"));
    commit(tx).await;
    assert_eq!(inactive(), server.introspect(&access).await);
    assert_eq!(inactive(), server.introspect(&refresh).await);
    server.stop().await;
}

#[tokio::test]
async fn an_online_refresh_token_ends_with_its_upstream_session() {
    let server = Server::start().await;
    let session = unique();
    server
        .store
        .begin_session(
            &session,
            "https://idp.example.org",
            "upstream-alice",
            Some("sid-1"),
        )
        .await
        .expect("recorded");
    let grant = server
        .grant("app", Some(Access::Online), Some(&session), &json!({}))
        .await;
    let refresh = server.refresh(&grant, 3600).await;
    assert_eq!(json!(true), server.introspect(&refresh).await["active"]);
    let mut tx = server.store.begin().await.expect("begins");
    assert!(tx.end_session(&session).await.expect("ended"));
    commit(tx).await;
    // NOTE: docs/architecture.md §13.6 item 7, online_access ends with the upstream login.
    assert_eq!(inactive(), server.introspect(&refresh).await);
    server.stop().await;
}

// NOTE: RFC 9068 §2.2.3.1, roles are a person's; a Backend Services token has none.
#[tokio::test]
async fn a_backend_services_token_carries_no_roles() {
    let server = Server::start().await;
    let token = server.token("export", "system/Patient.rs", RESOURCE).await;
    let claims: Value = jsonwebtoken::dangerous::insecure_decode_claims(&token).expect("claims");
    assert_eq!(Value::Null, claims["roles"]);
    assert_eq!(Value::Null, server.introspect(&token).await["roles"]);
    server.stop().await;
}

// NOTE: RFC 9068 §2.2.3.1; the introspection answer carries what the JWT does.
#[tokio::test]
async fn a_person_s_token_answers_their_mapped_roles() {
    let server = Server::start().await;
    let id = unique();
    let roles = [String::from("clinician"), String::from("emergency")];
    server
        .store
        .create_grant(&NewGrant {
            id: &id,
            client_id: "portal",
            subject: "alice",
            fhir_user: Some("Practitioner/7"),
            audience: RESOURCE,
            scope: "openid user/Observation.rs",
            context: &json!({}),
            auth_time: Some(jiff::Timestamp::now().as_second()),
            access: None,
            upstream_session: None,
            roles: &roles,
            basis: None,
            acr: None,
            dpop_jkt: None,
        })
        .await
        .expect("recorded");
    let token = server.access("portal", Some(&id), 300).await;
    assert_eq!(
        json!(["clinician", "emergency"]),
        server.introspect(&token).await["roles"]
    );
    server.stop().await;
}

#[tokio::test]
async fn a_bearer_token_with_the_introspection_scope_may_introspect() {
    let server = Server::start().await;
    let target = server.token("export", "system/Patient.rs", RESOURCE).await;
    // NOTE: SMART App Launch 2.2.0, Token Introspection, Authorization to perform
    // Token Introspection: a SMART Backend Service bearer token.
    let bearer = server.token("rs", "system/introspect", ISSUER).await;
    let form = vec![(String::from("token"), target)];
    let (status, _, body) = server.post("/introspect", &form, Some(&bearer)).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    assert_eq!(json!(true), body["active"]);
    assert_eq!(json!("export"), body["client_id"]);
    server.stop().await;
}

#[tokio::test]
async fn a_bearer_token_without_the_right_is_refused_with_a_401() {
    let server = Server::start().await;
    let target = server.token("export", "system/Patient.rs", RESOURCE).await;
    let form = vec![(String::from("token"), target.clone())];
    // NOTE: RFC 7662 §2.3, HTTP 401 as RFC 6750 §3 describes.
    let cases = [
        (
            target.clone(),
            "invalid_token",
            "a token for another resource server",
        ),
        (
            server.token("export", "system/Patient.rs", ISSUER).await,
            "insufficient_scope",
            "a token for this server without the scope",
        ),
        (unique(), "invalid_token", "no token this server issued"),
    ];
    for (bearer, error, case) in cases {
        let (status, headers, _) = server.post("/introspect", &form, Some(&bearer)).await;
        assert_eq!(StatusCode::UNAUTHORIZED, status, "{case}");
        assert_eq!(
            Some(format!("Bearer error=\"{error}\"").as_str()),
            headers
                .get(header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok()),
            "{case}"
        );
    }
    server.stop().await;
}

#[tokio::test]
async fn a_client_without_the_right_is_refused_with_a_401() {
    let server = Server::start().await;
    let target = server.token("export", "system/Patient.rs", RESOURCE).await;
    let token = (String::from("token"), target);
    // NOTE: RFC 7662 §2.1, the endpoint MUST require authorization.
    let mut unauthenticated = vec![token.clone()];
    let (status, _, body) = server.post("/introspect", &unauthenticated, None).await;
    assert_eq!(StatusCode::UNAUTHORIZED, status);
    assert_eq!(json!("invalid_client"), body["error"]);
    unauthenticated.push((String::from("client_id"), String::from("app")));
    let (status, _, body) = server.post("/introspect", &unauthenticated, None).await;
    assert_eq!(
        StatusCode::UNAUTHORIZED,
        status,
        "a public client cannot authenticate"
    );
    assert_eq!(json!("invalid_client"), body["error"]);
    let mut export = server.credentials("export");
    export.push(token);
    let (status, _, body) = server.post("/introspect", &export, None).await;
    assert_eq!(StatusCode::UNAUTHORIZED, status);
    assert_eq!(json!("unauthorized_client"), body["error"]);
    server.stop().await;
}

#[tokio::test]
async fn a_request_without_a_token_is_malformed() {
    let server = Server::start().await;
    let (status, _, body) = server
        .post("/introspect", &server.credentials("rs"), None)
        .await;
    assert_eq!(StatusCode::BAD_REQUEST, status);
    assert_eq!(json!("invalid_request"), body["error"]);
    server.stop().await;
}
