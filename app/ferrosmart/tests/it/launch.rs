// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The EHR launch API against a real PostgreSQL (`docs/architecture.md`
//! §13.6 item 3, our own design): a launch registered at `POST /launch` by
//! an EHR client authenticated with its `private_key_jwt` assertion, and a
//! launch JWT the EHR signs, each redeemed once, within its lifetime, by
//! the app and at the resource server it names, every refusal its own case.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use ferrohealth_smart::client::assertion::AssertionKey;
use ferrosmart::audit::{Event, Happening};
use ferrosmart::launch::context::Context;
use ferrosmart::launch::{Unresolved, redeem};
use ferrosmart::server::{AppState, router};
use ferrosmart::store::Store;
use ferrosmart::store::launch::NewLaunch;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt as _;
use jsonwebtoken::Algorithm;
use serde_json::{Value, json};
use sqlx::Connection as _;
use tower::ServiceExt as _;

use crate::support::{
    CLIENT_ADDRESS, Database, Keys, RESOURCE, audit, config, ec_key, events, from_client, records,
    rsa_key,
};

/// The issuer every case configures.
const ISSUER: &str = "https://smart.example.org";
/// The token endpoint of [`ISSUER`], the audience of a client assertion.
const TOKEN_URL: &str = "https://smart.example.org/token";
/// The openEHR resource server every case configures beside [`RESOURCE`].
const OPENEHR: &str = "https://ehr.example.org/openehr/rest/v1";
/// The assertion type of RFC 7523 §2.2.
const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// A running server over a fresh database with an EHR client `ehr`, a
/// Backend Services client `export` that may not launch, and the apps
/// `app` and `other`.
struct Server {
    /// The state, for the authorization endpoint's resolution.
    state: Arc<AppState>,
    /// The application.
    app: Router,
    /// The EHR's signing key.
    ehr: AssertionKey,
    /// The signing key of `export`.
    export: AssertionKey,
    /// The keys, kept for the case's length.
    _keys: Keys,
    /// The database.
    database: Option<Database>,
    /// The store.
    store: Store,
}

impl Server {
    /// Starts the server.
    async fn start() -> Self {
        let keys = Keys::new();
        let ehr = client_key(&keys, "ehr", Algorithm::ES384);
        let export = client_key(&keys, "export", Algorithm::RS384);
        let database = Database::create().await;
        let text = format!(
            "[ferrosmart]\nissuer = {ISSUER:?}\n[ferrosmart.database]\nurl = {:?}\n\
             [[ferrosmart.resource]]\nbase = {RESOURCE:?}\n\
             [[ferrosmart.resource]]\nbase = {OPENEHR:?}\nkind = \"openehr\"\n\
             [[client]]\nclient_id = \"ehr\"\ntoken_endpoint_auth_method = \"private_key_jwt\"\n\
             jwks = {}\nscope = [\"system/launch.c\"]\ngrant_types = [\"client_credentials\"]\n\
             [[client]]\nclient_id = \"export\"\ntoken_endpoint_auth_method = \"private_key_jwt\"\n\
             jwks = {}\nscope = [\"system/Patient.rs\"]\ngrant_types = [\"client_credentials\"]\n\
             [[client]]\nclient_id = \"app\"\ntoken_endpoint_auth_method = \"none\"\n\
             redirect_uris = [\"https://app.example.org/callback\"]\ngrant_types = [\"authorization_code\"]\n\
             launch_uri = \"https://app.example.org/launch\"\n\
             [[client]]\nclient_id = \"other\"\ntoken_endpoint_auth_method = \"none\"\n\
             redirect_uris = [\"https://other.example.org/callback\"]\ngrant_types = [\"authorization_code\"]\n\
             [[client]]\nclient_id = \"fhir-only\"\ntoken_endpoint_auth_method = \"none\"\n\
             redirect_uris = [\"https://fhir-only.example.org/callback\"]\ngrant_types = [\"authorization_code\"]\n\
             resources = [{RESOURCE:?}]",
            secrecy::ExposeSecret::expose_secret(&database.url),
            jwks(&ehr),
            jwks(&export),
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
        let app = router(Arc::clone(&state));
        Self {
            state,
            app,
            ehr,
            export,
            _keys: keys,
            database: Some(database),
            store,
        }
    }

    /// Posts `form` to the launch API and returns the status, the headers
    /// and the JSON body.
    async fn post(&self, form: &[(&str, &str)]) -> (StatusCode, http::HeaderMap, Value) {
        let body: String = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        self.post_raw("application/x-www-form-urlencoded", body)
            .await
    }

    /// Posts `body` as `content_type` to the launch API.
    async fn post_raw(
        &self,
        content_type: &str,
        body: String,
    ) -> (StatusCode, http::HeaderMap, Value) {
        let request = Request::post("/launch")
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(body))
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

    /// Returns a fresh client assertion of `client_id` signed by `key`.
    fn assertion(key: &AssertionKey, client_id: &str) -> String {
        let now = jiff::Timestamp::now().as_second();
        let claims = json!({"iss": client_id, "sub": client_id, "aud": TOKEN_URL, "exp": now + 120, "jti": unique()});
        key.sign("JWT", &claims).expect("signs")
    }

    /// Registers a launch of `ehr` for `app` at `resource` with `context`
    /// and returns the answer.
    async fn register(
        &self,
        app: &str,
        resource: &str,
        context: &[(&str, &str)],
    ) -> (StatusCode, http::HeaderMap, Value) {
        let assertion = Self::assertion(&self.ehr, "ehr");
        let mut form = vec![
            ("client_assertion_type", JWT_BEARER),
            ("client_assertion", assertion.as_str()),
            ("app_client_id", app),
            ("resource", resource),
        ];
        form.extend_from_slice(context);
        self.post(&form).await
    }

    /// Returns a launch JWT of the EHR over `claims`, typed `typ`.
    fn launch_jwt(&self, typ: &str, claims: &Value) -> String {
        self.ehr.sign(typ, claims).expect("signs")
    }

    /// Redeems `launch` for `app` at `resource`, as the authorization
    /// endpoint does with the `launch` scope requested.
    async fn resolve(&self, launch: &str, app: &str, resource: &str) -> Result<Context, String> {
        let from = CLIENT_ADDRESS.parse().expect("an address");
        let redeemed = redeem(&self.state, app, launch, resource, "openid launch", from).await;
        assert!(
            !matches!(redeemed, Err(Unresolved::Store(_))),
            "the store answers: {redeemed:?}"
        );
        redeemed.map_err(|refusal| refusal.to_string())
    }

    /// Drops the database.
    async fn stop(mut self) {
        if let Some(database) = self.database.take() {
            database.drop(self.store).await;
        }
    }
}

/// Returns a fresh key of `client_id` under `algorithm`.
fn client_key(keys: &Keys, client_id: &str, algorithm: Algorithm) -> AssertionKey {
    let name = format!("{client_id}.pem");
    let path = if algorithm == Algorithm::ES384 {
        ec_key(keys.dir.path(), &name)
    } else {
        rsa_key(keys.dir.path(), &name)
    };
    let pem = std::fs::read(path).expect("the key reads");
    AssertionKey::from_pem(
        &pem,
        Some(crate::support::jws_algorithm(algorithm)),
        Some(format!("{client_id}-1")),
    )
    .expect("a client key")
}

/// Writes the JWK Set of `key` and returns its path.
fn jwks(key: &AssertionKey) -> String {
    crate::support::inline(&json!({"keys": [key.public_jwk()]}))
}

/// Returns an id no other JWT of the run carries.
fn unique() -> String {
    let mut bytes = [0_u8; 12];
    aws_lc_rs::rand::fill(&mut bytes).expect("draws");
    bytes.iter().fold(String::new(), |mut id, byte| {
        use std::fmt::Write as _;
        write!(id, "{byte:02x}").expect("a String takes every write");
        id
    })
}

/// Returns the claims of a valid launch JWT of the EHR for `app` at
/// [`RESOURCE`], in the context of patient `123`.
fn launch_claims(app: &str) -> Value {
    let now = jiff::Timestamp::now().as_second();
    json!({
        "iss": "ehr", "aud": ISSUER, "exp": now + 120, "iat": now, "jti": unique(),
        "client_id": app, "resource": RESOURCE,
        "patient": "123", "need_patient_banner": false
    })
}

/// Returns the `error` of a refusal, asserting the status and that the
/// answer is never cached.
fn refused(answer: &(StatusCode, http::HeaderMap, Value)) -> String {
    assert_eq!(StatusCode::BAD_REQUEST, answer.0, "{:?}", answer.2);
    assert_eq!(
        Some("no-store"),
        answer
            .1
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        "a refusal is never cached"
    );
    assert!(
        answer
            .2
            .get("error_description")
            .is_some_and(Value::is_string),
        "{:?}",
        answer.2
    );
    answer
        .2
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn an_ehr_registers_a_launch_the_app_redeems_once() {
    let server = Server::start().await;
    let fhir_context = r#"[{"reference":"DiagnosticReport/7"},{"reference":"List/1","role":"https://example.org/med-list-at-home"}]"#;
    let (status, headers, body) = server
        .register(
            "app",
            RESOURCE,
            &[
                ("patient", "123"),
                ("encounter", "456"),
                ("fhirContext", fhir_context),
                ("intent", "reconcile-medications"),
                ("need_patient_banner", "false"),
                ("tenant", "2ddd6c3a"),
            ],
        )
        .await;
    // NOTE: RFC 9126 §2.2, the shape the API follows: 201 with the handle and
    // its lifetime, never cached.
    assert_eq!(StatusCode::CREATED, status, "{body}");
    assert_eq!(
        Some("no-store"),
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
    );
    assert_eq!(json!(300), body["expires_in"]);
    let launch = body["launch"].as_str().expect("a launch value");
    assert_eq!(43, launch.len(), "256 bits, base64url");

    let context = server
        .resolve(launch, "app", RESOURCE)
        .await
        .expect("redeemed");
    assert_eq!(
        json!({
            "patient": "123", "encounter": "456",
            "fhirContext": serde_json::from_str::<Value>(fhir_context).expect("JSON"),
            "intent": "reconcile-medications", "need_patient_banner": false,
            "tenant": "2ddd6c3a"
        }),
        serde_json::to_value(&context).expect("JSON"),
        "the token response's context parameters, as SMART names them"
    );
    assert!(
        server.resolve(launch, "app", RESOURCE).await.is_err(),
        "a launch is redeemed once"
    );
    server.stop().await;
}

// NOTE: RFC 8707 §2, an app whose `resources` does not list the base gets no
// launch for it, as its authorization request would be refused.
#[tokio::test]
async fn a_launch_names_only_a_base_the_app_s_resources_list() {
    let server = Server::start().await;
    let (status, _, _) = server.register("fhir-only", RESOURCE, &[]).await;
    assert_eq!(StatusCode::CREATED, status);
    let answer = server.register("fhir-only", OPENEHR, &[]).await;
    assert_eq!("invalid_target", refused(&answer));
    server.stop().await;
}

#[tokio::test]
async fn a_launch_is_bound_to_its_app_and_resource_server() {
    let server = Server::start().await;
    let (status, _, body) = server.register("app", RESOURCE, &[("patient", "1")]).await;
    assert_eq!(StatusCode::CREATED, status, "{body}");
    let launch = body["launch"].as_str().expect("a launch value");
    assert!(server.resolve(launch, "other", RESOURCE).await.is_err());
    assert!(server.resolve(launch, "app", OPENEHR).await.is_err());
    assert!(
        server
            .resolve("not-a-launch", "app", RESOURCE)
            .await
            .is_err()
    );
    assert!(
        server.resolve(launch, "app", RESOURCE).await.is_ok(),
        "a refused attempt leaves the launch unredeemed"
    );

    let (status, _, body) = server
        .register(
            "app",
            OPENEHR,
            &[("ehrId", "7d44b88c-4199-4bad-97dc-d78268e01398")],
        )
        .await;
    assert_eq!(
        StatusCode::CREATED,
        status,
        "an ehrId for an openEHR server"
    );
    let launch = body["launch"].as_str().expect("a launch value");
    let context = server
        .resolve(launch, "app", OPENEHR)
        .await
        .expect("redeemed");
    assert_eq!(
        Some("7d44b88c-4199-4bad-97dc-d78268e01398"),
        context.ehr_id.as_deref()
    );
    server.stop().await;
}

#[tokio::test]
async fn a_lapsed_launch_is_refused() {
    let server = Server::start().await;
    let context = Context {
        patient: Some(String::from("1")),
        ..Context::default()
    };
    let launch = "lapsed-launch-value";
    // The SHA-256 of `lapsed-launch-value`, base64url, as the store keeps it.
    let hash = {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(aws_lc_rs::digest::digest(
            &aws_lc_rs::digest::SHA256,
            launch.as_bytes(),
        ))
    };
    let mut tx = server.store.begin().await.expect("a transaction");
    tx.record_launch(&NewLaunch {
        launch_hash: &hash,
        ehr_client_id: "ehr",
        client_id: "app",
        audience: RESOURCE,
        context: &context,
        expires_at: jiff::Timestamp::now().as_second() - 1,
    })
    .await
    .expect("recorded");
    let endpoint = url::Url::parse(ISSUER).expect("a URL");
    let happening = Happening {
        event: Event::LaunchRegistered,
        issuer: ISSUER,
        client_id: Some("ehr"),
        subject: None,
        from: CLIENT_ADDRESS.parse().expect("an address"),
        endpoint: &endpoint,
        details: Vec::new(),
    };
    server
        .state
        .audit()
        .commit_happening(tx, &happening)
        .await
        .expect("committed");
    assert!(server.resolve(launch, "app", RESOURCE).await.is_err());
    server.store.sweep().await.expect("swept");
    server.stop().await;
}

#[tokio::test]
async fn a_launch_registration_breaking_a_rule_is_refused() {
    let server = Server::start().await;
    let refusal = |answer| refused(&answer);

    // NOTE: RFC 9126 §2.1, the EHR authenticates as at the token endpoint.
    let unauthenticated = server
        .post(&[("app_client_id", "app"), ("resource", RESOURCE)])
        .await;
    assert_eq!("invalid_client", refusal(unauthenticated));
    let assertion = Server::assertion(&server.export, "export");
    let not_an_ehr = server
        .post(&[
            ("client_assertion_type", JWT_BEARER),
            ("client_assertion", &assertion),
            ("app_client_id", "app"),
            ("resource", RESOURCE),
        ])
        .await;
    assert_eq!("unauthorized_client", refusal(not_an_ehr));
    let assertion = Server::assertion(&server.ehr, "ehr");
    let form = [
        ("client_assertion_type", JWT_BEARER),
        ("client_assertion", assertion.as_str()),
        ("app_client_id", "app"),
        ("resource", RESOURCE),
    ];
    let (status, _, _) = server.post(&form).await;
    assert_eq!(StatusCode::CREATED, status);
    assert_eq!(
        "invalid_client",
        refusal(server.post(&form).await),
        "a replayed assertion"
    );

    for (app, resource, context, error) in [
        ("export", RESOURCE, vec![], "invalid_request"),
        ("nobody", RESOURCE, vec![], "invalid_request"),
        (
            "app",
            "https://elsewhere.example.org/fhir",
            vec![],
            "invalid_target",
        ),
        ("app", RESOURCE, vec![("ehrId", "e1")], "invalid_request"),
        (
            "app",
            RESOURCE,
            vec![("fhirContext", "{}")],
            "invalid_request",
        ),
        (
            "app",
            RESOURCE,
            vec![("fhirContext", r#"[{"reference":"Patient/1"}]"#)],
            "invalid_request",
        ),
        (
            "app",
            RESOURCE,
            vec![("need_patient_banner", "yes")],
            "invalid_request",
        ),
        (
            "app",
            RESOURCE,
            vec![("smart_style_url", "v1.json")],
            "invalid_request",
        ),
        (
            "app",
            RESOURCE,
            vec![("need_patient_baner", "true")],
            "invalid_request",
        ),
    ] {
        let answer = server.register(app, resource, &context).await;
        assert_eq!(error, refusal(answer), "{app} {resource} {context:?}");
    }
    let no_app = server.register("", RESOURCE, &[]).await;
    assert_eq!("invalid_request", refusal(no_app));
    let json_body = server
        .post_raw("application/json", String::from("{}"))
        .await;
    assert_eq!("invalid_request", refusal(json_body));
    server.stop().await;
}

#[tokio::test]
async fn an_ehr_signed_launch_jwt_is_redeemed_once() {
    let server = Server::start().await;
    let jwt = server.launch_jwt("launch+jwt", &launch_claims("app"));
    assert!(
        server.resolve(&jwt, "other", RESOURCE).await.is_err(),
        "bound to its app"
    );
    let context = server
        .resolve(&jwt, "app", RESOURCE)
        .await
        .expect("redeemed");
    assert_eq!(Some("123"), context.patient.as_deref());
    assert_eq!(Some(false), context.need_patient_banner);
    assert!(
        server.resolve(&jwt, "app", RESOURCE).await.is_err(),
        "the jti is refused a second time"
    );
    server.stop().await;
}

#[tokio::test]
async fn a_launch_jwt_breaking_a_rule_is_refused() {
    let server = Server::start().await;
    let now = jiff::Timestamp::now().as_second();
    let with = |member: &str, value: Value| {
        let mut claims = launch_claims("app");
        claims[member] = value;
        claims
    };
    let without = |member: &str| {
        let mut claims = launch_claims("app");
        claims.as_object_mut().expect("an object").remove(member);
        claims
    };
    let cases = [
        ("JWT", launch_claims("app"), "typ"),
        (
            "launch+jwt",
            with("exp", json!(now - 120)),
            "does not verify",
        ),
        ("launch+jwt", with("exp", json!(now + 3600)), "five minutes"),
        ("launch+jwt", with("aud", json!([ISSUER])), "aud"),
        ("launch+jwt", with("aud", json!(TOKEN_URL)), "aud"),
        (
            "launch+jwt",
            with("resource", json!("https://elsewhere.example.org/fhir")),
            "resource",
        ),
        ("launch+jwt", with("ehrId", json!("e1")), "ehrId"),
        (
            "launch+jwt",
            with("patiant", json!("1")),
            "no context parameter",
        ),
        ("launch+jwt", with("iss", json!("export")), "may launch"),
        ("launch+jwt", without("jti"), "jti"),
        ("launch+jwt", without("client_id"), "client_id"),
        ("launch+jwt", without("resource"), "resource"),
    ];
    for (typ, claims, rule) in cases {
        let jwt = server.launch_jwt(typ, &claims);
        let refusal = server
            .resolve(&jwt, "app", RESOURCE)
            .await
            .expect_err("refused");
        assert!(refusal.contains(rule), "{typ} {claims}: {refusal}");
    }
    let by_export = server
        .export
        .sign("launch+jwt", &with("iss", json!("export")))
        .expect("signs");
    assert!(
        server.resolve(&by_export, "app", RESOURCE).await.is_err(),
        "a client that may not launch"
    );
    let jwt = server.launch_jwt("launch+jwt", &launch_claims("app"));
    let mut tampered = jwt.clone();
    let last = tampered.pop();
    tampered.push(if last == Some('x') { 'y' } else { 'x' });
    assert!(server.resolve(&tampered, "app", RESOURCE).await.is_err());
    server.stop().await;
}

#[tokio::test]
async fn a_registration_a_redemption_and_a_refusal_are_recorded_without_the_launch() {
    let server = Server::start().await;
    let (status, _, body) = server
        .register(
            "app",
            RESOURCE,
            &[("patient", "synthetic-patient-in-context")],
        )
        .await;
    assert_eq!(StatusCode::CREATED, status, "{body}");
    let launch = body["launch"].as_str().expect("a launch value");
    server
        .resolve(launch, "app", RESOURCE)
        .await
        .expect("redeemed");
    assert!(server.resolve(launch, "app", RESOURCE).await.is_err());
    let unknown = server.register("nobody", RESOURCE, &[]).await;
    assert_eq!(StatusCode::BAD_REQUEST, unknown.0);

    // NOTE: docs/architecture.md §13.6 item 3, each launch write commits with
    // its record, and a refusal is recorded on its own.
    let records = records(&server.store).await;
    let kinds = events(&records);
    for (event, count) in [
        ("launch-registered", 1),
        ("launch-redeemed", 1),
        ("launch-refused", 2),
    ] {
        assert_eq!(
            count,
            kinds.iter().filter(|kind| *kind == event).count(),
            "{event}: {kinds:?}"
        );
    }
    let text = serde_json::to_string(&records).expect("JSON");
    assert!(!text.contains(launch), "no record holds the launch value");
    assert!(
        !text.contains("synthetic-patient-in-context"),
        "no record holds a context value"
    );
    server.stop().await;
}

#[tokio::test]
async fn a_launch_whose_record_cannot_be_committed_is_not_kept() {
    let server = Server::start().await;
    let (status, _, body) = server.register("app", RESOURCE, &[]).await;
    assert_eq!(StatusCode::CREATED, status, "{body}");
    let launch = body["launch"].as_str().expect("a launch value").to_owned();
    let url = server.database.as_ref().expect("a database").url.clone();
    let mut connection = sqlx::PgConnection::connect(secrecy::ExposeSecret::expose_secret(&url))
        .await
        .expect("connects");
    sqlx::query("ALTER TABLE audit_record RENAME TO audit_record_gone")
        .execute(&mut connection)
        .await
        .expect("the table moves");
    let (status, _, _) = server.register("app", RESOURCE, &[]).await;
    assert_ne!(
        StatusCode::CREATED,
        status,
        "a registration with no record fails"
    );
    assert!(
        server.resolve(&launch, "app", RESOURCE).await.is_err(),
        "a redemption with no record fails"
    );
    sqlx::query("ALTER TABLE audit_record_gone RENAME TO audit_record")
        .execute(&mut connection)
        .await
        .expect("the table returns");
    let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM launch")
        .fetch_one(&mut connection)
        .await
        .expect("counts");
    assert_eq!(1, kept, "only the first launch was kept");
    server
        .resolve(&launch, "app", RESOURCE)
        .await
        .expect("the launch stayed unredeemed");
    server.stop().await;
}

/// The `appContext` of the IG's `Task-task-for-ehr-launch.json`.
const APP_CONTEXT: &str = r#"{"field1":"value"}"#;

// NOTE: SMART App Launch 2.2.0, Task profile for requesting a SMART launch: a
// Task names the app by its launch URL and may carry appContext; naming the app
// by it and carrying appContext as context are our own design (#659, #660).
#[tokio::test]
async fn an_ehr_names_the_app_by_its_launch_url_and_passes_its_app_context() {
    let server = Server::start().await;
    let assertion = Server::assertion(&server.ehr, "ehr");
    let registration = |app: Vec<(&'static str, String)>| {
        let mut form: Vec<(&str, String)> = vec![
            ("client_assertion_type", JWT_BEARER.to_owned()),
            ("client_assertion", assertion.clone()),
            ("resource", RESOURCE.to_owned()),
        ];
        form.extend(app);
        form
    };
    let post = |form: Vec<(&'static str, String)>| {
        let pairs: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let body: String = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        server.post_raw("application/x-www-form-urlencoded", body)
    };
    // NOTE: RFC 3986 §6.2.2, case, port and percent-encoding normalized.
    let (status, _, body) = post(registration(vec![
        (
            "app_launch_uri",
            String::from("HTTPS://App.Example.ORG:443/%6Caunch"),
        ),
        ("appContext", String::from(APP_CONTEXT)),
    ]))
    .await;
    assert_eq!(StatusCode::CREATED, status, "{body}");
    let launch = body["launch"].as_str().expect("a launch value");
    let context = server
        .resolve(launch, "app", RESOURCE)
        .await
        .expect("redeemed for the app the URL names");
    assert_eq!(
        json!({"appContext": APP_CONTEXT}),
        serde_json::to_value(&context).expect("JSON"),
        "passed on unchanged"
    );

    let refusals = [
        (
            vec![
                ("app_client_id", String::from("app")),
                (
                    "app_launch_uri",
                    String::from("https://app.example.org/launch"),
                ),
            ],
            "both",
        ),
        (Vec::new(), "neither"),
        (
            vec![(
                "app_launch_uri",
                String::from("https://unknown.example.org/launch"),
            )],
            "app_launch_uri",
        ),
        (
            vec![
                ("app_client_id", String::from("app")),
                ("appContext", "x".repeat(8193)),
            ],
            "appContext",
        ),
    ];
    for (app, named) in refusals {
        let mut form: Vec<(&str, String)> = vec![
            ("client_assertion_type", JWT_BEARER.to_owned()),
            ("client_assertion", Server::assertion(&server.ehr, "ehr")),
            ("resource", RESOURCE.to_owned()),
        ];
        form.extend(app);
        let answer = post(form).await;
        assert_eq!("invalid_request", refused(&answer), "{named}");
        let description = answer.2["error_description"].as_str().unwrap_or_default();
        assert!(
            named == "both" || named == "neither" || description.contains(named),
            "{named}: {description}"
        );
    }
    server.stop().await;
}
