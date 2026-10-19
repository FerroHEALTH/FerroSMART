// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The guard in front of an axum router: the `401` of a missing or invalid
//! credential, the `400` of two credentials, the `403` of a token without
//! the permission, the patient compartment a handler holds a token to, the
//! Basic credential, the open surface, the extractor, and the one audit
//! line of every request with its fixed fields.

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::sync::Arc;
use std::sync::Mutex;

use argon2::Argon2;
use argon2::password_hash::PasswordHasher;
use axum::Router;
use axum::body::Body;
use axum::extract::MatchedPath;
use axum::response::Response;
use axum::routing::get;
use axum::routing::post;
use ferrohealth_smart::audit::AUDIT_TARGET;
use ferrohealth_smart::basic::Credential;
use ferrohealth_smart::basic::PasswordStore;
use ferrohealth_smart::extract::HeaderOnly;
use ferrohealth_smart::guard::AnsweredAs;
use ferrohealth_smart::guard::AuthLayer;
use ferrohealth_smart::guard::Classify;
use ferrohealth_smart::guard::Gate;
use ferrohealth_smart::guard::Requirement;
use ferrohealth_smart::guard::Target;
use ferrohealth_smart::refusal::Refusal;
use ferrohealth_smart::resource::Access;
use ferrohealth_smart::resource::Verifier;
use ferrohealth_smart::scope::Permission;
use http::Extensions;
use http::Method;
use http::Request;
use http::StatusCode;
use http::Uri;
use http::header;
use http_body_util::BodyExt as _;
use jsonwebtoken::Algorithm;
use secrecy::SecretString;
use tower::ServiceExt as _;

use crate::support::Issuer;
use crate::support::SigningKey;
use crate::support::ec_key;
use crate::support::mint;
use crate::support::server;

/// The route table of the cases, a FHIR-like surface under `/fhir`, read
/// from the template axum matched.
///
/// `GET /fhir/metadata` is public, `GET /fhir/{type}/{id}` needs `r` on the
/// type, `POST /fhir/{type}` needs `c`, `POST /fhir/{type}/$check` needs
/// `c` on the type or the operator scope, `GET /fhir/open` any caller,
/// `/fhir/unknown` is refused, and `/health` is outside the guard.
fn classify(_method: &Method, uri: &Uri, extensions: &Extensions) -> Option<Target> {
    let template = extensions.get::<MatchedPath>()?.as_str().to_owned();
    let mut segments = uri.path().trim_start_matches("/fhir/").split('/');
    let first = segments.next().map(str::to_owned);
    let second = segments.next().map(str::to_owned);
    let target = match template.as_str() {
        "/fhir/metadata" => Target::new("capabilities", Requirement::Public),
        "/fhir/open" => Target::new("open", Requirement::Caller),
        "/fhir/{resource_type}/$check" => Target::new(
            "operation",
            Requirement::Either(
                Box::new(fhir(Permission::Create, first.clone())),
                Box::new(Requirement::Scope(String::from("__operator"))),
            ),
        )
        .target(format!("{}/$check", first.unwrap_or_default())),
        "/fhir/{resource_type}/{id}" => Target::new("read", fhir(Permission::Read, first.clone()))
            .target(format!(
                "{}/{}",
                first.unwrap_or_default(),
                second.unwrap_or_default()
            )),
        "/fhir/{resource_type}" => Target::new("create", fhir(Permission::Create, first.clone()))
            .target(first.unwrap_or_default()),
        "/health" => return None,
        _ => Target::new("unclassified", Requirement::Refused),
    };
    Some(target.route(template))
}

/// Returns the FHIR requirement of `permission` on `resource_type`.
fn fhir(permission: Permission, resource_type: Option<String>) -> Requirement {
    Requirement::Fhir {
        permission,
        resource_type: resource_type.unwrap_or_default(),
    }
}

/// Renders a refusal over a text body naming its reason, as a product's own
/// body would, with the status and challenge of [`HeaderOnly`].
fn render(refusal: &Refusal) -> Response {
    HeaderOnly::with_realm("ferro").respond(
        refusal,
        Body::from(format!("refused: {}", refusal.reason())),
    )
}

/// The handler every guarded route runs: it answers the subject the guard
/// admitted and, for a read of `Condition/p-2-only`, holds a patient token
/// to the patient `p-2`.
async fn handler(access: Access, request: Request<Body>) -> Response {
    let subject = access
        .caller()
        .map_or("open", |caller| caller.subject())
        .to_owned();
    if request.uri().path() == "/fhir/Condition/p-2-only" {
        let admitted = access
            .reach(Permission::Read, "Condition")
            .is_some_and(|compartment| compartment.admits(Some("p-2")));
        if !admitted {
            return render(&Refusal::Forbidden);
        }
    }
    let mut response = Response::new(Body::from(format!("hello {subject}")));
    if request.uri().path() == "/fhir/Bundle" {
        response.extensions_mut().insert(AnsweredAs("batch"));
    }
    response
}

/// A handler outside the guard, whose extractor finds no access.
async fn outside(access: Access) -> String {
    access
        .caller()
        .map_or(String::from("open"), |caller| caller.subject().to_owned())
}

/// Returns the router of the cases under `layer`.
fn app<C: Classify>(layer: AuthLayer<C>) -> Router {
    Router::new()
        .route("/fhir/metadata", get(handler))
        .route("/fhir/open", get(handler))
        .route("/fhir/unknown", get(handler))
        .route("/fhir/{resource_type}", post(handler))
        .route("/fhir/{resource_type}/$check", post(handler))
        .route("/fhir/{resource_type}/{id}", get(handler))
        .route("/health", get(outside))
        .layer(layer)
}

/// One captured audit line, field by field.
#[derive(Debug, Clone, Default)]
struct Line(BTreeMap<String, String>);

impl Line {
    /// Returns the field `name`, or an empty string.
    fn field(&self, name: &str) -> &str {
        self.0.get(name).map_or("", String::as_str)
    }

    /// Returns the names of the fields on the line.
    fn names(&self) -> Vec<&str> {
        self.0.keys().map(String::as_str).collect()
    }
}

impl tracing::field::Visit for Line {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0.insert(field.name().to_owned(), value.to_string());
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.0.insert(field.name().to_owned(), value.to_string());
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.0.insert(field.name().to_owned(), value.to_string());
    }
}

/// A subscriber that keeps every audit line, so a case reads what was
/// recorded.
#[derive(Debug, Default)]
struct Capture {
    /// The lines, in order.
    lines: Mutex<Vec<Line>>,
}

impl Capture {
    fn lines(&self) -> Vec<Line> {
        self.lines.lock().expect("not poisoned").clone()
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == AUDIT_TARGET
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut line = Line::default();
        event.record(&mut line);
        self.lines.lock().expect("not poisoned").push(line);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

/// One case: the issuer, its key, the gate and the captured audit.
struct Case {
    issuer: Issuer,
    key: SigningKey,
    gate: Gate,
    audit: Arc<Capture>,
}

impl Case {
    /// Returns a case admitting the issuer's tokens.
    async fn bearer() -> Self {
        let key = ec_key("k1", Algorithm::ES256);
        let issuer = Issuer::start(&[&key]).await;
        let verifier: Arc<dyn Verifier> = server(issuer.settings()).await;
        let gate = Gate::open().with_bearer(verifier).with_realm("ferro");
        Self {
            issuer,
            key,
            gate,
            audit: Arc::new(Capture::default()),
        }
    }

    /// Returns a token granting `scope`.
    fn token(&self, scope: &str) -> String {
        mint(&self.key, &self.issuer.claims(scope))
    }

    /// Sends `request` through the guarded router.
    async fn send(&self, request: Request<Body>) -> Result<Response, Box<dyn StdError>> {
        let layer = AuthLayer::new(self.gate.clone(), classify).with_render(render);
        let _guard = tracing::subscriber::set_default(Arc::clone(&self.audit));
        Ok(app(layer).oneshot(request).await?)
    }

    /// Sends `method` on `path` under `authorization`, when given.
    async fn call(
        &self,
        method: Method,
        path: &str,
        authorization: Option<&str>,
    ) -> Result<(StatusCode, Option<String>, String), Box<dyn StdError>> {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("x-request-id", "req-1");
        if let Some(authorization) = authorization {
            builder = builder.header(header::AUTHORIZATION, authorization);
        }
        let response = self.send(builder.body(Body::empty())?).await?;
        let status = response.status();
        let challenge = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = response.into_body().collect().await?.to_bytes();
        Ok((
            status,
            challenge,
            String::from_utf8_lossy(&body).into_owned(),
        ))
    }

    /// Returns the last audit line.
    fn last_line(&self) -> Line {
        self.audit.lines().last().cloned().expect("an audit line")
    }
}

#[tokio::test]
async fn a_valid_token_reaches_the_handler_and_is_audited_with_the_fixed_fields()
-> Result<(), Box<dyn StdError>> {
    let case = Case::bearer().await;
    let token = case.token("system/Condition.r");
    let (status, challenge, body) = case
        .call(
            Method::GET,
            "/fhir/Condition/c-1",
            Some(&format!("Bearer {token}")),
        )
        .await?;
    assert_eq!(StatusCode::OK, status);
    assert_eq!(None, challenge);
    assert_eq!("hello synthetic-client-sub", body);
    let line = case.last_line();
    assert_eq!(
        vec![
            "at",
            "client",
            "duration_ms",
            "interaction",
            "issuer",
            "message",
            "method",
            "principal",
            "request_id",
            "route",
            "status",
            "target",
            "via",
        ],
        line.names(),
        "the fixed field set, and nothing else"
    );
    assert_eq!("synthetic-client-sub", line.field("principal"));
    assert_eq!("synthetic-client", line.field("client"));
    assert_eq!("bearer", line.field("via"));
    assert_eq!(case.issuer.uri(), line.field("issuer"));
    assert_eq!("GET", line.field("method"));
    assert_eq!("/fhir/{resource_type}/{id}", line.field("route"));
    assert_eq!("Condition/c-1", line.field("target"));
    assert_eq!("read", line.field("interaction"));
    assert_eq!("200", line.field("status"));
    assert_eq!("req-1", line.field("request_id"));
    let at = line.field("at");
    assert!(
        at.ends_with('Z') && at.contains('T'),
        "RFC 3339 in UTC: {at}"
    );
    let text = format!("{line:?}");
    assert!(
        !text.contains(&token),
        "the audit line never carries the token"
    );
    assert!(
        !text.contains("system/"),
        "the audit line never carries a scope"
    );
    Ok(())
}

#[tokio::test]
async fn a_missing_token_is_challenged_without_an_error_code() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 6750 §3.1, a request lacking authentication information gets
    // no error code in the challenge.
    let case = Case::bearer().await;
    let (status, challenge, _) = case.call(Method::GET, "/fhir/Condition/c-1", None).await?;
    assert_eq!(StatusCode::UNAUTHORIZED, status);
    assert_eq!(Some("Bearer realm=\"ferro\""), challenge.as_deref());
    let line = case.last_line();
    assert_eq!("unauthenticated", line.field("principal"));
    assert_eq!("none", line.field("via"));
    assert_eq!("-", line.field("issuer"));
    assert_eq!("401", line.field("status"));
    let basic = Credential::new("alice", SecretString::from("pw"))?;
    let (status, challenge, _) = case
        .call(
            Method::GET,
            "/fhir/Condition/c-1",
            Some(basic.header_value().to_str()?),
        )
        .await?;
    assert_eq!(
        StatusCode::UNAUTHORIZED,
        status,
        "Basic is not admitted here"
    );
    assert_eq!(Some("Bearer realm=\"ferro\""), challenge.as_deref());
    Ok(())
}

#[tokio::test]
async fn two_credentials_or_a_malformed_value_are_invalid_request() -> Result<(), Box<dyn StdError>>
{
    // NOTE: RFC 6750 §3.1, a request with two credentials or a malformed
    // one is `invalid_request`.
    let case = Case::bearer().await;
    let token = case.token("system/Condition.r");
    let request = Request::builder()
        .method(Method::GET)
        .uri("/fhir/Condition/c-1")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())?;
    let response = case.send(request).await?;
    assert_eq!(StatusCode::BAD_REQUEST, response.status());
    assert_eq!(
        Some("Bearer realm=\"ferro\", error=\"invalid_request\""),
        response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
    );
    for malformed in ["Bearer", "Bearer ", "token-without-scheme"] {
        let (status, _, _) = case
            .call(Method::GET, "/fhir/Condition/c-1", Some(malformed))
            .await?;
        assert_eq!(StatusCode::BAD_REQUEST, status, "{malformed:?}");
    }
    Ok(())
}

#[tokio::test]
async fn an_invalid_token_is_the_one_generic_401() -> Result<(), Box<dyn StdError>> {
    let case = Case::bearer().await;
    let forger = ec_key("k1", Algorithm::ES256);
    let mut foreign = case.issuer.claims("system/Condition.r");
    foreign["aud"] = serde_json::json!("https://another-server.invalid/fhir");
    for (name, token) in [
        (
            "forged",
            mint(&forger, &case.issuer.claims("system/Condition.r")),
        ),
        ("another audience", mint(&case.key, &foreign)),
        ("opaque", String::from("an-opaque-token")),
    ] {
        let (status, challenge, body) = case
            .call(
                Method::GET,
                "/fhir/Condition/c-1",
                Some(&format!("Bearer {token}")),
            )
            .await?;
        assert_eq!(StatusCode::UNAUTHORIZED, status, "{name}");
        assert_eq!(
            Some("Bearer realm=\"ferro\", error=\"invalid_token\""),
            challenge.as_deref(),
            "{name}: no error_description"
        );
        assert_eq!("refused: invalid_token", body, "{name}: one body");
    }
    Ok(())
}

#[tokio::test]
async fn a_token_without_the_permission_is_403_naming_no_scope() -> Result<(), Box<dyn StdError>> {
    let case = Case::bearer().await;
    for scope in ["system/Condition.rus", "system/Observation.c", "openid"] {
        let token = case.token(scope);
        let (status, challenge, body) = case
            .call(
                Method::POST,
                "/fhir/Condition",
                Some(&format!("Bearer {token}")),
            )
            .await?;
        assert_eq!(StatusCode::FORBIDDEN, status, "{scope}");
        assert_eq!(
            Some("Bearer realm=\"ferro\", error=\"insufficient_scope\""),
            challenge.as_deref(),
            "{scope}: RFC 6750 §3.1 insufficient_scope, naming no scope"
        );
        for named in ["Condition.", "system/", ".c"] {
            assert!(!body.contains(named), "the body names {named}");
        }
        let line = case.last_line();
        assert_eq!(
            "synthetic-client-sub",
            line.field("principal"),
            "a refused caller is still named"
        );
        assert_eq!("403", line.field("status"));
    }
    let token = case.token("system/Condition.c");
    let (status, _, _) = case
        .call(
            Method::POST,
            "/fhir/Condition",
            Some(&format!("Bearer {token}")),
        )
        .await?;
    assert_eq!(StatusCode::OK, status);
    Ok(())
}

#[tokio::test]
async fn either_a_permission_or_the_products_scope_admits() -> Result<(), Box<dyn StdError>> {
    let case = Case::bearer().await;
    for (scope, expected) in [
        ("__operator", StatusCode::OK),
        ("system/*.c", StatusCode::OK),
        ("system/*.r", StatusCode::FORBIDDEN),
    ] {
        let token = case.token(scope);
        let (status, _, _) = case
            .call(
                Method::POST,
                "/fhir/Condition/$check",
                Some(&format!("Bearer {token}")),
            )
            .await?;
        assert_eq!(expected, status, "{scope}");
    }
    assert_eq!("Condition/$check", case.last_line().field("target"));
    Ok(())
}

#[tokio::test]
async fn a_patient_token_is_held_to_its_patient_by_the_handler() -> Result<(), Box<dyn StdError>> {
    let case = Case::bearer().await;
    let mut own = case.issuer.claims("patient/Condition.rs");
    own["patient"] = serde_json::json!("p-2");
    let mut other = case.issuer.claims("patient/Condition.rs");
    other["patient"] = serde_json::json!("p-3");
    let none = case.issuer.claims("patient/Condition.rs");
    for (name, claims, expected) in [
        ("the launched patient", own, StatusCode::OK),
        ("another patient", other, StatusCode::FORBIDDEN),
        ("no patient claim", none, StatusCode::FORBIDDEN),
    ] {
        let token = mint(&case.key, &claims);
        let (status, _, body) = case
            .call(
                Method::GET,
                "/fhir/Condition/p-2-only",
                Some(&format!("Bearer {token}")),
            )
            .await?;
        assert_eq!(expected, status, "{name}");
        if expected == StatusCode::FORBIDDEN {
            assert!(!body.contains("p-"), "{name}: the body names no patient");
        }
    }
    let system = case.token("system/Condition.r");
    let (status, _, _) = case
        .call(
            Method::GET,
            "/fhir/Condition/p-2-only",
            Some(&format!("Bearer {system}")),
        )
        .await?;
    assert_eq!(
        StatusCode::OK,
        status,
        "a system scope reaches every patient"
    );
    Ok(())
}

#[tokio::test]
async fn a_public_route_needs_no_token_and_a_refused_route_fails_closed()
-> Result<(), Box<dyn StdError>> {
    let case = Case::bearer().await;
    let (status, _, body) = case.call(Method::GET, "/fhir/metadata", None).await?;
    assert_eq!(StatusCode::OK, status);
    assert_eq!("hello open", body);
    assert_eq!("-", case.last_line().field("principal"));
    assert_eq!("open", case.last_line().field("via"));
    let token = case.token("system/*.cruds");
    let (status, challenge, _) = case
        .call(
            Method::GET,
            "/fhir/unknown",
            Some(&format!("Bearer {token}")),
        )
        .await?;
    assert_eq!(StatusCode::FORBIDDEN, status);
    assert_eq!(None, challenge);
    assert_eq!("unclassified", case.last_line().field("interaction"));
    let before = case.audit.lines().len();
    let (status, _, _) = case.call(Method::GET, "/health", None).await?;
    assert_eq!(
        StatusCode::INTERNAL_SERVER_ERROR,
        status,
        "outside the guard, the extractor finds no access"
    );
    assert_eq!(
        before,
        case.audit.lines().len(),
        "no audit line outside the guard"
    );
    Ok(())
}

#[tokio::test]
async fn the_handler_names_the_interaction_it_answered() -> Result<(), Box<dyn StdError>> {
    let case = Case::bearer().await;
    let token = case.token("system/Bundle.c");
    let (status, _, _) = case
        .call(
            Method::POST,
            "/fhir/Bundle",
            Some(&format!("Bearer {token}")),
        )
        .await?;
    assert_eq!(StatusCode::OK, status);
    assert_eq!("batch", case.last_line().field("interaction"));
    Ok(())
}

#[tokio::test]
async fn a_key_set_that_cannot_be_read_again_is_503() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let stranger = ec_key("stranger", Algorithm::ES256);
    let issuer = Issuer::bare().await;
    issuer
        .mount_metadata("/.well-known/oauth-authorization-server")
        .await;
    issuer.mount_keys(&[&key], Some(1)).await;
    issuer.mount_failing_keys().await;
    let verifier: Arc<dyn Verifier> = server(issuer.settings()).await;
    let case = Case {
        gate: Gate::open().with_bearer(verifier),
        issuer,
        key,
        audit: Arc::new(Capture::default()),
    };
    let token = mint(&stranger, &case.issuer.claims("system/Condition.r"));
    let (status, challenge, _) = case
        .call(
            Method::GET,
            "/fhir/Condition/c-1",
            Some(&format!("Bearer {token}")),
        )
        .await?;
    assert_eq!(StatusCode::SERVICE_UNAVAILABLE, status);
    assert_eq!(None, challenge);
    Ok(())
}

#[tokio::test]
async fn an_open_gate_admits_everyone_and_still_audits() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let case = Case {
        issuer,
        key,
        gate: Gate::open(),
        audit: Arc::new(Capture::default()),
    };
    let (status, _, body) = case.call(Method::POST, "/fhir/Condition", None).await?;
    assert_eq!(StatusCode::OK, status);
    assert_eq!("hello open", body);
    assert_eq!("-", case.last_line().field("principal"));
    assert_eq!("create", case.last_line().field("interaction"));
    Ok(())
}

#[tokio::test]
async fn a_basic_credential_is_admitted_beside_a_token_with_its_scopes()
-> Result<(), Box<dyn StdError>> {
    let hash = Argon2::default()
        .hash_password_with_salt(b"synthetic-pw", b"synthetic-salt-16")?
        .to_string();
    let store =
        PasswordStore::new().with_user("alice", SecretString::from(hash), "system/Condition.c")?;
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let verifier: Arc<dyn Verifier> = server(issuer.settings()).await;
    let case = Case {
        gate: Gate::open()
            .with_bearer(verifier)
            .with_basic(Arc::new(store))
            .with_realm("ferro"),
        issuer,
        key,
        audit: Arc::new(Capture::default()),
    };
    let good = Credential::new("alice", SecretString::from("synthetic-pw"))?;
    let (status, _, body) = case
        .call(
            Method::POST,
            "/fhir/Condition",
            Some(good.header_value().to_str()?),
        )
        .await?;
    assert_eq!(StatusCode::OK, status);
    assert_eq!("hello alice", body);
    let line = case.last_line();
    assert_eq!("alice", line.field("principal"));
    assert_eq!("-", line.field("client"));
    assert_eq!("basic", line.field("via"));
    assert_eq!("-", line.field("issuer"));

    let (status, _, _) = case
        .call(
            Method::GET,
            "/fhir/Condition/c-1",
            Some(good.header_value().to_str()?),
        )
        .await?;
    assert_eq!(
        StatusCode::FORBIDDEN,
        status,
        "the user's scopes grant no read"
    );

    let bad = Credential::new("alice", SecretString::from("wrong"))?;
    let (status, challenge, _) = case
        .call(
            Method::POST,
            "/fhir/Condition",
            Some(bad.header_value().to_str()?),
        )
        .await?;
    assert_eq!(StatusCode::UNAUTHORIZED, status);
    assert_eq!(
        Some("Basic realm=\"ferro\", charset=\"UTF-8\""),
        challenge.as_deref(),
        "RFC 7617 §2 and §2.1"
    );

    let (status, challenge, _) = case.call(Method::POST, "/fhir/Condition", None).await?;
    assert_eq!(StatusCode::UNAUTHORIZED, status);
    assert_eq!(
        Some("Bearer realm=\"ferro\", Basic realm=\"ferro\", charset=\"UTF-8\""),
        challenge.as_deref(),
        "RFC 9110 §11.6.1, one challenge per admitted scheme"
    );

    let token = case.token("system/Condition.c");
    let (status, _, _) = case
        .call(
            Method::POST,
            "/fhir/Condition",
            Some(&format!("Bearer {token}")),
        )
        .await?;
    assert_eq!(StatusCode::OK, status, "the token is admitted beside Basic");
    Ok(())
}

#[tokio::test]
async fn the_default_renderer_sends_the_challenge_with_no_body() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let verifier: Arc<dyn Verifier> = server(issuer.settings()).await;
    let gate = Gate::open().with_bearer(verifier).with_realm("ferro");
    let router = app(AuthLayer::new(gate, classify));
    let response = router
        .oneshot(Request::get("/fhir/Condition/c-1").body(Body::empty())?)
        .await?;
    assert_eq!(StatusCode::UNAUTHORIZED, response.status());
    assert_eq!(
        Some("Bearer realm=\"ferro\""),
        response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
    );
    let body = response.into_body().collect().await?.to_bytes();
    assert!(body.is_empty(), "the header-only renderer sends no body");
    Ok(())
}
