// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The guard in front of an axum router: the `401` of a missing or invalid
//! credential, the `400` of two credentials, the `403` of a token without
//! the permission, the patient compartment a handler holds a token to, the
//! Basic credential, the open surface, the extractor, and the one audit
//! line of every request with its fixed fields.

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::future::Future;
use std::pin::Pin;
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
use ferrohealth_smart::guard::CredentialHeader;
use ferrohealth_smart::guard::Gate;
use ferrohealth_smart::guard::Requirement;
use ferrohealth_smart::guard::Target;
use ferrohealth_smart::refusal::Denied;
use ferrohealth_smart::refusal::Reason;
use ferrohealth_smart::refusal::Refusal;
use ferrohealth_smart::resource::Access;
use ferrohealth_smart::resource::Caller;
use ferrohealth_smart::resource::Rejection;
use ferrohealth_smart::resource::Verifier;
use ferrohealth_smart::scope::Permission;
use http::Extensions;
use http::HeaderMap;
use http::HeaderName;
use http::HeaderValue;
use http::Method;
use http::Request;
use http::StatusCode;
use http::Uri;
use http::header;
use http::request::Parts;
use http_body_util::BodyExt as _;
use jsonwebtoken::Algorithm;
use secrecy::SecretString;
use tower::ServiceExt as _;

use crate::support::CLIENT;
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
fn refused(denied: &Denied) -> Response {
    HeaderOnly::with_realm("ferro").respond(
        denied,
        Body::from(format!("refused: {}", denied.refusal().reason())),
    )
}

/// Renders a refusal in the format the request negotiates, as a FHIR server
/// does: XML when `_format` or `Accept` asks for it, the text body
/// otherwise.
fn render(denied: &Denied, parts: &Parts) -> Response {
    let format_xml = parts
        .uri
        .query()
        .is_some_and(|query| query.split('&').any(|pair| pair == "_format=xml"));
    let accept_xml = parts
        .headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| accept.contains("application/fhir+xml"));
    if format_xml || accept_xml {
        let mut response = HeaderOnly::with_realm("ferro").respond(
            denied,
            Body::from(format!(
                "<refused reason=\"{}\"/>",
                denied.refusal().reason()
            )),
        );
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/fhir+xml"),
        );
        return response;
    }
    refused(denied)
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
            return refused(&Denied::from(Refusal::Forbidden));
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
pub(crate) struct Line(BTreeMap<String, String>);

impl Line {
    /// Returns the field `name`, or an empty string.
    pub(crate) fn field(&self, name: &str) -> &str {
        self.0.get(name).map_or("", String::as_str)
    }

    /// Returns the names of the fields on the line.
    pub(crate) fn names(&self) -> Vec<&str> {
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

/// The target the gate logs a refusal under.
const REFUSAL_TARGET: &str = "ferrohealth_smart::guard::gate";

/// A subscriber that keeps every audit line and every refusal log line, so
/// a case reads what was recorded.
#[derive(Debug, Default)]
pub(crate) struct Capture {
    /// The audit lines, in order.
    lines: Mutex<Vec<Line>>,
    /// The refusal log lines, in order.
    refusals: Mutex<Vec<Line>>,
}

impl Capture {
    /// Returns the audit lines kept, in order.
    pub(crate) fn lines(&self) -> Vec<Line> {
        self.lines.lock().expect("not poisoned").clone()
    }

    /// Returns the refusal log lines kept, in order.
    pub(crate) fn refusals(&self) -> Vec<Line> {
        self.refusals.lock().expect("not poisoned").clone()
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == AUDIT_TARGET
            || (metadata.target() == REFUSAL_TARGET && *metadata.level() == tracing::Level::INFO)
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut line = Line::default();
        event.record(&mut line);
        let kept = if event.metadata().target() == AUDIT_TARGET {
            &self.lines
        } else {
            &self.refusals
        };
        kept.lock().expect("not poisoned").push(line);
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
async fn each_refusal_is_logged_at_info_with_its_code_and_the_tokens_names()
-> Result<(), Box<dyn StdError>> {
    let case = Case::bearer().await;
    let mut foreign = case.issuer.claims("system/Condition.r");
    foreign["aud"] = serde_json::json!("https://another-server.invalid/fhir");
    let refused = mint(&case.key, &foreign);
    let narrow = case.token("system/Observation.r");
    for (authorization, status, code) in [
        (
            Some(format!("Bearer {refused}")),
            "401",
            "audience-mismatch",
        ),
        (Some(format!("Bearer {narrow}")), "403", "scope-not-granted"),
        (None, "401", "credential-missing"),
    ] {
        case.call(Method::GET, "/fhir/Condition/c-1", authorization.as_deref())
            .await?;
        let line = case
            .audit
            .refusals()
            .last()
            .cloned()
            .expect("a refusal line");
        assert_eq!(code, line.field("reason"), "{code}");
        assert_eq!(status, line.field("status"), "{code}");
        let named = authorization.is_some();
        let expected = |value: String| if named { value } else { String::from("-") };
        assert_eq!(expected(case.issuer.uri()), line.field("issuer"), "{code}");
        assert_eq!(
            expected(String::from(CLIENT)),
            line.field("client_id"),
            "{code}"
        );
        assert_eq!(expected(String::from("k1")), line.field("kid"), "{code}");
        for (name, value) in &line.0 {
            for forbidden in ["synthetic-client-sub", refused.as_str(), narrow.as_str()] {
                assert!(
                    !value.contains(forbidden),
                    "{code}: {name} carries {forbidden}"
                );
            }
        }
    }
    Ok(())
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
            "addressed",
            "at",
            "binding",
            "client",
            "duration_ms",
            "interaction",
            "issuer",
            "kind",
            "message",
            "method",
            "party",
            "principal",
            "request_id",
            "route",
            "status",
            "via",
        ],
        line.names(),
        "the fixed field set, and nothing else"
    );
    assert_eq!("synthetic-client-sub", line.field("principal"));
    assert_eq!("synthetic-client", line.field("client"));
    assert_eq!("user", line.field("kind"), "the caller kind (#215)");
    assert_eq!(
        "-",
        line.field("binding"),
        "no party binding looked it up (#216)"
    );
    assert_eq!("-", line.field("party"), "no party (#216)");
    assert_eq!("bearer", line.field("via"));
    assert_eq!(case.issuer.uri(), line.field("issuer"));
    assert_eq!("GET", line.field("method"));
    assert_eq!("/fhir/{resource_type}/{id}", line.field("route"));
    assert_eq!("Condition/c-1", line.field("addressed"));
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
        Some(
            "Bearer realm=\"ferro\", error=\"invalid_request\", error_description=\"two-credentials\""
        ),
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
async fn an_invalid_token_is_401_with_its_reason_code() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 6750 §3, the challenge's `error_description` carries the
    // stable reason code; the body stays the one generic refusal.
    let case = Case::bearer().await;
    let forger = ec_key("k1", Algorithm::ES256);
    let mut foreign = case.issuer.claims("system/Condition.r");
    foreign["aud"] = serde_json::json!("https://another-server.invalid/fhir");
    for (name, token, code) in [
        (
            "forged",
            mint(&forger, &case.issuer.claims("system/Condition.r")),
            "signature-invalid",
        ),
        (
            "another audience",
            mint(&case.key, &foreign),
            "audience-mismatch",
        ),
        ("opaque", String::from("an-opaque-token"), "malformed-token"),
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
            Some(format!(
                "Bearer realm=\"ferro\", error=\"invalid_token\", error_description=\"{code}\""
            )),
            challenge,
            "{name}: the reason code"
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
            Some(
                "Bearer realm=\"ferro\", error=\"insufficient_scope\", error_description=\"scope-not-granted\""
            ),
            challenge.as_deref(),
            "{scope}: RFC 6750 §3.1 insufficient_scope with its code, naming no scope"
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
    assert_eq!("Condition/$check", case.last_line().field("addressed"));
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
    let store = PasswordStore::new()
        .with_user("alice", SecretString::from(hash))?
        .with_scope("alice", "user/Condition.c")?;
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

#[tokio::test]
async fn the_renderer_negotiates_the_body_from_the_refused_request() -> Result<(), Box<dyn StdError>>
{
    let case = Case::bearer().await;
    let by_accept = case
        .send(
            Request::get("/fhir/Condition/c-1")
                .header(header::ACCEPT, "application/fhir+xml")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(StatusCode::UNAUTHORIZED, by_accept.status());
    assert_eq!(
        Some("application/fhir+xml"),
        by_accept
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        "the Accept header reaches the renderer"
    );
    let body = by_accept.into_body().collect().await?.to_bytes();
    assert_eq!(&b"<refused reason=\"missing\"/>"[..], &*body);
    let token = case.token("system/Patient.r");
    let by_format = case
        .send(
            Request::get("/fhir/Condition/c-1?_format=xml")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(StatusCode::FORBIDDEN, by_format.status());
    assert_eq!(
        Some(
            "Bearer realm=\"ferro\", error=\"insufficient_scope\", error_description=\"scope-not-granted\""
        ),
        by_format
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        "the challenge stays the refusal's"
    );
    let body = by_format.into_body().collect().await?.to_bytes();
    assert_eq!(&b"<refused reason=\"insufficient_scope\"/>"[..], &*body);
    Ok(())
}

/// Returns the headers of a request carrying `authorization`.
fn authorized(authorization: &str) -> Result<HeaderMap, Box<dyn StdError>> {
    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, HeaderValue::from_str(authorization)?);
    Ok(headers)
}

/// Returns a store admitting `alice` with the password `synthetic-pw`.
fn alice(scope: &str) -> Result<PasswordStore, Box<dyn StdError>> {
    let hash = Argon2::default()
        .hash_password_with_salt(b"synthetic-pw", b"synthetic-salt-16")?
        .to_string();
    Ok(PasswordStore::new()
        .with_user("alice", SecretString::from(hash))?
        .with_scope("alice", scope)?)
}

// NOTE: RFC 6750 §2.1 fixes the `b64token` syntax, and §3.1 answers a token
// that is "malformed" with `invalid_token`, with the code as §3 describes.
#[tokio::test]
async fn a_bearer_value_outside_b64token_is_401_not_b64token() -> Result<(), Box<dyn StdError>> {
    let case = Case::bearer().await;
    for value in ["a,b", "a=b", "a\"b", "=abc", "a;b"] {
        let (status, challenge, body) = case
            .call(
                Method::GET,
                "/fhir/Condition/c-1",
                Some(&format!("Bearer {value}")),
            )
            .await?;
        assert_eq!(StatusCode::UNAUTHORIZED, status, "{value}");
        assert_eq!(
            Some(
                "Bearer realm=\"ferro\", error=\"invalid_token\", error_description=\"not-b64token\""
            ),
            challenge.as_deref(),
            "{value}: the reason code"
        );
        assert_eq!("refused: invalid_token", body, "{value}");
        let denied = case
            .gate
            .authenticate(&authorized(&format!("Bearer {value}"))?)
            .await
            .expect_err("refused");
        assert_eq!(Some(Reason::NotB64Token), denied.reason(), "{value}");
    }
    Ok(())
}

#[tokio::test]
async fn the_gate_hands_the_product_the_reason_and_the_wire_its_code()
-> Result<(), Box<dyn StdError>> {
    let case = Case::bearer().await;
    let mut expired = case.issuer.claims("system/Condition.r");
    expired["exp"] = serde_json::json!(crate::support::now() - 3600);
    let token = mint(&case.key, &expired);
    let denied = case
        .gate
        .authenticate(&authorized(&format!("Bearer {token}"))?)
        .await
        .expect_err("an expired token");
    assert_eq!(&Refusal::InvalidToken, denied.refusal());
    assert_eq!(Some(Reason::Expired), denied.reason());
    assert_eq!(
        Some(String::from(
            "Bearer realm=\"ferro\", error=\"invalid_token\", error_description=\"expired\""
        )),
        denied.challenge(Some("ferro")),
        "RFC 6750 §3: the reason code as error_description"
    );
    assert_eq!("expired", denied.code());
    let missing = case
        .gate
        .authenticate(&HeaderMap::new())
        .await
        .expect_err("no credential");
    assert_eq!(None, missing.reason(), "no credential was examined");
    let mut two = authorized("Bearer a")?;
    two.append(header::AUTHORIZATION, HeaderValue::from_static("Bearer b"));
    let denied = case.gate.authenticate(&two).await.expect_err("two");
    assert_eq!(&Refusal::InvalidRequest, denied.refusal());
    assert_eq!(Some(Reason::TwoCredentials), denied.reason());

    let basic = Gate::open().with_basic(Arc::new(alice("")?));
    let wrong = Credential::new("alice", SecretString::from("wrong"))?;
    let denied = basic
        .authenticate(&authorized(wrong.header_value().to_str()?)?)
        .await
        .expect_err("a wrong password");
    assert_eq!(&Refusal::InvalidBasic, denied.refusal());
    assert_eq!(Some(Reason::BasicRejected), denied.reason());
    Ok(())
}

/// A product verifier that hands the gate a blank subject.
struct BlankSubject;

impl Verifier for BlankSubject {
    fn verify<'a>(
        &'a self,
        _token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Caller, Rejection>> + Send + 'a>> {
        Box::pin(async {
            Ok(Caller::new(
                String::from("  "),
                None,
                "",
                None,
                ferrohealth_smart::kind::CallerKind::Person,
            ))
        })
    }
}

// NOTE: RFC 9068 §2.2 requires `sub`; the gate holds it over every verifier.
#[tokio::test]
async fn the_gate_refuses_a_blank_subject_from_any_verifier() -> Result<(), Box<dyn StdError>> {
    let gate = Gate::open().with_bearer(Arc::new(BlankSubject));
    let denied = gate
        .authenticate(&authorized("Bearer opaque-token")?)
        .await
        .expect_err("a blank subject");
    assert_eq!(&Refusal::InvalidToken, denied.refusal());
    assert_eq!(Some(Reason::BlankSubject), denied.reason());
    Ok(())
}

#[tokio::test]
async fn a_basic_only_gate_admits_basic_and_challenges_a_token_with_basic_alone()
-> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let case = Case {
        gate: Gate::open()
            .with_basic(Arc::new(alice("user/Condition.c")?))
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
    let token = case.token("system/Condition.c");
    let (status, challenge, _) = case
        .call(
            Method::POST,
            "/fhir/Condition",
            Some(&format!("Bearer {token}")),
        )
        .await?;
    assert_eq!(StatusCode::UNAUTHORIZED, status, "no bearer is admitted");
    assert_eq!(
        Some("Basic realm=\"ferro\", charset=\"UTF-8\""),
        challenge.as_deref(),
        "RFC 6750 §3.1: no error code for a scheme the surface does not admit"
    );
    Ok(())
}

#[tokio::test]
async fn a_cached_basic_credential_is_admitted_again_and_a_wrong_one_refused()
-> Result<(), Box<dyn StdError>> {
    let store = alice("user/Condition.c")?.with_cache(std::time::Duration::from_secs(60))?;
    let gate = Gate::open().with_basic(Arc::new(store));
    let good = Credential::new("alice", SecretString::from("synthetic-pw"))?;
    for round in ["first", "cached"] {
        let access = gate
            .authenticate(&authorized(good.header_value().to_str()?)?)
            .await
            .map_err(|denied| format!("{round}: {:?}", denied.reason()))?;
        assert_eq!(
            Some("alice"),
            access.caller().map(Caller::subject),
            "{round}"
        );
    }
    let wrong = Credential::new("alice", SecretString::from("wrong"))?;
    assert!(
        gate.authenticate(&authorized(wrong.header_value().to_str()?)?)
            .await
            .is_err(),
        "a wrong password is never admitted from the cache"
    );
    Ok(())
}

#[tokio::test]
async fn the_gate_says_when_a_basic_credential_came_from_the_cache() -> Result<(), Box<dyn StdError>>
{
    let good = Credential::new("alice", SecretString::from("synthetic-pw"))?;
    let headers = authorized(good.header_value().to_str()?)?;
    let cached = Gate::open().with_basic(Arc::new(
        alice("")?.with_cache(std::time::Duration::from_secs(60))?,
    ));
    let first = cached
        .authenticate(&headers)
        .await
        .map_err(|denied| format!("{denied:?}"))?;
    assert_eq!(
        Some(false),
        first.caller().map(Caller::cached),
        "a fresh authentication"
    );
    let repeat = cached
        .authenticate(&headers)
        .await
        .map_err(|denied| format!("{denied:?}"))?;
    assert_eq!(
        Some(true),
        repeat.caller().map(Caller::cached),
        "admitted from the cache"
    );
    let uncached = Gate::open().with_basic(Arc::new(alice("")?));
    for round in ["first", "second"] {
        let access = uncached
            .authenticate(&headers)
            .await
            .map_err(|denied| format!("{denied:?}"))?;
        assert_eq!(
            Some(false),
            access.caller().map(Caller::cached),
            "{round}: no cache"
        );
    }
    let case = Case::bearer().await;
    let token = case.token("system/Condition.r");
    let access = case
        .gate
        .authenticate(&authorized(&format!("Bearer {token}"))?)
        .await
        .map_err(|denied| format!("{denied:?}"))?;
    assert_eq!(
        Some(false),
        access.caller().map(Caller::cached),
        "a bearer caller"
    );
    Ok(())
}

// NOTE: RFC 9700 §4.13 has the proxy sanitize the header; the gate keeps the
// rules of `Authorization` (RFC 6750 §2.1, §3.1) in whichever header it reads.
#[tokio::test]
async fn a_named_bare_header_carries_the_token_under_the_same_rules()
-> Result<(), Box<dyn StdError>> {
    let case = Case::bearer().await;
    let name = HeaderName::from_static("x-edge-assertion");
    let gate = case
        .gate
        .clone()
        .with_credential_header(CredentialHeader::bare(name.clone()));
    assert!(gate.credential_header().is_bare());
    let token = case.token("system/Condition.r");
    let mut headers = HeaderMap::new();
    headers.insert(name.clone(), HeaderValue::from_str(&token)?);
    let access = gate
        .authenticate(&headers)
        .await
        .map_err(|denied| format!("{denied:?}"))?;
    assert_eq!(
        Some("synthetic-client-sub"),
        access.caller().map(Caller::subject)
    );
    assert_eq!(Some(token.as_str()), gate.credential(&headers));

    let in_authorization = authorized(&format!("Bearer {token}"))?;
    let denied = gate
        .authenticate(&in_authorization)
        .await
        .expect_err("Authorization is not read once another header is named");
    assert!(matches!(denied.refusal(), Refusal::Missing(_)));
    assert_eq!(None, gate.credential(&in_authorization));

    let mut two = HeaderMap::new();
    two.append(name.clone(), HeaderValue::from_str(&token)?);
    two.append(name.clone(), HeaderValue::from_str(&token)?);
    let denied = gate.authenticate(&two).await.expect_err("two fields");
    assert_eq!(&Refusal::InvalidRequest, denied.refusal());
    assert_eq!(Some(Reason::TwoCredentials), denied.reason());
    assert_eq!(None, gate.credential(&two));

    let mut empty = HeaderMap::new();
    empty.insert(name.clone(), HeaderValue::from_static(""));
    let denied = gate.authenticate(&empty).await.expect_err("an empty field");
    assert_eq!(&Refusal::InvalidRequest, denied.refusal());

    let mut outside = HeaderMap::new();
    outside.insert(name, HeaderValue::from_static("a,b"));
    let denied = gate
        .authenticate(&outside)
        .await
        .expect_err("not a b64token");
    assert_eq!(&Refusal::InvalidToken, denied.refusal());
    assert_eq!(Some(Reason::NotB64Token), denied.reason());
    Ok(())
}

#[tokio::test]
async fn a_named_schemed_header_reads_a_scheme_and_a_credential() -> Result<(), Box<dyn StdError>> {
    let case = Case::bearer().await;
    let name = HeaderName::from_static("x-forwarded-authorization");
    let gate = case
        .gate
        .clone()
        .with_basic(Arc::new(alice("")?))
        .with_credential_header(CredentialHeader::schemed(name.clone()));
    let token = case.token("system/Condition.r");
    let mut headers = HeaderMap::new();
    headers.insert(
        name.clone(),
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );
    assert!(gate.authenticate(&headers).await.is_ok());
    assert_eq!(Some(token.as_str()), gate.credential(&headers));
    let good = Credential::new("alice", SecretString::from("synthetic-pw"))?;
    let mut basic = HeaderMap::new();
    basic.insert(name.clone(), good.header_value());
    let access = gate
        .authenticate(&basic)
        .await
        .map_err(|denied| format!("{denied:?}"))?;
    assert_eq!(Some("alice"), access.basic_user_in(&["alice"]));
    let mut bare = HeaderMap::new();
    bare.insert(name, HeaderValue::from_str(&token)?);
    let denied = gate.authenticate(&bare).await.expect_err("no scheme");
    assert_eq!(&Refusal::InvalidRequest, denied.refusal());
    assert_eq!(
        CredentialHeader::authorization(),
        Gate::open().credential_header().clone(),
        "the default stays Authorization"
    );
    Ok(())
}

/// A product verifier whose own upstream is down.
struct UpstreamDown;

impl Verifier for UpstreamDown {
    fn verify<'a>(
        &'a self,
        _token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Caller, Rejection>> + Send + 'a>> {
        Box::pin(async {
            Err(Rejection::upstream(
                "introspection endpoint",
                std::io::Error::other("connection refused"),
            ))
        })
    }
}

#[tokio::test]
async fn a_product_verifier_reports_its_upstream_failure_as_503() -> Result<(), Box<dyn StdError>> {
    let gate = Gate::open()
        .with_bearer(Arc::new(UpstreamDown))
        .with_realm("ferro");
    let denied = gate
        .authenticate(&authorized("Bearer opaque-token")?)
        .await
        .expect_err("the upstream is down");
    assert_eq!(&Refusal::Unavailable, denied.refusal());
    assert_eq!(Some(Reason::UpstreamUnavailable), denied.reason());
    let app = app(AuthLayer::new(gate, classify).with_render(render));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/fhir/Condition/c-1")
                .header(header::AUTHORIZATION, "Bearer opaque-token")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(StatusCode::SERVICE_UNAVAILABLE, response.status());
    assert_eq!(
        None,
        response.headers().get(header::WWW_AUTHENTICATE),
        "503 carries no challenge"
    );
    Ok(())
}

#[tokio::test]
async fn a_basic_users_requirement_admits_its_users_alone() -> Result<(), Box<dyn StdError>> {
    let gate = Gate::open().with_basic(Arc::new(alice("")?));
    let good = Credential::new("alice", SecretString::from("synthetic-pw"))?;
    let access = gate
        .authenticate(&authorized(good.header_value().to_str()?)?)
        .await
        .map_err(|denied| format!("{denied:?}"))?;
    let none = ferrohealth_smart::resource::Honoured::default();
    assert!(Requirement::basic_users(["alice"]).met_by(&access, none));
    assert!(!Requirement::basic_users(["scrape"]).met_by(&access, none));
    let case = Case::bearer().await;
    let token = case.token("");
    let bearer = case
        .gate
        .authenticate(&authorized(&format!("Bearer {token}"))?)
        .await
        .map_err(|denied| format!("{denied:?}"))?;
    assert!(
        !Requirement::basic_users(["synthetic-client-sub"]).met_by(&bearer, none),
        "a bearer subject never passes for a Basic user-id"
    );
    assert_eq!(None, bearer.basic_user_in(&["synthetic-client-sub"]));
    Ok(())
}

#[tokio::test]
async fn an_issuers_extension_reaches_the_handlers_access() -> Result<(), Box<dyn StdError>> {
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Trust(&'static str);
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let server = ferrohealth_smart::resource::ResourceServer::discover(issuer.settings())
        .await?
        .with_extension(Trust("member-a"));
    let gate = Gate::open().with_bearer(Arc::new(server));
    let token = mint(&key, &issuer.claims("system/Condition.r"));
    let access = gate
        .authenticate(&authorized(&format!("Bearer {token}"))?)
        .await
        .map_err(|denied| format!("{denied:?}"))?;
    assert_eq!(Some(&Trust("member-a")), access.extension::<Trust>());
    Ok(())
}
