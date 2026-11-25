// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The party binding behind the guard: a token in, the caller classified,
//! its login looked up once, the outcome on the handler's `Access`, and the
//! outcome and the party reference on the audit line, never a party
//! attribute; a failing source answers `503`.

use std::error::Error as StdError;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::routing::get;
use ferrohealth_smart::guard::AuthLayer;
use ferrohealth_smart::guard::Gate;
use ferrohealth_smart::guard::Requirement;
use ferrohealth_smart::guard::Target;
use ferrohealth_smart::jws::algorithm::Algorithm;
use ferrohealth_smart::party::Markers;
use ferrohealth_smart::party::Membership;
use ferrohealth_smart::party::PartyRef;
use ferrohealth_smart::party::binding::PartyBinding;
use ferrohealth_smart::party::config::PartySection;
use ferrohealth_smart::party::source::Lookup;
use ferrohealth_smart::party::source::PartySource;
use ferrohealth_smart::party::source::SourceError;
use ferrohealth_smart::resource::Access;
use ferrohealth_smart::resource::Verifier;
use http::Extensions;
use http::Method;
use http::Request;
use http::StatusCode;
use http::Uri;
use http::header;
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

use super::FakeSource;
use super::record;
use crate::guard::Capture;
use crate::guard::Line;
use crate::support::CLIENT;
use crate::support::Issuer;
use crate::support::SigningKey;
use crate::support::ec_key;
use crate::support::mint;
use crate::support::server;

/// Every route needs a valid credential, whatever it grants; `/health` is
/// outside the guard.
fn classify(_method: &Method, uri: &Uri, _extensions: &Extensions) -> Option<Target> {
    (uri.path() != "/health")
        .then(|| Target::new("read", Requirement::Caller).route("/fhir/{resource_type}/{id}"))
}

/// Answers the outcome the guard left on the caller and its party.
async fn handler(access: Access) -> String {
    access.party().map_or_else(
        || String::from("not looked up"),
        |outcome| {
            format!(
                "{} {}",
                outcome.as_str(),
                outcome.party().map_or("-", PartyRef::id)
            )
        },
    )
}

/// One case: the stub issuer, its key, the source and the audit.
struct Case {
    issuer: Issuer,
    key: SigningKey,
    source: Arc<FakeSource>,
    audit: Arc<Capture>,
}

impl Case {
    async fn new(source: Arc<FakeSource>) -> Self {
        let key = ec_key("k1", Algorithm::Es256);
        let issuer = Issuer::start(&[&key]).await;
        Self {
            issuer,
            key,
            source,
            audit: Arc::new(Capture::default()),
        }
    }

    /// Sends a token of `claims` through the guarded router and returns the
    /// status, the body and the audit line.
    async fn call(
        &self,
        claims: &serde_json::Value,
    ) -> Result<(StatusCode, String, Line), Box<dyn StdError>> {
        let settings = self.issuer.settings();
        let table = PartySection {
            issuer: ferrohealth_secret::secret_url::SecretUrl::new(settings.issuer.as_str()),
            identifier_issuer: String::from(super::IDENTIFIERS),
            identifier_type: String::from("login"),
            group_claim: String::from("groups"),
            group_identifier_issuer: String::from(super::GROUPS),
        };
        let concrete = Arc::clone(&self.source);
        let source: Arc<dyn PartySource> = concrete;
        let binding = PartyBinding::new(source).with_issuer(table, settings.kind)?;
        let verifier: Arc<dyn Verifier> = server(settings).await;
        let gate = Gate::open()
            .with_bearer(verifier)
            .with_party(Arc::new(binding));
        let app = Router::new()
            .route("/fhir/{resource_type}/{id}", get(handler))
            .layer(AuthLayer::new(gate, classify));
        let request = Request::builder()
            .uri("/fhir/Condition/c-1")
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", mint(&self.key, claims)),
            )
            .body(Body::empty())?;
        let _guard = tracing::subscriber::set_default(Arc::clone(&self.audit));
        let response = app.oneshot(request).await?;
        let status = response.status();
        let body = response.into_body().collect().await?.to_bytes();
        let line = self.audit.lines().last().cloned().ok_or("an audit line")?;
        Ok((status, String::from_utf8_lossy(&body).into_owned(), line))
    }
}

// NOTE: Regulation (EU) 2016/679 Art. 5(1)(c): data "adequate, relevant and limited to
// what is necessary", so the line names the outcome and the reference, no attribute.
#[tokio::test]
async fn a_person_token_reaches_the_handler_bound_and_the_line_names_the_party()
-> Result<(), Box<dyn StdError>> {
    let source = FakeSource::answering(Lookup::Parties(vec![
        record("p-1", Markers::PROFESSIONAL).with_memberships(vec![Membership::new(
            PartyRef::new("ferro-demographic", "GROUP", "g-hidden"),
            "group-1",
        )]),
    ]));
    let case = Case::new(source).await;
    let mut claims = case.issuer.claims("user/Condition.r");
    claims["groups"] = serde_json::json!(["group-1"]);
    let (status, body, line) = case.call(&claims).await?;
    assert_eq!(StatusCode::OK, status);
    assert_eq!("party p-1", body, "the handler reads the outcome");
    assert_eq!(1, case.source.calls(), "one lookup for the request");
    assert_eq!("party", line.field("binding"));
    assert_eq!("ferro-demographic/PERSON/p-1", line.field("party"));
    let text = format!("{line:?}");
    assert!(!text.contains("g-hidden"), "no group on the line: {text}");
    assert!(
        !text.contains("group-1"),
        "no group claim on the line: {text}"
    );
    Ok(())
}

// NOTE: RFC 9068 §2.2 and §5: a client credentials token's `sub` names the client, so a
// System caller is admitted without a lookup and the line records none.
#[tokio::test]
async fn a_system_token_is_admitted_without_a_lookup() -> Result<(), Box<dyn StdError>> {
    let case = Case::new(FakeSource::answering(Lookup::Parties(Vec::new()))).await;
    let mut claims = case.issuer.claims("system/Condition.r");
    claims["sub"] = serde_json::json!(CLIENT);
    let (status, body, line) = case.call(&claims).await?;
    assert_eq!(StatusCode::OK, status);
    assert_eq!("not looked up", body);
    assert_eq!(0, case.source.calls(), "a System never reaches the source");
    assert_eq!("-", line.field("binding"));
    Ok(())
}

// NOTE: no specification governs the binding: our own design; an unbound login reaches
// the handler, which answers it, and the line records the outcome with no party.
#[tokio::test]
async fn an_unbound_login_reaches_the_handler_as_unbound() -> Result<(), Box<dyn StdError>> {
    let case = Case::new(FakeSource::answering(Lookup::Parties(Vec::new()))).await;
    let (status, body, line) = case.call(&case.issuer.claims("user/Condition.r")).await?;
    assert_eq!(
        StatusCode::OK,
        status,
        "the product decides what Unbound means"
    );
    assert_eq!("unbound -", body);
    assert_eq!("unbound", line.field("binding"));
    assert_eq!("-", line.field("party"));
    Ok(())
}

/// The failure of the fake store.
#[derive(Debug, thiserror::Error)]
#[error("the synthetic store is down")]
struct StoreDown;

// NOTE: no specification governs the binding: our own design; a source that cannot answer
// is a 503, never an admitted caller with no party, and the line records the failure.
#[tokio::test]
async fn a_failing_source_answers_503_and_the_line_records_it() -> Result<(), Box<dyn StdError>> {
    let case = Case::new(FakeSource::with(|_query| Err(SourceError::new(StoreDown)))).await;
    let (status, body, line) = case.call(&case.issuer.claims("user/Condition.r")).await?;
    assert_eq!(StatusCode::SERVICE_UNAVAILABLE, status);
    assert_eq!("", body, "the handler never ran");
    assert_eq!("source_unavailable", line.field("binding"));
    assert_eq!("synthetic-client-sub", line.field("principal"));
    assert_eq!("503", line.field("status"));
    Ok(())
}
