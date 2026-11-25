// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A `DPoP`-bound onward grant: the exchange proves itself (RFC 9449 §4.2),
//! takes only a `DPoP` token (§5), and keeps the tokens of one key apart
//! from those of another in its cache.

use std::sync::Arc;

use ferrohealth_smart::client::TokenError;
use ferrohealth_smart::client::binding::IssuedToken;
use ferrohealth_smart::client::dpop::DpopKey;
use ferrohealth_smart::client::onward::OnwardError;
use ferrohealth_smart::client::onward::exchange::Onward;
use ferrohealth_smart::jws::algorithm::Algorithm;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::Request;
use wiremock::ResponseTemplate;
use wiremock::matchers::method;
use wiremock::matchers::path;

use super::ClientKey;
use super::TestClock;
use super::endpoint;
use super::harness::Flavor;
use super::harness::ROUTE;
use super::sign;
use super::subject_of;
use crate::support::ec_key;

/// Starts a token endpoint that answers a request carrying a `DPoP` proof
/// with a token of `token_type`, and returns it with the issued token.
async fn endpoint_issuing(token_type: &str) -> (MockServer, String, serde_json::Value) {
    let server = MockServer::start().await;
    let authority = ec_key("as-2026", Algorithm::Es256);
    let subject = Flavor::Generic.subject_claims(jiff::Timestamp::now().as_second());
    let token = sign(
        &authority,
        &Flavor::Generic.issued_claims(&subject, jiff::Timestamp::now().as_second()),
    );
    let mut response = Flavor::Generic.response(&token);
    if let Some(members) = response.as_object_mut() {
        members.insert(String::from("token_type"), serde_json::json!(token_type));
    }
    Mock::given(method("POST"))
        .and(path(ROUTE))
        .and(|request: &Request| request.headers.contains_key("dpop"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .mount(&server)
        .await;
    let subject_token = sign(&authority, &subject);
    (server, subject_token, subject)
}

/// Returns an onward client of the generic profile at `server`, bound to
/// `key`.
fn onward(server: &MockServer, key: &Arc<DpopKey>) -> Onward {
    let credentials = ClientKey::new()
        .credentials(endpoint(server, ROUTE), Flavor::Generic.client_id())
        .with_dpop(Arc::clone(key));
    Onward::with_clock(
        Flavor::Generic.settings(3600),
        credentials,
        TestClock::now(),
    )
    .expect("the onward client builds")
}

fn key() -> Arc<DpopKey> {
    Arc::new(DpopKey::from_pem(&ec_key("dpop", Algorithm::Es256).pem).expect("the key reads"))
}

#[tokio::test]
async fn a_dpop_bound_exchange_proves_itself_and_takes_a_dpop_token() {
    let (server, token, claims) = endpoint_issuing("DPoP").await;
    let key = key();
    let subject = subject_of(&token, &claims, ferrohealth_smart::kind::CallerKind::Person);
    let issued = onward(&server, &key)
        .token(&subject, None, &Flavor::Generic.target())
        .await
        .expect("a DPoP-bound onward token");
    assert!(
        issued
            .header()
            .to_str()
            .expect("ASCII")
            .starts_with("DPoP "),
        "the token travels under the DPoP scheme (RFC 9449 §7.1)"
    );
    let bound: &IssuedToken = issued.as_ref();
    assert!(bound.dpop_key().is_some());
    let url = url::Url::parse("https://ehr.example.org/api/ehr").expect("a URL");
    assert!(
        bound
            .proof(&http::Method::GET, &url)
            .expect("signs")
            .is_some()
    );
}

#[tokio::test]
async fn a_dpop_bound_exchange_refuses_a_bearer_token() {
    let (server, token, claims) = endpoint_issuing("Bearer").await;
    let subject = subject_of(&token, &claims, ferrohealth_smart::kind::CallerKind::Person);
    let outcome = onward(&server, &key())
        .token(&subject, None, &Flavor::Generic.target())
        .await;
    assert!(
        matches!(
            &outcome,
            Err(OnwardError::Token(TokenError::TokenType {
                expected: "DPoP",
                ..
            }))
        ),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn the_client_names_itself_the_actor_with_an_assertion_signed_per_request() {
    use super::harness::Harness;
    let harness = Harness::start(Flavor::Generic).await;
    let onward = harness
        .onward
        .clone()
        .with_actor_assertion()
        .expect("a private_key_jwt client asserts itself");
    assert!(onward.asserts_actor());
    let (subject, claims) = harness.person();
    harness
        .issue(
            &Flavor::Generic.issued_claims(&claims, harness.now()),
            Some(Flavor::Generic.client_id()),
        )
        .await;
    for _ in 0..2 {
        onward
            .token(&subject, None, &Flavor::Generic.target())
            .await
            .expect("the harness takes the actor assertion");
    }
    let sent = super::received(&harness.server).await;
    assert_eq!(1, sent.len(), "one subject and one target hit the cache");
    let form = sent.first().expect("one exchange");
    // NOTE: RFC 8693 §3, the actor assertion is a JWT.
    assert_eq!(
        Some("urn:ietf:params:oauth:token-type:jwt"),
        super::param(form, "actor_token_type")
    );
    assert_ne!(
        super::param(form, "actor_token"),
        super::param(form, "client_assertion"),
        "the actor assertion has a jti of its own (RFC 7523 §3)"
    );
}

#[tokio::test]
async fn the_jwt_bearer_grant_carries_no_actor_assertion() {
    use super::harness::Harness;
    let harness = Harness::start(Flavor::GenericJwtBearer).await;
    assert!(matches!(
        harness.onward.clone().with_actor_assertion(),
        Err(OnwardError::ActorToken)
    ));
}
