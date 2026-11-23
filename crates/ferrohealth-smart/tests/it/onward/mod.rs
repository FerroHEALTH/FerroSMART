// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The onward grants: token exchange (RFC 8693) and the JWT bearer grant
//! (RFC 7523) against the official examples first, then against a harness
//! token endpoint under a standards-only profile, the `entra` preset and the
//! `keycloak` preset, every refusal a typed error.
//!
//! Every token the cases exchange is signed when the case runs, with the
//! times of the case: a published example's past times are moved to now.

mod bound;
mod cache;
mod config;
#[cfg(feature = "test-support")]
mod consent;
#[cfg(feature = "test-support")]
mod correlation;
mod examples;
mod federation;
mod harness;
mod lanes;
mod patients;
mod refusals;
#[cfg(feature = "test-support")]
mod windows;

use std::sync::Arc;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::Ordering;

use ferrohealth_smart::client::ClientCredentials;
use ferrohealth_smart::client::Endpoint;
use ferrohealth_smart::client::assertion::ASSERTION_TYPE;
use ferrohealth_smart::client::assertion::AssertionKey;
use ferrohealth_smart::client::onward::SubjectToken;
use ferrohealth_smart::client::onward::exchange::WallClock;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::resource::Caller;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Header;
use jsonwebtoken::Validation;
use jsonwebtoken::jwk::Jwk;
use secrecy::SecretString;
use serde_json::Map;
use serde_json::Value;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::Request;
use wiremock::ResponseTemplate;
use wiremock::matchers::method;
use wiremock::matchers::path;

use crate::support::SigningKey;
use crate::support::ec_key;
use crate::support::mint_with;
use crate::support::now;

/// A clock the case sets.
#[derive(Debug)]
pub(crate) struct TestClock(AtomicI64);

impl TestClock {
    /// Returns a clock reading the current time.
    pub(crate) fn now() -> Arc<Self> {
        Arc::new(Self(AtomicI64::new(now())))
    }

    /// Moves the clock `seconds` forward.
    pub(crate) fn advance(&self, seconds: i64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl WallClock for TestClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Returns `value` as a claims object.
pub(crate) fn object(value: &Value) -> Map<String, Value> {
    value
        .as_object()
        .cloned()
        .expect("the claims are an object")
}

/// Returns `claims` signed by `key` with `typ` of `JWT`.
pub(crate) fn sign(key: &SigningKey, claims: &Value) -> String {
    let mut header = Header::new(key.alg);
    header.kid = Some(key.kid.clone());
    header.typ = Some(String::from("JWT"));
    mint_with(key, &header, claims)
}

/// Returns the caller a resource server admits with `claims`, a caller of
/// `kind`.
pub(crate) fn caller(claims: &Value, kind: CallerKind) -> Caller {
    let claims = object(claims);
    let text = |name: &str| claims.get(name).and_then(Value::as_str).map(str::to_owned);
    Caller::new(
        text("sub").unwrap_or_default(),
        text("client_id").or_else(|| text("azp")),
        &text("scope").unwrap_or_default(),
        None,
        kind,
    )
    .with_issuer(text("iss").unwrap_or_default())
    .with_claims(claims)
}

/// Returns the subject token `token` of a caller of `kind` admitted with
/// `claims`.
pub(crate) fn subject_of(token: &str, claims: &Value, kind: CallerKind) -> SubjectToken {
    SubjectToken::from_caller(&caller(claims, kind), SecretString::from(token))
        .expect("the caller holds a verified token")
}

/// Returns the form parameters of `request`, in the order sent.
pub(crate) fn form(request: &Request) -> Vec<(String, String)> {
    url::form_urlencoded::parse(&request.body)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

/// Returns the value of the one parameter `name` of `form`.
pub(crate) fn param<'a>(form: &'a [(String, String)], name: &str) -> Option<&'a str> {
    let mut values = form.iter().filter(|(key, _)| key == name);
    let first = values.next().map(|(_, value)| value.as_str());
    assert!(values.next().is_none(), "{name} is sent once");
    first
}

/// Returns `form` sorted, without the parameters `leave_out` names.
pub(crate) fn sorted(form: &[(String, String)], leave_out: &[&str]) -> Vec<(String, String)> {
    let mut kept: Vec<(String, String)> = form
        .iter()
        .filter(|(name, _)| !leave_out.contains(&name.as_str()))
        .cloned()
        .collect();
    kept.sort();
    kept
}

/// Returns the pairs of a figure's form body, `&` separated.
pub(crate) fn figure_form(body: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(body.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

/// Returns the token endpoint of `server` at `route`.
pub(crate) fn endpoint(server: &MockServer, route: &str) -> Endpoint {
    Endpoint::Token(
        format!("{}{route}", server.uri())
            .parse()
            .expect("a token endpoint URL"),
    )
}

/// The client key of the `private_key_jwt` cases, with its assertion key.
pub(crate) struct ClientKey {
    /// The generated key.
    pub(crate) key: SigningKey,
}

impl ClientKey {
    /// Returns a fresh ES384 client key.
    pub(crate) fn new() -> Self {
        Self {
            key: ec_key("client-2026", Algorithm::ES384),
        }
    }

    /// Returns `private_key_jwt` credentials of `client_id` at `endpoint`.
    pub(crate) fn credentials(&self, endpoint: Endpoint, client_id: &str) -> ClientCredentials {
        let key = AssertionKey::from_pem(
            &self.key.pem,
            Some(Algorithm::ES384),
            Some(self.key.kid.clone()),
        )
        .expect("the client key reads");
        ClientCredentials::with_private_key_jwt(endpoint, client_id.to_owned(), key)
    }

    /// Checks that `form` authenticates `client_id` with a `private_key_jwt`
    /// assertion this key signed for `audience` (RFC 7523 §2.2 and §3).
    pub(crate) fn verify(&self, form: &[(String, String)], client_id: &str, audience: &str) {
        assert_eq!(
            Some(ASSERTION_TYPE),
            param(form, "client_assertion_type"),
            "RFC 7523 §2.2 client_assertion_type"
        );
        let assertion = param(form, "client_assertion").expect("a client assertion");
        let jwk: Jwk = serde_json::from_value(self.key.jwk.clone()).expect("the public JWK");
        let mut validation = Validation::new(Algorithm::ES384);
        validation.set_audience(&[audience]);
        validation.set_issuer(&[client_id]);
        let claims = jsonwebtoken::decode::<Value>(
            assertion,
            &DecodingKey::from_jwk(&jwk).expect("a decoding key"),
            &validation,
        )
        .expect("the assertion verifies")
        .claims;
        assert_eq!(
            Some(client_id),
            claims.get("sub").and_then(Value::as_str),
            "RFC 7523 §3 sub"
        );
    }
}

/// Mounts `response` as the answer of `route` on `server`.
pub(crate) async fn answer(server: &MockServer, route: &str, response: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path(route))
        .respond_with(response)
        .mount(server)
        .await;
}

/// Returns the forms `server` received, in order.
pub(crate) async fn received(server: &MockServer) -> Vec<Vec<(String, String)>> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .map(form)
        .collect()
}
