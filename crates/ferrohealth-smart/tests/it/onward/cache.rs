// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The onward token cache: one exchange per subject token, target and
//! scope, an entry living until a margin before the earlier `exp`, the
//! check run again on every hit, and no token in a log line.

use std::io::Write;

use ferrohealth_smart::client::onward::OnwardError;
use ferrohealth_smart::client::onward::Rejected;
use ferrohealth_smart::client::onward::SubjectToken;
use ferrohealth_smart::client::onward::Target;
use ferrohealth_smart::kind::CallerKind;
use secrecy::SecretString;
use serde_json::json;

use super::caller;
use super::harness::FLAVORS;
use super::harness::Flavor;
use super::harness::Harness;

#[tokio::test]
async fn a_second_request_for_the_same_subject_target_and_scope_is_served_from_the_cache() {
    for flavor in FLAVORS {
        let harness = Harness::start(flavor).await;
        let (subject, claims) = harness.person();
        harness
            .issue(&flavor.issued_claims(&claims, harness.now()), None)
            .await;
        let first = harness
            .token(&subject, None)
            .await
            .expect("the first token");
        let second = harness
            .token(&subject, None)
            .await
            .expect("the cached token");
        assert_eq!(first.header(), second.header(), "{flavor:?}");
        assert_eq!(1, harness.calls().await, "{flavor:?}: one exchange");
    }
}

#[tokio::test]
async fn two_audiences_with_one_scope_are_two_exchanges() {
    // NOTE: RFC 8707 §2, a token issued for one target is never handed to
    // another, so the target is part of the cache key.
    let harness = Harness::start(Flavor::Generic).await;
    let (subject, claims) = harness.person();
    let mut issued = Flavor::Generic.issued_claims(&claims, harness.now());
    let audiences = ["https://ehr-a.example.org", "https://ehr-b.example.org"];
    issued["aud"] = json!(audiences);
    harness.issue(&issued, None).await;
    for audience in audiences {
        let target = Target::new(audiences)
            .with_indicator(audience)
            .with_scope("user/*.rs");
        harness
            .onward
            .token(&subject, None, &target)
            .await
            .expect("a token");
    }
    assert_eq!(2, harness.calls().await);
}

#[tokio::test]
async fn another_subject_token_is_another_exchange() {
    let harness = Harness::start(Flavor::Generic).await;
    let (subject, claims) = harness.person();
    harness
        .issue(&Flavor::Generic.issued_claims(&claims, harness.now()), None)
        .await;
    harness.token(&subject, None).await.expect("a token");
    let mut again = claims.clone();
    again["jti"] = json!("subject-2");
    let other = harness.subject(&again, CallerKind::Person);
    harness.token(&other, None).await.expect("a token");
    assert_eq!(2, harness.calls().await);
}

#[tokio::test]
async fn an_entry_is_renewed_the_margin_before_it_expires() {
    let harness = Harness::start(Flavor::Generic).await;
    let (subject, claims) = harness.person();
    harness
        .issue(&Flavor::Generic.issued_claims(&claims, harness.now()), None)
        .await;
    harness.token(&subject, None).await.expect("a token");
    harness.clock.advance(269);
    harness
        .token(&subject, None)
        .await
        .expect("the cached token");
    assert_eq!(1, harness.calls().await, "still within the margin");
    harness.clock.advance(1);
    harness.token(&subject, None).await.expect("a new token");
    assert_eq!(2, harness.calls().await, "30 seconds before exp");
}

#[tokio::test]
async fn a_token_outliving_its_subject_is_used_only_until_the_subjects_exp() {
    // NOTE: RFC 8693 §2.2.1: the issued token carries its own `expires_in`,
    // here past the subject's.
    let harness = Harness::start(Flavor::Generic).await;
    let now = harness.now();
    let mut claims = Flavor::Generic.subject_claims(now);
    claims["exp"] = json!(now + 120);
    let subject = harness.subject(&claims, CallerKind::Person);
    let mut issued = Flavor::Generic.issued_claims(&claims, now);
    issued["exp"] = json!(now + 3269);
    harness.issue(&issued, None).await;
    let token = harness.token(&subject, None).await.expect("accepted");
    assert_eq!(now + 120, token.expires_at(), "the subject token's exp");
    harness.clock.advance(89);
    harness
        .token(&subject, None)
        .await
        .expect("the cached token");
    assert_eq!(1, harness.calls().await, "within the subject token's life");
    harness.clock.advance(1);
    harness.token(&subject, None).await.expect("a new token");
    assert_eq!(
        2,
        harness.calls().await,
        "the margin before the subject's exp"
    );
    harness.clock.advance(30);
    let error = harness.token(&subject, None).await.expect_err("expired");
    assert!(
        matches!(error, OnwardError::Rejected(Rejected::Expired)),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_cache_hit_that_no_longer_passes_the_check_is_refused_and_dropped() {
    let harness = Harness::start(Flavor::Generic).await;
    let now = harness.now();
    let claims = Flavor::Generic.subject_claims(now);
    let opaque = "opaque-subject-token-1";
    let admitted = |claims: &serde_json::Value| {
        SubjectToken::from_caller(
            &caller(claims, CallerKind::Person),
            SecretString::from(opaque),
        )
        .expect("an opaque token stands on its introspected claims")
    };
    harness
        .issue(&Flavor::Generic.issued_claims(&claims, now), None)
        .await;
    harness
        .token(&admitted(&claims), None)
        .await
        .expect("a token");
    let mut moved = claims.clone();
    moved["sub"] = json!("person-2");
    let error = harness
        .token(&admitted(&moved), None)
        .await
        .expect_err("the hit fails the check");
    assert!(
        matches!(&error, OnwardError::Rejected(Rejected::Person { claim }) if claim == "sub"),
        "{error:?}"
    );
    harness
        .token(&admitted(&claims), None)
        .await
        .expect("a token");
    assert_eq!(2, harness.calls().await, "the refused entry is dropped");
}

thread_local! {
    /// What the capturing subscriber wrote on this thread.
    static CAPTURED: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// A writer into this thread's [`CAPTURED`] bytes.
struct ThreadBuffer;

impl Write for ThreadBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        CAPTURED.with(|captured| captured.borrow_mut().extend_from_slice(bytes));
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Starts capturing every event of this thread at `TRACE`, empty.
///
/// The subscriber is the binary's global one, so its interest in a callsite
/// never depends on which other test's thread registered the callsite
/// first, as a thread-local subscriber's does under `cargo test`'s threads.
fn capture() {
    static GLOBAL: std::sync::Once = std::sync::Once::new();
    GLOBAL.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(|| ThreadBuffer)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("no other test sets the global subscriber");
    });
    CAPTURED.with(|captured| captured.borrow_mut().clear());
}

/// Returns what this thread captured since [`capture`].
fn captured() -> String {
    CAPTURED.with(|captured| String::from_utf8_lossy(&captured.borrow()).into_owned())
}

#[tokio::test]
async fn no_token_reaches_a_log_line_or_a_debug_rendering() {
    capture();
    let harness = Harness::start(Flavor::Generic).await;
    let now = harness.now();
    let claims = Flavor::Generic.subject_claims(now);
    let subject_token = super::sign(&harness.key, &claims);
    let subject = super::subject_of(&subject_token, &claims, CallerKind::Person);
    let issued = harness
        .issue(&Flavor::Generic.issued_claims(&claims, now), None)
        .await;
    let token = harness.token(&subject, None).await.expect("a token");
    harness
        .token(&subject, None)
        .await
        .expect("the cached token");
    let error = harness
        .onward
        .token(&subject, None, &Target::new(Vec::<String>::new()))
        .await
        .expect_err("refused");
    let rendered = format!("{subject:?} {token:?} {error:?} {:?}", harness.onward);
    let logged = captured();
    assert!(logged.contains("onward token"), "the client logs: {logged}");
    for secret in [subject_token.as_str(), issued.as_str()] {
        assert!(!logged.contains(secret), "no token is logged");
        assert!(!rendered.contains(secret), "no token is rendered");
    }
    assert!(
        !rendered.contains("person-1"),
        "no claim of the subject token is rendered"
    );
}

/// RFC 6750 §3.1: a token the resource server refuses as `invalid_token` is
/// dropped, so the next call for its subject and target exchanges again,
/// while another subject's entry, and a token already renewed, stay.
#[tokio::test]
async fn an_invalidated_token_is_exchanged_again_and_other_entries_stay() {
    let harness = Harness::start(Flavor::Generic).await;
    let target = Flavor::Generic.target();
    let (subject, claims) = harness.person();
    harness
        .issue(&Flavor::Generic.issued_claims(&claims, harness.now()), None)
        .await;
    let refused = harness.token(&subject, None).await.expect("a token");
    let mut again = claims.clone();
    again["jti"] = json!("subject-2");
    let other = harness.subject(&again, CallerKind::Person);
    harness.token(&other, None).await.expect("a token");
    assert_eq!(2, harness.calls().await);

    harness.server.reset().await;
    let mut renewed_claims = Flavor::Generic.issued_claims(&claims, harness.now());
    renewed_claims["jti"] = json!("renewed");
    harness.issue(&renewed_claims, None).await;
    harness
        .onward
        .invalidate(&subject, None, &target, refused.header());
    let renewed = harness.token(&subject, None).await.expect("a new token");
    assert_ne!(refused.header(), renewed.header());
    assert_eq!(
        1,
        harness.calls().await,
        "the dropped entry exchanges again"
    );
    harness.token(&other, None).await.expect("the cached token");
    assert_eq!(1, harness.calls().await, "the other subject's entry stays");

    harness
        .onward
        .invalidate(&subject, None, &target, refused.header());
    let held = harness
        .token(&subject, None)
        .await
        .expect("the renewed token");
    assert_eq!(renewed.header(), held.header());
    assert_eq!(
        1,
        harness.calls().await,
        "a token already renewed is not dropped by the stale one"
    );
    let (unknown, _) = harness.person();
    harness
        .onward
        .invalidate(&unknown, None, &target, refused.header());
}
