// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The authorization code flow with PKCE through the four routes: the sign-in with its return path, the refusals, the refresh with
//! rotation, the session watch and the sign-out.

use axum::Router;
use ferrohealth_secret::secret::Secret;
use ferrohealth_session::config::SessionSection;
use ferrohealth_session::cookies::CookieNames;
use ferrohealth_session::record::SignedIn;
use ferrohealth_session::routes::{Pages as _, SignIn};
use ferrohealth_session::sessions::Sessions;
use http::{Method, StatusCode};

use crate::console::{Browser, RESOURCE, TestPages, console, console_of, query, sign_in};
use crate::provider::Provider;

/// The `state`, `nonce` and challenge `GET /login?return=…` sent the
/// browser to the provider with.
struct Begun {
    state: String,
    nonce: String,
    challenge: String,
}

async fn begin(app: &Router, browser: &mut Browser, provider: &Provider) -> Begun {
    let answer = browser
        .get(app, "/login?return=%2Fsources%3Fpage%3D2")
        .await;
    assert_eq!(StatusCode::SEE_OTHER, answer.status, "{answer:?}");
    assert_eq!(Some("no-store"), answer.cache.as_deref(), "never cached");
    let location = answer.location.expect("a redirect");
    assert!(
        location.starts_with(&format!("{}/authorize?", provider.uri())),
        "{location}"
    );
    let sent = query(&location);
    assert_eq!(
        Some("code"),
        sent.get("response_type").map(String::as_str),
        "RFC 6749 §4.1.1"
    );
    assert_eq!(
        Some("S256"),
        sent.get("code_challenge_method").map(String::as_str),
        "RFC 7636 §4.3"
    );
    assert_eq!(
        Some("openid profile"),
        sent.get("scope").map(String::as_str),
        "the scopes configured"
    );
    assert!(
        answer
            .set_cookies
            .iter()
            .any(|cookie| cookie.starts_with("__Host-synthetic_console_sign_in=")),
        "{:?}",
        answer.set_cookies
    );
    Begun {
        state: sent.get("state").expect("a state").clone(),
        nonce: sent.get("nonce").expect("a nonce").clone(),
        challenge: sent.get("code_challenge").expect("a challenge").clone(),
    }
}

async fn signed_in(
    provider: &Provider,
    tokens: impl Fn(&str) -> serde_json::Value,
) -> (Router, Browser) {
    let app = console(provider).await;
    let mut browser = Browser::default();
    let begun = begin(&app, &mut browser, provider).await;
    provider
        .mount_exchange(&begun.challenge, tokens(&provider.id_token(&begun.nonce)))
        .await;
    let answer = browser
        .get(
            &app,
            &format!("/auth/callback?code=synthetic-code&state={}", begun.state),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, answer.status, "{answer:?}");
    assert_eq!(
        Some("/sources?page=2"),
        answer.location.as_deref(),
        "the return path"
    );
    assert!(
        answer
            .set_cookies
            .iter()
            .any(|cookie| cookie.contains("_sign_in=") && cookie.contains("Max-Age=0")),
        "the sign-in cookie is spent"
    );
    assert!(
        browser.jar.contains_key("__Host-synthetic_console_session"),
        "{:?}",
        browser.jar
    );
    (app, browser)
}

fn tokens(id_token: &str) -> serde_json::Value {
    serde_json::json!({
        "access_token": "synthetic-access-1",
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": id_token
    })
}

#[tokio::test]
async fn an_operator_signs_in_is_watched_and_signs_out() {
    let provider = Provider::start().await;
    let (app, mut browser) = signed_in(&provider, tokens).await;
    let page = browser.get(&app, "/").await;
    assert_eq!("Synthetic Operator synthetic-access-1", page.body);
    let watch = browser.get(&app, "/session").await;
    assert_eq!(StatusCode::OK, watch.status);
    assert_eq!(Some("no-store"), watch.cache.as_deref());
    let left: serde_json::Value = serde_json::from_str(&watch.body).expect("JSON");
    assert!(
        left["idle"].as_u64().is_some_and(|idle| idle <= 300),
        "{left}"
    );
    assert!(
        left["absolute"]
            .as_u64()
            .is_some_and(|absolute| absolute <= 300),
        "{left}"
    );
    let extended = browser.send(&app, Method::POST, "/session").await;
    assert_eq!(StatusCode::OK, extended.status);
    provider
        .mount_revoke("synthetic-access-1", "access_token")
        .await;
    let out = browser.send(&app, Method::POST, "/logout").await;
    assert_eq!(StatusCode::SEE_OTHER, out.status);
    let location = out.location.expect("a redirect");
    assert!(
        location.starts_with(&format!("{}/logout?", provider.uri())),
        "{location}"
    );
    assert!(
        query(&location).contains_key("id_token_hint"),
        "RP-Initiated Logout 1.0 §2"
    );
    assert!(
        !browser.jar.contains_key("__Host-synthetic_console_session"),
        "the cookie is removed"
    );
    let gone = browser.get(&app, "/session").await;
    assert_eq!(StatusCode::UNAUTHORIZED, gone.status);
    assert_eq!(
        Some("application/problem+json"),
        gone.content_type.as_deref(),
        "RFC 9457 §3"
    );
    assert_eq!(Some("no-store"), gone.cache.as_deref());
    let problem: serde_json::Value = serde_json::from_str(&gone.body).expect("JSON");
    assert_eq!("about:blank", problem["type"], "RFC 9457 §4.2.1");
    assert_eq!(401, problem["status"]);
    assert_eq!("Unauthorized", problem["title"]);
    assert_eq!(
        crate::console::GONE,
        problem["detail"],
        "the console's words"
    );
    provider.server.verify().await;
}

#[tokio::test]
async fn a_redirect_with_another_state_is_refused() {
    let provider = Provider::start().await;
    let app = console(&provider).await;
    let mut browser = Browser::default();
    begin(&app, &mut browser, &provider).await;
    let answer = browser
        .get(&app, "/auth/callback?code=synthetic-code&state=forged")
        .await;
    assert_eq!(
        (StatusCode::BAD_REQUEST, "StateMismatch"),
        (answer.status, answer.body.as_str())
    );
    let again = browser
        .get(&app, "/auth/callback?code=synthetic-code&state=forged")
        .await;
    assert_eq!(
        "NoSignInPending", again.body,
        "the sign-in is spent either way"
    );
}

#[tokio::test]
async fn a_callback_with_no_sign_in_pending_is_refused() {
    let provider = Provider::start().await;
    let app = console(&provider).await;
    let answer = Browser::default()
        .get(&app, "/auth/callback?code=synthetic-code&state=any")
        .await;
    assert_eq!(
        (StatusCode::BAD_REQUEST, "NoSignInPending"),
        (answer.status, answer.body.as_str())
    );
}

#[tokio::test]
async fn a_provider_that_refuses_the_operator_is_a_rejected_sign_in() {
    let provider = Provider::start().await;
    let app = console(&provider).await;
    let mut browser = Browser::default();
    let begun = begin(&app, &mut browser, &provider).await;
    let answer = browser
        .get(
            &app,
            &format!("/auth/callback?error=access_denied&state={}", begun.state),
        )
        .await;
    assert_eq!(
        (StatusCode::UNAUTHORIZED, "Rejected"),
        (answer.status, answer.body.as_str())
    );
}

#[tokio::test]
async fn an_id_token_with_another_nonce_is_a_rejected_sign_in() {
    let provider = Provider::start().await;
    let app = console(&provider).await;
    let mut browser = Browser::default();
    let begun = begin(&app, &mut browser, &provider).await;
    provider
        .mount_exchange(
            &begun.challenge,
            tokens(&provider.id_token("another-nonce")),
        )
        .await;
    let answer = browser
        .get(
            &app,
            &format!("/auth/callback?code=synthetic-code&state={}", begun.state),
        )
        .await;
    assert_eq!(
        (StatusCode::UNAUTHORIZED, "Rejected"),
        (answer.status, answer.body.as_str())
    );
    assert!(
        !browser.jar.contains_key("__Host-synthetic_console_session"),
        "no session"
    );
}

#[tokio::test]
async fn a_provider_that_fails_is_a_sign_in_not_completed() {
    let provider = Provider::start().await;
    let app = console(&provider).await;
    let mut browser = Browser::default();
    let begun = begin(&app, &mut browser, &provider).await;
    provider.mount_failing_token().await;
    let answer = browser
        .get(
            &app,
            &format!("/auth/callback?code=synthetic-code&state={}", begun.state),
        )
        .await;
    assert_eq!(
        (StatusCode::BAD_GATEWAY, "NotCompleted"),
        (answer.status, answer.body.as_str())
    );
}

fn refreshable(id_token: &str) -> serde_json::Value {
    serde_json::json!({
        "access_token": "synthetic-access-1",
        "token_type": "Bearer",
        "expires_in": 0,
        "refresh_token": "synthetic-refresh-1",
        "id_token": id_token
    })
}

#[tokio::test]
async fn an_access_token_due_is_refreshed_and_its_rotated_refresh_token_kept() {
    let provider = Provider::start().await;
    let (app, mut browser) = signed_in(&provider, refreshable).await;
    provider
        .mount_refresh(
            "synthetic-refresh-1",
            200,
            serde_json::json!({
                "access_token": "synthetic-access-2",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "synthetic-refresh-2"
            }),
        )
        .await;
    let page = browser.get(&app, "/").await;
    assert_eq!(
        "Synthetic Operator synthetic-access-2", page.body,
        "RFC 6749 §6"
    );
    let again = browser.get(&app, "/").await;
    assert_eq!(
        "Synthetic Operator synthetic-access-2", again.body,
        "refreshed once"
    );
    provider
        .mount_revoke("synthetic-refresh-2", "refresh_token")
        .await;
    browser.send(&app, Method::POST, "/logout").await;
    provider.server.verify().await;
}

#[tokio::test]
async fn a_refused_refresh_ends_the_session() {
    let provider = Provider::start().await;
    let (app, mut browser) = signed_in(&provider, refreshable).await;
    provider
        .mount_refresh(
            "synthetic-refresh-1",
            400,
            serde_json::json!({ "error": "invalid_grant" }),
        )
        .await;
    let page = browser.get(&app, "/").await;
    assert_eq!("Ended", page.body, "RFC 6749 §5.2");
    assert!(
        !browser.jar.contains_key("__Host-synthetic_console_session"),
        "the cookie is removed"
    );
    provider.server.verify().await;
}

#[tokio::test]
async fn a_console_with_no_provider_answers_not_configured() {
    let settings = SessionSection::default().check().expect("valid");
    let sessions = Sessions::new(settings, CookieNames::for_console("synthetic_console"));
    let app = console_of(SignIn::new(sessions, None, TestPages));
    let answer = Browser::default().get(&app, "/login").await;
    assert_eq!(
        (StatusCode::SERVICE_UNAVAILABLE, "NotConfigured"),
        (answer.status, answer.body.as_str())
    );
    let home = Browser::default().get(&app, "/").await;
    assert_eq!("Absent", home.body, "no cookie, no session");
}

#[tokio::test]
async fn a_sign_out_with_no_provider_ends_the_session_and_lands_on_the_signed_out_page() {
    let settings = SessionSection::default().check().expect("valid");
    let sessions = Sessions::new(settings, CookieNames::for_console("synthetic_console"));
    let cookie = sessions
        .establish(
            &http::HeaderMap::new(),
            SignedIn::basic("synthetic-operator", Secret::new("synthetic-password")),
        )
        .expect("a session");
    let app = console_of(SignIn::new(sessions, None, TestPages));
    let mut browser = Browser::default();
    let name = browser.keep(&cookie);
    let out = browser.send(&app, Method::POST, "/logout").await;
    assert_eq!(StatusCode::SEE_OTHER, out.status, "never a 503");
    assert_eq!(Some(TestPages.signed_out()), out.location.as_deref());
    assert!(!browser.jar.contains_key(&name), "the cookie is removed");
    let home = browser.get(&app, "/").await;
    assert_eq!("Absent", home.body, "the session is gone");
}

#[tokio::test]
async fn a_basic_sign_out_with_a_provider_lands_on_the_signed_out_page() {
    let provider = Provider::start().await;
    let sign_in = sign_in(&provider).await;
    let cookie = sign_in
        .sessions()
        .establish(
            &http::HeaderMap::new(),
            SignedIn::basic("synthetic-operator", Secret::new("synthetic-password")),
        )
        .expect("a session");
    let app = console_of(sign_in);
    let mut browser = Browser::default();
    let name = browser.keep(&cookie);
    let page = browser.get(&app, "/").await;
    assert_eq!("synthetic-operator", page.body);
    let out = browser.send(&app, Method::POST, "/logout").await;
    assert_eq!(StatusCode::SEE_OTHER, out.status);
    assert_eq!(
        Some(TestPages.signed_out()),
        out.location.as_deref(),
        "RP-Initiated Logout 1.0 §2: no ID Token, no session at the provider to end"
    );
    assert!(!browser.jar.contains_key(&name), "the cookie is removed");
    let home = browser.get(&app, "/").await;
    assert_eq!("Absent", home.body, "the session is gone");
    provider.server.verify().await;
}

#[tokio::test]
async fn a_return_path_off_the_console_leads_home() {
    let provider = Provider::start().await;
    let app = console(&provider).await;
    let mut browser = Browser::default();
    let answer = browser
        .get(&app, "/login?return=%2F%2Felsewhere.example")
        .await;
    let sent = query(&answer.location.expect("a redirect"));
    let nonce = sent.get("nonce").expect("a nonce").clone();
    provider
        .mount_exchange(
            sent.get("code_challenge").expect("a challenge"),
            tokens(&provider.id_token(&nonce)),
        )
        .await;
    let back = browser
        .get(
            &app,
            &format!(
                "/auth/callback?code=synthetic-code&state={}",
                sent.get("state").expect("a state")
            ),
        )
        .await;
    assert_eq!(Some("/"), back.location.as_deref(), "RFC 3986 §4.2");
}

/// A sign-in whose access token lasts an hour, with a refresh token.
fn lasting(id_token: &str) -> serde_json::Value {
    serde_json::json!({
        "access_token": "synthetic-access-1",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "synthetic-refresh-1",
        "id_token": id_token
    })
}

#[tokio::test]
async fn a_token_for_another_resource_is_refreshed_once_and_its_rotated_refresh_token_kept() {
    let provider = Provider::start().await;
    let (app, mut browser) = signed_in(&provider, lasting).await;
    provider
        .mount_refresh_for(
            "synthetic-refresh-1",
            RESOURCE,
            200,
            serde_json::json!({
                "access_token": "synthetic-fhir-1",
                "token_type": "Bearer",
                "expires_in": 300,
                "refresh_token": "synthetic-refresh-2"
            }),
        )
        .await;
    // NOTE: RFC 8707 §2.2, the refresh names the resource the token is for.
    let first = browser.get(&app, "/resource").await;
    assert_eq!("Issued synthetic-fhir-1", first.body);
    let again = browser.get(&app, "/resource").await;
    assert_eq!(
        "Issued synthetic-fhir-1", again.body,
        "kept until it is due"
    );
    let home = browser.get(&app, "/").await;
    assert_eq!(
        "Synthetic Operator synthetic-access-1", home.body,
        "the session's own token stays"
    );
    // NOTE: RFC 9700 §4.14.2, the rotated refresh token replaces the session's.
    provider
        .mount_revoke("synthetic-refresh-2", "refresh_token")
        .await;
    browser.send(&app, Method::POST, "/logout").await;
    provider.server.verify().await;
}

#[tokio::test]
async fn a_refused_resource_leaves_the_session_and_a_refused_grant_ends_it() {
    let provider = Provider::start().await;
    let (app, mut browser) = signed_in(&provider, lasting).await;
    provider
        .mount_refresh_for(
            "synthetic-refresh-1",
            RESOURCE,
            400,
            serde_json::json!({ "error": "invalid_target" }),
        )
        .await;
    let refused = browser.get(&app, "/resource").await;
    assert_eq!("Refused", refused.body, "RFC 8707 §2");
    let home = browser.get(&app, "/").await;
    assert_eq!("Synthetic Operator synthetic-access-1", home.body);
    provider.server.verify().await;

    provider.server.reset().await;
    provider
        .mount_refresh_for(
            "synthetic-refresh-1",
            RESOURCE,
            400,
            serde_json::json!({ "error": "invalid_grant" }),
        )
        .await;
    let ended = browser.get(&app, "/resource").await;
    assert_eq!("Ended", ended.body, "RFC 6749 §5.2");
    let home = browser.get(&app, "/").await;
    assert!(
        !home.body.starts_with("Synthetic Operator"),
        "{}",
        home.body
    );
    provider.server.verify().await;
}
