// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! No silent code for a public client without a claimed `https` redirect:
//! an organisation approval or a remembered consent answers for the person
//! only when the request's redirect URI assures the app's identity, and the
//! page shows otherwise, starting from the remembered decision (RFC 8252
//! §8.6, §7.2; RFC 6749 §10.2).

use super::*;

/// A custom-scheme redirect of a native app (RFC 8252 §7.1).
const CUSTOM: &str = "com.example.app:/callback";

/// A loopback redirect of a native app (RFC 8252 §7.3).
const LOOPBACK: &str = "http://127.0.0.1:8400/callback";

/// Starts FerroSMART whose public app is the organisation's own, approved
/// for what a patient's launch asks, and registers `REDIRECT`, [`CUSTOM`]
/// and [`LOOPBACK`].
async fn start_first_party() -> Smart {
    Smart::start_redirecting(
        "[\"authorization_code\"]",
        "[\"openid\", \"fhirUser\", \"user/Observation.rs\"]\n\
         \
         first_party = true",
        "[\"user/Observation.rs\"]",
        &[REDIRECT, CUSTOM, LOOPBACK],
    )
    .await
}

/// Runs the request to `redirect` asking for `scope` and the login of a
/// patient, and returns the cookie and where the callback sends the browser.
pub(super) async fn login(smart: &Smart, redirect: &str, scope: &str) -> (String, Url) {
    let path = authorize_path(&[("redirect_uri", redirect), ("scope", scope)]);
    let (status, headers, body) = smart.get(&path, None).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "on to the provider: {body}");
    let upstream = location(&headers);
    let cookie = set_cookie(&headers);
    smart
        .provider
        .answer_as(
            &param(&upstream, "nonce").expect("a nonce"),
            &["clinician"],
            "synthetic-person",
            "Patient/synthetic-2",
        )
        .await;
    let callback = format!(
        "/callback?code=a&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, headers, _) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "the login returns");
    (cookie, location(&headers))
}

#[tokio::test]
async fn a_first_party_public_app_with_a_claimed_https_redirect_gets_a_silent_code() {
    let smart = start_first_party().await;
    let (_, back) = login(&smart, REDIRECT, "openid fhirUser").await;
    assert!(
        back.as_str().starts_with(REDIRECT) && param(&back, "code").is_some(),
        "the claimed https redirect assures the app: {back}"
    );
    smart.stop().await;
}

#[tokio::test]
async fn a_first_party_public_app_with_a_custom_scheme_redirect_shows_the_page() {
    let smart = start_first_party().await;
    let (_, back) = login(&smart, CUSTOM, "openid fhirUser").await;
    assert_eq!("/consent", back.path(), "a custom scheme assures nothing");
    smart.stop().await;
}

#[tokio::test]
async fn a_first_party_public_app_with_a_loopback_redirect_shows_the_page() {
    let smart = start_first_party().await;
    let (_, back) = login(&smart, LOOPBACK, "openid fhirUser").await;
    assert_eq!("/consent", back.path(), "any app may listen on loopback");
    smart.stop().await;
}

#[tokio::test]
async fn a_remembered_consent_of_a_custom_scheme_app_shows_the_page_with_the_decision_ticked() {
    let smart = Smart::start_redirecting(
        "[\"authorization_code\"]",
        "[\"openid\", \"fhirUser\", \"user/Observation.rs\"]",
        "[\"user/Observation.rs\"]",
        &[CUSTOM],
    )
    .await;
    let scope = "openid fhirUser user/Observation.rs";
    let (cookie, back) = login(&smart, CUSTOM, scope).await;
    assert_eq!("/consent", back.path());
    let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
    assert!(
        !page
            .contains("name=\"remember\" value=\"yes\" aria-describedby=\"remember-help\" checked"),
        "nothing remembered yet: {page}"
    );
    let decision = [
        ("form_token", form_token(&page)),
        ("decision", String::from("approve")),
        ("scope", String::from("user/Observation.rs")),
        ("remember", String::from("yes")),
    ];
    let pairs: Vec<(&str, &str)> = decision
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    let (status, headers, _) = smart.post("/consent", &pairs, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    assert!(location(&headers).as_str().starts_with(CUSTOM), "the code");

    let (cookie, back) = login(&smart, CUSTOM, scope).await;
    assert_eq!(
        "/consent",
        back.path(),
        "the remembered consent does not answer for an unassured app"
    );
    let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
    assert!(
        page.contains("name=\"remember\" value=\"yes\" aria-describedby=\"remember-help\" checked"),
        "the remembered decision is preselected: {page}"
    );
    assert!(
        page.contains("value=\"user/Observation.rs\" checked"),
        "the remembered scope is ticked: {page}"
    );
    smart.stop().await;
}
