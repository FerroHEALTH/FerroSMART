// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! What OpenID Connect Core 1.0 §15.1 has every OpenID Provider implement,
//! through the authorization and token endpoints: RS256 ID Tokens,
//! `prompt` with `none` and `login`, `display`, `ui_locales` and
//! `claims_locales`, `auth_time`, `max_age` and `acr_values`, each beside
//! SMART App Launch 2.2.0's own parameters (`docs/architecture.md` §13.25).

use super::*;

/// Sends the authorization request with `overrides` and returns the
/// request cookie and the upstream authorization request it began.
async fn begin(smart: &Smart, overrides: &[(&str, &str)]) -> (String, Url) {
    let (status, headers, body) = smart.get(&authorize_path(overrides), None).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{body}");
    let upstream = location(&headers);
    assert!(
        upstream.as_str().starts_with(&smart.provider.server.uri()),
        "on to the provider: {upstream}"
    );
    (set_cookie(&headers), upstream)
}

/// Answers the upstream login `upstream` began with an ID Token carrying
/// `extra` and returns where the callback sends the browser.
async fn log_in(smart: &Smart, cookie: &str, upstream: &Url, extra: &Value) -> Url {
    let mut claims = json!({
        "sub": "synthetic-person", "name": "Synthetic Clinician", "roles": ["clinician"],
        "fhir_user": PERSON,
        "nonce": param(upstream, "nonce").expect("a nonce"),
    });
    if let (Some(base), Some(over)) = (claims.as_object_mut(), extra.as_object()) {
        base.extend(over.clone());
    }
    smart.provider.answer_claims(&claims).await;
    let callback = format!(
        "/callback?code=synthetic-upstream-code&state={}",
        param(upstream, "state").expect("a state")
    );
    let (status, headers, body) = smart.get(&callback, Some(cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{body}");
    location(&headers)
}

/// Approves the consent page of `cookie` and returns the token response.
async fn approve_and_redeem(smart: &Smart, cookie: &str) -> Value {
    let (status, _, page) = smart.get("/consent", Some(cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    let token = page
        .split("name=\"form_token\" value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("a form token")
        .to_owned();
    let (status, headers, _) = smart
        .post(
            "/consent",
            &[
                ("form_token", &token),
                ("decision", "approve"),
                ("scope", "openid"),
                ("scope", "fhirUser"),
                ("scope", "user/Observation.rs"),
            ],
            Some(cookie),
        )
        .await;
    assert_eq!(
        StatusCode::SEE_OTHER,
        status,
        "the consent sends the browser back"
    );
    let code = param(&location(&headers), "code").expect("a code");
    let exchange = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("client_id", "app"),
    ];
    let (status, _, body) = smart.post("/token", &exchange, None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    serde_json::from_str(&body).expect("JSON")
}

/// The claims of the ID Token of the token response `body`.
fn id_claims(body: &Value) -> Value {
    let id_token = body["id_token"].as_str().expect("an ID Token");
    jsonwebtoken::dangerous::insecure_decode_claims(id_token).expect("claims")
}

/// The time now, in seconds since the epoch.
fn now() -> i64 {
    jiff::Timestamp::now().as_second()
}

// NOTE: OpenID Connect Core 1.0 §15.1 Signing ID Tokens with RSA SHA-256, and
// Authentication Time: the auth_time is the upstream login's.
#[tokio::test]
async fn the_id_token_is_rs256_and_carries_the_upstream_login_s_auth_time() {
    let smart = Smart::start().await;
    let (cookie, upstream) = begin(&smart, &[]).await;
    let authenticated = now() - 120;
    let onward = log_in(
        &smart,
        &cookie,
        &upstream,
        &json!({ "auth_time": authenticated }),
    )
    .await;
    assert_eq!("/consent", onward.path());
    let body = approve_and_redeem(&smart, &cookie).await;
    let header = jsonwebtoken::decode_header(body["id_token"].as_str().expect("an ID Token"))
        .expect("a header");
    assert_eq!(Algorithm::RS256, header.alg);
    assert_eq!(json!(authenticated), id_claims(&body)["auth_time"]);
    smart.stop().await;
}

// NOTE: OpenID Connect Discovery 1.0 §3: id_token_signing_alg_values_supported names
// RS256, display_values_supported and ui_locales_supported what the OP supports.
#[tokio::test]
async fn the_document_names_rs256_the_display_values_and_the_page_languages() {
    let smart = Smart::start().await;
    let (status, _, body) = smart.get("/.well-known/openid-configuration", None).await;
    assert_eq!(StatusCode::OK, status);
    let openid: Value = serde_json::from_str(&body).expect("JSON");
    assert!(
        openid["id_token_signing_alg_values_supported"]
            .as_array()
            .expect("algorithms")
            .contains(&json!("RS256"))
    );
    assert_eq!(
        json!(["page", "popup", "touch", "wap"]),
        openid["display_values_supported"]
    );
    assert_eq!(json!(["en"]), openid["ui_locales_supported"]);
    assert_eq!(
        Value::Null,
        openid["claims_locales_supported"],
        "no claim depends on a language"
    );
    assert!(
        openid["claims_supported"]
            .as_array()
            .expect("claims")
            .contains(&json!("auth_time"))
    );
    smart.stop().await;
}

// NOTE: OpenID Connect Core 1.0 §3.1.2.1 and §3.1.2.6: prompt=none shows no page
// and answers login_required; none beside another value is invalid_request.
#[tokio::test]
async fn prompt_none_answers_login_required_without_a_page() {
    let smart = Smart::start().await;
    for (prompt, error) in [
        ("none", "login_required"),
        ("none login", "invalid_request"),
    ] {
        let (status, headers, _) = smart
            .get(&authorize_path(&[("prompt", prompt)]), None)
            .await;
        assert_eq!(StatusCode::SEE_OTHER, status, "{prompt}");
        let back = location(&headers);
        assert!(back.as_str().starts_with(REDIRECT), "{prompt}: {back}");
        assert_eq!(Some(String::from(error)), param(&back, "error"), "{prompt}");
        assert_eq!(Some(String::from("synthetic-state")), param(&back, "state"));
        assert_eq!(Some(String::from(ISSUER)), param(&back, "iss"));
        assert!(headers.get(header::SET_COOKIE).is_none(), "no login begins");
    }
    smart.stop().await;
}

// NOTE: OpenID Connect Core 1.0 §3.1.2.1: prompt=login re-authenticates the person,
// which the upstream login does; select_account goes with it.
#[tokio::test]
async fn prompt_login_and_select_account_reach_the_upstream_login() {
    let smart = Smart::start().await;
    let (_, upstream) = begin(&smart, &[("prompt", "login select_account")]).await;
    assert_eq!(
        Some(String::from("login select_account")),
        param(&upstream, "prompt")
    );
    let (_, plain) = begin(&smart, &[]).await;
    assert_eq!(None, param(&plain, "prompt"), "nothing asked, nothing sent");
    smart.stop().await;
}

// NOTE: OpenID Connect Core 1.0 §3.1.2.1: prompt=consent asks the person for consent,
// so an organisation approval that would skip the page does not answer for them.
#[tokio::test]
async fn prompt_consent_shows_the_page_the_registration_would_skip() {
    let smart = Smart::start().await;
    let professional = json!({ "fhir_user": "Practitioner/synthetic-1" });
    let scope = ("scope", "openid fhirUser user/Observation.rs");
    let (cookie, upstream) = begin(&smart, &[scope]).await;
    let onward = log_in(&smart, &cookie, &upstream, &professional).await;
    assert!(
        onward.as_str().starts_with(REDIRECT) && param(&onward, "code").is_some(),
        "the registration answers: {onward}"
    );
    let (cookie, upstream) = begin(&smart, &[scope, ("prompt", "consent")]).await;
    let onward = log_in(&smart, &cookie, &upstream, &professional).await;
    assert_eq!("/consent", onward.path(), "the person is asked");
    smart.stop().await;
}

// NOTE: OpenID Connect Core 1.0 §15.1: display, ui_locales, claims_locales and
// acr_values cause no error; ui_locales reaches the upstream login and the pages.
#[tokio::test]
async fn display_locales_and_acr_values_are_taken() {
    let smart = Smart::start().await;
    for display in ["page", "popup", "touch", "wap"] {
        begin(&smart, &[("display", display)]).await;
    }
    let (cookie, upstream) = begin(
        &smart,
        &[
            ("display", "popup"),
            ("ui_locales", "nl-NL en"),
            ("claims_locales", "de"),
            ("acr_values", "urn:mace:incommon:iap:silver"),
        ],
    )
    .await;
    assert_eq!(
        Some(String::from("nl-NL en")),
        param(&upstream, "ui_locales")
    );
    let onward = log_in(&smart, &cookie, &upstream, &json!({})).await;
    assert_eq!("/consent", onward.path());
    let (status, _, page) = smart.get("/consent", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status);
    assert!(
        page.contains("lang=\"en\""),
        "the catalog's language: {page}"
    );
    let body = approve_and_redeem(&smart, &cookie).await;
    assert!(body["id_token"].is_string());
    smart.stop().await;
}

// NOTE: OpenID Connect Core 1.0 §3.1.2.1: past max_age the OP actively
// re-authenticates, and the ID Token carries auth_time.
#[tokio::test]
async fn an_upstream_login_older_than_max_age_is_begun_again_with_prompt_login() {
    let smart = Smart::start().await;
    let (cookie, upstream) = begin(&smart, &[("max_age", "60")]).await;
    assert_eq!(Some(String::from("60")), param(&upstream, "max_age"));
    let again = log_in(
        &smart,
        &cookie,
        &upstream,
        &json!({ "auth_time": now() - 600 }),
    )
    .await;
    assert!(
        again.as_str().starts_with(&smart.provider.server.uri()),
        "back to the provider: {again}"
    );
    assert_eq!(Some(String::from("login")), param(&again, "prompt"));
    assert_eq!(Some(String::from("60")), param(&again, "max_age"));
    assert_ne!(param(&upstream, "state"), param(&again, "state"));
    let fresh = now() - 5;
    let onward = log_in(&smart, &cookie, &again, &json!({ "auth_time": fresh })).await;
    assert_eq!("/consent", onward.path());
    let body = approve_and_redeem(&smart, &cookie).await;
    assert_eq!(json!(fresh), id_claims(&body)["auth_time"]);

    // NOTE: OpenID Connect Core 1.0 §3.1.2.6: a login still older than max_age
    // once begun again is login_required.
    let (cookie, upstream) = begin(&smart, &[("max_age", "60")]).await;
    let again = log_in(
        &smart,
        &cookie,
        &upstream,
        &json!({ "auth_time": now() - 600 }),
    )
    .await;
    let back = log_in(
        &smart,
        &cookie,
        &again,
        &json!({ "auth_time": now() - 600 }),
    )
    .await;
    assert!(back.as_str().starts_with(REDIRECT), "{back}");
    assert_eq!(Some(String::from("login_required")), param(&back, "error"));

    // NOTE: a login that names no auth_time is begun again with prompt=login, which
    // authenticates the person at that login.
    let (cookie, upstream) = begin(&smart, &[("max_age", "60")]).await;
    let again = log_in(&smart, &cookie, &upstream, &json!({})).await;
    assert_eq!(Some(String::from("login")), param(&again, "prompt"));
    let before = now();
    let onward = log_in(&smart, &cookie, &again, &json!({})).await;
    assert_eq!("/consent", onward.path());
    let body = approve_and_redeem(&smart, &cookie).await;
    let auth_time = id_claims(&body)["auth_time"]
        .as_i64()
        .expect("an auth_time");
    assert!(auth_time >= before, "the forced login's time");

    let (status, headers, _) = smart.get(&authorize_path(&[("max_age", "-1")]), None).await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    assert_eq!(
        Some(String::from("invalid_request")),
        param(&location(&headers), "error")
    );
    smart.stop().await;
}
