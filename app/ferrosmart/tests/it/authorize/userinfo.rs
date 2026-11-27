// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The UserInfo Endpoint (OpenID Connect Core 1.0 §5.3) answering a token
//! the code flow issued, its RFC 6750 §3 refusals, and FerroSMART's own
//! UserInfo request to an upstream provider that names a UserInfo Endpoint.

use super::*;

/// The ceiling of the app in these cases.
const CEILING: &str = "[\"openid\", \"fhirUser\", \"profile\", \"email\", \"user/Observation.rs\"]";

/// The upstream claims the person's login carries.
fn upstream_claims() -> Value {
    json!({
        "name": "Synthetic Clinician", "preferred_username": "sclinician",
        "email": "clinician@example.org", "email_verified": true
    })
}

/// Starts FerroSMART for an app with [`CEILING`].
async fn started() -> Smart {
    Smart::start_with(
        "[\"authorization_code\"]",
        CEILING,
        "[\"user/Observation.rs\"]",
    )
    .await
}

/// Sends a UserInfo request by `method` with the `Authorization` header
/// `authorization`, when there is one.
async fn ask(
    smart: &Smart,
    method: &str,
    authorization: Option<&str>,
) -> (StatusCode, http::HeaderMap, String) {
    let mut request = Request::builder().method(method).uri("/userinfo");
    if let Some(authorization) = authorization {
        request = request.header(header::AUTHORIZATION, authorization);
    }
    smart
        .send(request.body(Body::empty()).expect("a request"))
        .await
}

/// Returns the challenge of a refusal.
fn challenge(headers: &http::HeaderMap) -> Option<&str> {
    headers
        .get(header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
}

// NOTE: OpenID Connect Core 1.0 §5.3.1 and §5.3.2, GET and POST with a bearer
// token answer `sub` and the claims the ID Token carries.
#[tokio::test]
async fn userinfo_answers_the_id_token_s_subject_and_claims_by_get_and_post() {
    let smart = started().await;
    let body = with_claims(&smart, "openid fhirUser profile email", &upstream_claims()).await;
    let id = jwt_claims(&body, "id_token");
    let bearer = format!(
        "Bearer {}",
        body["access_token"].as_str().expect("an access token")
    );
    for method in ["GET", "POST"] {
        let (status, headers, answer) = ask(&smart, method, Some(&bearer)).await;
        assert_eq!(StatusCode::OK, status, "{method}: {answer}");
        assert_eq!(
            Some("no-store"),
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok())
        );
        let answer: Value = serde_json::from_str(&answer).expect("JSON");
        assert_eq!(id["sub"], answer["sub"], "the ID Token's sub");
        assert_eq!(json!(PERSON), answer["fhirUser"]);
        for claim in ["name", "preferred_username", "email", "email_verified"] {
            assert_eq!(id[claim], answer[claim], "{claim}");
        }
        for claim in ["iss", "aud", "nonce", "auth_time"] {
            assert!(answer.get(claim).is_none(), "no {claim} in a JSON answer");
        }
    }
    smart.stop().await;
}

// NOTE: OpenID Connect Core 1.0 §5.4, the claims the granted scope passes on.
#[tokio::test]
async fn userinfo_answers_only_what_the_granted_scope_passes_on() {
    let smart = started().await;
    let body = with_claims(&smart, "openid profile", &upstream_claims()).await;
    let bearer = format!("Bearer {}", body["access_token"].as_str().expect("a token"));
    let (status, _, answer) = ask(&smart, "GET", Some(&bearer)).await;
    assert_eq!(StatusCode::OK, status, "{answer}");
    let answer: Value = serde_json::from_str(&answer).expect("JSON");
    assert_eq!(json!("sclinician"), answer["preferred_username"]);
    for claim in ["email", "email_verified", "fhirUser"] {
        assert!(answer.get(claim).is_none(), "not granted: {claim}");
    }
    smart.stop().await;
}

// NOTE: RFC 6750 §3.1, a request without a token gets a challenge with no
// error code; an unknown or forged token is invalid_token.
#[tokio::test]
async fn userinfo_without_a_valid_token_is_refused_with_a_401() {
    let smart = started().await;
    let (status, headers, _) = ask(&smart, "GET", None).await;
    assert_eq!(StatusCode::UNAUTHORIZED, status);
    assert_eq!(Some("Bearer"), challenge(&headers));
    let (status, headers, _) = ask(&smart, "GET", Some("Basic YXBwOnNlY3JldA==")).await;
    assert_eq!(StatusCode::UNAUTHORIZED, status);
    assert_eq!(Some("Bearer"), challenge(&headers));
    let body = with_claims(&smart, "openid profile", &upstream_claims()).await;
    let token = body["access_token"].as_str().expect("a token");
    let forged = format!("Bearer {token}x");
    for authorization in [forged.as_str(), "Bearer synthetic-not-a-token"] {
        let (status, headers, _) = ask(&smart, "GET", Some(authorization)).await;
        assert_eq!(StatusCode::UNAUTHORIZED, status, "{authorization}");
        assert_eq!(Some("Bearer error=\"invalid_token\""), challenge(&headers));
    }
    let (status, headers, _) = ask(&smart, "GET", Some("Bearer")).await;
    assert_eq!(StatusCode::BAD_REQUEST, status);
    assert_eq!(
        Some("Bearer error=\"invalid_request\""),
        challenge(&headers)
    );
    smart.stop().await;
}

// NOTE: RFC 6750 §3.1, a token whose grant holds no `openid` is
// insufficient_scope, answered 403.
#[tokio::test]
async fn userinfo_refuses_a_token_without_openid_with_a_403() {
    let smart = started().await;
    let (_, headers, _) = smart
        .get(&authorize_path(&[("scope", "user/Observation.rs")]), None)
        .await;
    let upstream = location(&headers);
    let cookie = set_cookie(&headers);
    smart
        .provider
        .answer(&param(&upstream, "nonce").expect("a nonce"), &["clinician"])
        .await;
    let callback = format!(
        "/callback?code=synthetic-upstream-code&state={}",
        param(&upstream, "state").expect("a state")
    );
    smart.get(&callback, Some(&cookie)).await;
    let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
    let (_, headers, _) = smart
        .post(
            "/consent",
            &[
                ("form_token", form_token(&page).as_str()),
                ("decision", "approve"),
                ("scope", "user/Observation.rs"),
            ],
            Some(&cookie),
        )
        .await;
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
    let body: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(json!("user/Observation.rs"), body["scope"]);
    let bearer = format!("Bearer {}", body["access_token"].as_str().expect("a token"));
    let (status, headers, _) = ask(&smart, "GET", Some(&bearer)).await;
    assert_eq!(StatusCode::FORBIDDEN, status);
    assert_eq!(
        Some("Bearer error=\"insufficient_scope\""),
        challenge(&headers)
    );
    smart.stop().await;
}

// NOTE: RFC 7009 §2.1, a revoked grant's tokens no longer answer.
#[tokio::test]
async fn userinfo_refuses_a_revoked_token() {
    let smart = started().await;
    let body = with_claims(&smart, "openid profile", &upstream_claims()).await;
    let token = body["access_token"].as_str().expect("a token");
    let (status, _, _) = smart
        .post("/revoke", &[("token", token), ("client_id", "app")], None)
        .await;
    assert_eq!(StatusCode::OK, status);
    let (status, headers, _) = ask(&smart, "GET", Some(&format!("Bearer {token}"))).await;
    assert_eq!(StatusCode::UNAUTHORIZED, status);
    assert_eq!(Some("Bearer error=\"invalid_token\""), challenge(&headers));
    smart.stop().await;
}

/// Starts FerroSMART for an app with [`CEILING`] whose upstream provider
/// names a UserInfo Endpoint answering `userinfo`.
async fn started_with_upstream_userinfo(userinfo: ResponseTemplate) -> Smart {
    let provider = Provider::start_naming(&json!({ "userinfo_endpoint": "/userinfo" })).await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/userinfo"))
        .and(matchers::header(
            "authorization",
            "Bearer synthetic-upstream-token",
        ))
        .respond_with(userinfo)
        .mount(&provider.server)
        .await;
    Smart::start_at(
        provider,
        "[\"authorization_code\"]",
        CEILING,
        "[\"user/Observation.rs\"]",
        "",
        &[REDIRECT],
        "",
    )
    .await
}

// NOTE: OpenID Connect Core 1.0 §5.3, the relying party asks the provider's
// UserInfo Endpoint, and its claims complete the ID Token's.
#[tokio::test]
async fn the_upstream_userinfo_response_completes_the_login() {
    let smart = started_with_upstream_userinfo(ResponseTemplate::new(200).set_body_json(json!({
        "sub": "synthetic-person", "email": "clinician@example.org", "email_verified": true
    })))
    .await;
    let body = with_claims(&smart, "openid email", &json!({})).await;
    let id = jwt_claims(&body, "id_token");
    assert_eq!(json!("clinician@example.org"), id["email"]);
    assert_eq!(json!(true), id["email_verified"]);
    smart.stop().await;
}

// NOTE: OpenID Connect Core 1.0 §5.3.2, a UserInfo Response about another
// subject is not used, and the login fails.
#[tokio::test]
async fn an_upstream_userinfo_response_about_another_subject_ends_the_login() {
    let smart = started_with_upstream_userinfo(ResponseTemplate::new(200).set_body_json(json!({
        "sub": "synthetic-other", "email": "other@example.org"
    })))
    .await;
    let (_, headers, _) = smart
        .get(&authorize_path(&[("scope", "openid email")]), None)
        .await;
    let upstream = location(&headers);
    let cookie = set_cookie(&headers);
    smart
        .provider
        .answer_claims(&json!({
            "sub": "synthetic-person", "roles": ["clinician"], "fhir_user": PERSON,
            "nonce": param(&upstream, "nonce").expect("a nonce")
        }))
        .await;
    let callback = format!(
        "/callback?code=synthetic-upstream-code&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, headers, _) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let back = location(&headers);
    assert!(back.as_str().starts_with(REDIRECT), "{back}");
    assert_eq!(Some(String::from("server_error")), param(&back, "error"));
    smart.stop().await;
}

// NOTE: OpenID Connect Discovery 1.0 §3, userinfo_endpoint is RECOMMENDED; RFC
// 8414 §2 lets the same member stand in the authorization server's metadata.
#[tokio::test]
async fn discovery_names_the_userinfo_endpoint() {
    let smart = started().await;
    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        let (status, _, body) = smart.get(path, None).await;
        assert_eq!(StatusCode::OK, status, "{path}");
        let document: Value = serde_json::from_str(&body).expect("JSON");
        assert_eq!(
            json!(format!("{ISSUER}/userinfo")),
            document["userinfo_endpoint"],
            "{path}"
        );
    }
    smart.stop().await;
}
