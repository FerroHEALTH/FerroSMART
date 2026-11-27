// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Pushed authorization requests (RFC 9126): the request posted to
//! `{issuer}/par`, a `request_uri` taken once at the authorization
//! endpoint, and the server's and a client's requirement of them.

use super::*;

/// The authorization request of [`authorize_path`] as form pairs, with
/// `overrides` over the defaults.
fn request(overrides: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
    let mut pairs: Vec<(&str, &str)> = vec![
        ("response_type", "code"),
        ("client_id", "app"),
        ("redirect_uri", REDIRECT),
        ("scope", "openid fhirUser user/Observation.rs"),
        ("state", "synthetic-state"),
        ("aud", RESOURCE),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ];
    for (name, value) in overrides {
        pairs.retain(|(kept, _)| kept != name);
        if !value.is_empty() {
            pairs.push((name, value));
        }
    }
    pairs
}

/// Starts a server whose app reaches [`RESOURCE`], with the `[ferrosmart]`
/// keys `settings`.
async fn start(settings: &str) -> Smart {
    Smart::start_setting(
        "[\"authorization_code\"]",
        "[\"openid\", \"fhirUser\", \"user/Observation.rs\"]",
        "[\"user/Observation.rs\"]",
        &format!("[[ferrosmart.resource]]\nbase = {RESOURCE:?}\n"),
        &[REDIRECT],
        settings,
    )
    .await
}

/// Pushes `pairs` and returns the status and the answer.
async fn push(smart: &Smart, pairs: &[(&str, &str)]) -> (StatusCode, http::HeaderMap, Value) {
    let (status, headers, body) = smart.post("/par", pairs, None).await;
    (
        status,
        headers,
        serde_json::from_str(&body).unwrap_or(Value::Null),
    )
}

/// Returns the authorization request naming `request_uri` for `client_id`.
fn by_reference(client_id: &str, request_uri: &str) -> String {
    format!(
        "/authorize?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([("client_id", client_id), ("request_uri", request_uri)])
            .finish()
    )
}

// NOTE: RFC 9126 §2.2, a 201 with a `request_uri` and its `expires_in`; §4, the
// authorization endpoint takes the pushed request in its place, once.
#[tokio::test]
async fn a_pushed_request_is_taken_once_at_the_authorization_endpoint() {
    let smart = start("").await;
    let (status, headers, answer) = push(&smart, &request(&[])).await;
    assert_eq!(StatusCode::CREATED, status, "{answer}");
    assert_eq!(
        Some("no-store"),
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
    );
    assert_eq!(Some(60), answer["expires_in"].as_i64());
    let request_uri = answer["request_uri"].as_str().expect("a request_uri");
    assert!(request_uri.starts_with("urn:ietf:params:oauth:request_uri:"));
    let (status, headers, _) = smart.get(&by_reference("app", request_uri), None).await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let upstream = location(&headers);
    assert!(
        upstream.as_str().starts_with(&smart.provider.server.uri()),
        "the pushed request begins the login"
    );
    let (replayed, _, _) = smart.get(&by_reference("app", request_uri), None).await;
    assert_eq!(
        StatusCode::NOT_FOUND,
        replayed,
        "RFC 9126 §4: a request_uri is used once"
    );
    smart.stop().await;
}

// NOTE: RFC 9126 §4, "An expired request_uri MUST be rejected as invalid".
#[tokio::test]
async fn an_expired_request_uri_is_refused() {
    use sqlx::Connection as _;
    let smart = start("").await;
    let (_, _, answer) = push(&smart, &request(&[])).await;
    let request_uri = answer["request_uri"].as_str().expect("a request_uri");
    let mut connection =
        sqlx::PgConnection::connect(secrecy::ExposeSecret::expose_secret(&smart.database.url))
            .await
            .expect("connects");
    sqlx::query("UPDATE pushed_request SET expires_at = now() - interval '1 second'")
        .execute(&mut connection)
        .await
        .expect("lapsed");
    let (status, _, _) = smart.get(&by_reference("app", request_uri), None).await;
    assert_eq!(StatusCode::NOT_FOUND, status);
    smart.stop().await;
}

// NOTE: RFC 9126 §2.2, the request_uri "MUST be bound to the client that posted
// the authorization request".
#[tokio::test]
async fn another_clients_request_uri_is_refused() {
    let smart = start("").await;
    let (_, _, answer) = push(&smart, &request(&[])).await;
    let request_uri = answer["request_uri"].as_str().expect("a request_uri");
    let (status, _, _) = smart
        .get(&by_reference("another-app", request_uri), None)
        .await;
    assert_eq!(StatusCode::NOT_FOUND, status);
    smart.stop().await;
}

// NOTE: RFC 9126 §2.1, the endpoint rejects a `request_uri` and validates the
// request as the authorization endpoint would; §2.3, the token endpoint's errors.
#[tokio::test]
async fn a_request_the_authorization_endpoint_would_refuse_is_refused_when_pushed() {
    let smart = start("").await;
    for (overrides, error) in [
        (
            request(&[("request_uri", "urn:ietf:params:oauth:request_uri:x")]),
            "invalid_request",
        ),
        (
            request(&[("redirect_uri", "https://elsewhere.example.org/cb")]),
            "invalid_request",
        ),
        (
            request(&[("response_type", "token")]),
            "unsupported_response_type",
        ),
        (
            request(&[("code_challenge_method", "plain")]),
            "invalid_request",
        ),
        (request(&[("state", "")]), "invalid_request"),
        (request(&[("scope", "")]), "invalid_scope"),
        (request(&[("client_id", "")]), "invalid_client"),
        (request(&[("client_id", "unknown-app")]), "invalid_client"),
    ] {
        let (status, _, answer) = push(&smart, &overrides).await;
        assert_eq!(StatusCode::BAD_REQUEST, status, "{overrides:?}");
        assert_eq!(Some(error), answer["error"].as_str(), "{overrides:?}");
    }
    let (status, _, _) = smart.get("/par", None).await;
    assert_eq!(StatusCode::METHOD_NOT_ALLOWED, status, "RFC 9126 §2.3");
    smart.stop().await;
}

// NOTE: RFC 9126 §4 and §6, a client whose `require_pushed_authorization_requests`
// is true starts an authorization request by pushing it alone.
#[tokio::test]
async fn a_client_that_requires_par_is_refused_a_plain_request() {
    use sqlx::Connection as _;
    let smart = start("").await;
    let mut connection =
        sqlx::PgConnection::connect(secrecy::ExposeSecret::expose_secret(&smart.database.url))
            .await
            .expect("connects");
    sqlx::query(
        "UPDATE client SET require_pushed_authorization_requests = true WHERE client_id = 'app'",
    )
    .execute(&mut connection)
    .await
    .expect("required");
    let (status, headers, _) = smart.get(&authorize_path(&[]), None).await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let back = location(&headers);
    assert_eq!(Some(REDIRECT), back.as_str().split('?').next());
    assert_eq!(Some(String::from("invalid_request")), param(&back, "error"));
    let (_, _, answer) = push(&smart, &request(&[])).await;
    let request_uri = answer["request_uri"].as_str().expect("a request_uri");
    let (status, headers, _) = smart.get(&by_reference("app", request_uri), None).await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    assert!(
        location(&headers)
            .as_str()
            .starts_with(&smart.provider.server.uri()),
        "the pushed request is admitted"
    );
    smart.stop().await;
}

// NOTE: RFC 9126 §5, the metadata names the endpoint and whether every request
// arrives through it.
#[tokio::test]
async fn the_metadata_names_the_endpoint_and_the_servers_requirement() {
    for (settings, required) in [
        ("", false),
        ("require_pushed_authorization_requests = true\n", true),
    ] {
        let smart = start(settings).await;
        let path = smart.settings.metadata_path();
        for document in [path.as_str(), "/.well-known/openid-configuration"] {
            let (status, _, body) = smart.get(document, None).await;
            assert_eq!(StatusCode::OK, status, "{document}");
            let metadata: Value = serde_json::from_str(&body).expect("JSON");
            assert_eq!(
                json!(format!("{ISSUER}/par")),
                metadata["pushed_authorization_request_endpoint"],
                "{document}"
            );
            assert_eq!(
                json!(required),
                metadata["require_pushed_authorization_requests"],
                "{document}"
            );
        }
        if required {
            let (status, headers, _) = smart.get(&authorize_path(&[]), None).await;
            assert_eq!(StatusCode::SEE_OTHER, status);
            assert_eq!(
                Some(String::from("invalid_request")),
                param(&location(&headers), "error"),
                "a server that requires PAR refuses a plain request"
            );
        }
        smart.stop().await;
    }
}

// NOTE: RFC 9207 §3, a server whose authorization responses carry `iss` says so
// in its metadata.
#[tokio::test]
async fn the_metadata_says_every_authorization_response_carries_iss() {
    let smart = start("").await;
    let path = smart.settings.metadata_path();
    for document in [path.as_str(), "/.well-known/openid-configuration"] {
        let (_, _, body) = smart.get(document, None).await;
        let metadata: Value = serde_json::from_str(&body).expect("JSON");
        assert_eq!(
            json!(true),
            metadata["authorization_response_iss_parameter_supported"],
            "{document}"
        );
    }
    smart.stop().await;
}
