// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The discovery routes, read back through the whole stack.

use std::sync::Arc;

use axum::body::Body;
use ferrosmart::server::{AppState, JWKS_CACHE_CONTROL, router};
use ferrosmart::store::Store;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use crate::support::{Keys, audit, config, rsa_key};

/// Answers `GET path` on the server `text` configures over `keys`, with the
/// status, the headers and the JSON body.
async fn get(text: &str, keys: &Keys, path: &str) -> (StatusCode, http::HeaderMap, Value) {
    let settings = config(text, keys).resolve().expect("resolves");
    let store = Store::connect_lazy(&settings.database_url, 1).expect("the URL parses");
    let audit = audit(&settings);
    let app = router(Arc::new(AppState::new(settings, store, audit)));
    let request = Request::get(path)
        .header(header::ACCEPT, "text/html")
        .body(Body::empty())
        .expect("a request");
    let response = app.oneshot(request).await.expect("an answer");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("the body")
        .to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, body)
}

const ROOT: &str = "[ferrosmart]\nissuer = \"https://smart.example.org\"";

#[tokio::test]
async fn the_rfc_8414_metadata_names_the_issuer_and_only_what_is_supported() {
    let keys = Keys::new();
    let (status, headers, body) = get(ROOT, &keys, "/.well-known/oauth-authorization-server").await;
    assert_eq!(StatusCode::OK, status);
    assert_eq!(
        Some("*"),
        headers
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok())
    );
    // NOTE: RFC 8414 §2 and §3.3, the issuer identical to the configured one.
    assert_eq!(json!("https://smart.example.org"), body["issuer"]);
    assert_eq!(
        json!("https://smart.example.org/token"),
        body["token_endpoint"]
    );
    assert_eq!(json!("https://smart.example.org/jwks"), body["jwks_uri"]);
    assert_eq!(
        json!(["client_credentials", "refresh_token"]),
        body["grant_types_supported"]
    );
    assert_eq!(
        json!(["private_key_jwt"]),
        body["token_endpoint_auth_methods_supported"]
    );
    assert_eq!(
        json!(["RS384", "ES384", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]),
        body["token_endpoint_auth_signing_alg_values_supported"]
    );
    // NOTE: RFC 8414 §2, REQUIRED; no authorization endpoint lists no type yet.
    assert_eq!(json!([]), body["response_types_supported"]);
    assert_eq!(Value::Null, body["authorization_endpoint"]);
    assert_eq!(
        Value::Null,
        body["launch_registration_endpoint"],
        "no app launch, so no launch to register"
    );
}

#[tokio::test]
async fn the_metadata_names_introspection_and_revocation_and_how_they_authenticate() {
    let keys = Keys::new();
    let (_, _, body) = get(ROOT, &keys, "/.well-known/oauth-authorization-server").await;
    assert_eq!(
        json!("https://smart.example.org/introspect"),
        body["introspection_endpoint"]
    );
    assert_eq!(
        json!("https://smart.example.org/revoke"),
        body["revocation_endpoint"]
    );
    // NOTE: RFC 8414 §2, absent auth methods would mean client_secret_basic.
    assert_eq!(
        json!([
            "private_key_jwt",
            "client_secret_basic",
            "client_secret_post"
        ]),
        body["introspection_endpoint_auth_methods_supported"]
    );
    assert_eq!(
        json!(["RS384", "ES384", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]),
        body["introspection_endpoint_auth_signing_alg_values_supported"]
    );
    assert_eq!(
        json!([
            "private_key_jwt",
            "client_secret_basic",
            "client_secret_post",
            "none"
        ]),
        body["revocation_endpoint_auth_methods_supported"]
    );
    assert_eq!(
        json!(["RS384", "ES384", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]),
        body["revocation_endpoint_auth_signing_alg_values_supported"]
    );
    // NOTE: SMART App Launch 2.2.0, Conformance, Metadata: both RECOMMENDED.
    let (_, _, smart) = get(ROOT, &keys, "/.well-known/smart-configuration").await;
    assert_eq!(
        body["introspection_endpoint"],
        smart["introspection_endpoint"]
    );
    assert_eq!(body["revocation_endpoint"], smart["revocation_endpoint"]);
}

#[tokio::test]
async fn the_smart_configuration_is_json_whatever_the_accept_header() {
    let keys = Keys::new();
    let (status, headers, body) = get(ROOT, &keys, "/.well-known/smart-configuration").await;
    assert_eq!(StatusCode::OK, status);
    // NOTE: SMART App Launch 2.2.0, Conformance, Using well-known.
    assert_eq!(
        Some("application/json"),
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
    );
    assert_eq!(
        Some("*"),
        headers
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok())
    );
    assert_eq!(
        json!("https://smart.example.org/token"),
        body["token_endpoint"]
    );
    assert_eq!(json!(["client_credentials"]), body["grant_types_supported"]);
    assert_eq!(json!(["S256"]), body["code_challenge_methods_supported"]);
    assert_eq!(
        json!(["client-confidential-asymmetric"]),
        body["capabilities"]
    );
    assert_eq!(
        json!(["private_key_jwt"]),
        body["token_endpoint_auth_methods_supported"]
    );
    assert_eq!(
        json!(["RS384", "ES384", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]),
        body["token_endpoint_auth_signing_alg_values_supported"]
    );
    assert_eq!(Value::Null, body["authorization_endpoint"]);
    assert_eq!(
        Value::Null,
        body["launch_registration_endpoint"],
        "no app launch, so no launch to register"
    );
}

#[tokio::test]
async fn the_jwk_set_publishes_bare_rs256_keys_and_may_be_cached() {
    let keys = Keys::new();
    let next = rsa_key(keys.dir.path(), "next.pem");
    let text = format!(
        "{ROOT}\n[ferrosmart.keys]\nprivate_key_files = [{:?}, {:?}]",
        keys.current.display().to_string(),
        next.display().to_string()
    );
    let (status, headers, body) = get(&text, &keys, "/jwks").await;
    assert_eq!(StatusCode::OK, status);
    assert_eq!(
        Some(JWKS_CACHE_CONTROL),
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
    );
    let published = body["keys"].as_array().expect("keys");
    assert_eq!(
        1,
        published.len(),
        "the first key until the store names the ring"
    );
    for key in published {
        // NOTE: SMART App Launch 2.2.0, bare JWK keys; RFC 9068 §2.1, RS256.
        assert_eq!(json!("RSA"), key["kty"]);
        assert_eq!(json!("RS256"), key["alg"]);
        assert_eq!(json!("sig"), key["use"]);
        assert!(key["n"].is_string() && key["e"].is_string());
        assert_eq!(Value::Null, key["d"], "never the private half");
    }
}

#[tokio::test]
async fn under_an_issuer_path_the_metadata_sits_beside_it() {
    let keys = Keys::new();
    let text =
        "[server]\nbase_path = \"/smart\"\n[ferrosmart]\nissuer = \"https://example.org/smart\"";
    let (status, _, body) = get(text, &keys, "/.well-known/oauth-authorization-server/smart").await;
    assert_eq!(StatusCode::OK, status);
    assert_eq!(json!("https://example.org/smart"), body["issuer"]);
    let (status, _, body) = get(text, &keys, "/smart/.well-known/smart-configuration").await;
    assert_eq!(StatusCode::OK, status);
    assert_eq!(
        json!("https://example.org/smart/token"),
        body["token_endpoint"]
    );
    let (status, _, _) = get(text, &keys, "/smart/jwks").await;
    assert_eq!(StatusCode::OK, status);
}

#[tokio::test]
async fn the_health_routes_are_served() {
    let keys = Keys::new();
    let (status, _, _) = get(ROOT, &keys, "/health/liveness").await;
    assert_eq!(StatusCode::OK, status);
}
