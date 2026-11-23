// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A refused key set, introspection or metadata answer keeps its status, and
//! for introspection the RFC 6749 §5.2 error code, and nothing else of the
//! body: a marker planted in the body never appears in the error's chain.

use std::error::Error as StdError;
use std::time::Duration;

use ferrohealth_smart::client::ClientCredentials;
use ferrohealth_smart::client::Endpoint;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::metadata::DiscoveryError;
use ferrohealth_smart::metadata::Http;
use ferrohealth_smart::resource::Rejection;
use ferrohealth_smart::resource::ResourceError;
use ferrohealth_smart::resource::ResourceServer;
use ferrohealth_smart::resource::introspection::IntrospectionAuth;
use ferrohealth_smart::resource::introspection::IntrospectionError;
use ferrohealth_smart::resource::introspection::IntrospectionSettings;
use ferrohealth_smart::resource::introspection::Introspector;
use http::StatusCode;
use secrecy::SecretString;
use wiremock::Mock;
use wiremock::ResponseTemplate;
use wiremock::matchers::method;
use wiremock::matchers::path;

use crate::support::AUDIENCE;
use crate::support::Issuer;
use crate::support::JWKS_PATH;

type TestResult = Result<(), Box<dyn StdError>>;

/// A secret-looking marker no refusal may render.
const MARKER: &str = "c2VjcmV0LXVwc3RyZWFtLWJvZHk";

/// A refusal body that carries the marker beside an OAuth error.
fn body() -> serde_json::Value {
    serde_json::json!({
        "error": "invalid_client",
        "error_description": MARKER,
        "access_token": MARKER,
        "private_key": MARKER,
    })
}

/// Returns every `Display` and `Debug` rendering of `error`'s source chain.
fn rendered(error: &(dyn StdError + 'static)) -> String {
    let mut text = Vec::new();
    let mut next = Some(error);
    while let Some(error) = next {
        text.push(format!("{error}\n{error:?}"));
        next = error.source();
    }
    text.join("\n")
}

#[tokio::test]
async fn a_refused_key_set_keeps_no_part_of_its_body() -> TestResult {
    let issuer = Issuer::bare().await;
    issuer
        .mount_metadata("/.well-known/oauth-authorization-server")
        .await;
    Mock::given(method("GET"))
        .and(path(JWKS_PATH))
        .respond_with(ResponseTemplate::new(500).set_body_json(body()))
        .mount(&issuer.server)
        .await;
    let error = ResourceServer::discover(issuer.settings())
        .await
        .expect_err("the key set is refused");
    let ResourceError::KeySetStatus { status, body, .. } = &error else {
        return Err(format!("{error:?}").into());
    };
    assert_eq!(StatusCode::INTERNAL_SERVER_ERROR, *status);
    assert!(body.is_empty(), "RFC 7517 defines no error body");
    let text = rendered(&error);
    assert!(text.contains("500"), "{text}");
    assert!(!text.contains(MARKER), "{text}");
    Ok(())
}

#[tokio::test]
async fn a_refused_introspection_keeps_its_status_and_error_code_only() -> TestResult {
    let issuer = Issuer::bare().await;
    issuer
        .mount_metadata("/.well-known/oauth-authorization-server")
        .await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(401).set_body_json(body()))
        .mount(&issuer.server)
        .await;
    let auth = IntrospectionAuth::Client(Box::new(ClientCredentials::new(
        Endpoint::Issuer(issuer.uri()),
        String::from("ferro-rs"),
        SecretString::from("synthetic-secret"),
    )));
    let settings = IntrospectionSettings::new(issuer.uri(), AUDIENCE, auth, IssuerKind::Smart);
    let introspector = Introspector::discover(settings).await?;
    let outcome = introspector.authenticate("synthetic-opaque-token").await;
    let Err(Rejection::Upstream { source, .. }) = outcome else {
        return Err(format!("an upstream failure, got {outcome:?}").into());
    };
    let error = source
        .downcast_ref::<IntrospectionError>()
        .ok_or("an introspection error")?;
    let IntrospectionError::Status { status, body, .. } = error else {
        return Err(format!("{error:?}").into());
    };
    assert_eq!(StatusCode::UNAUTHORIZED, *status);
    assert_eq!("invalid_client", body, "RFC 6749 §5.2");
    let text = rendered(error);
    assert!(text.contains("invalid_client"), "{text}");
    assert!(!text.contains(MARKER), "{text}");
    Ok(())
}

#[tokio::test]
async fn an_introspection_error_code_outside_the_rfc_6749_set_is_dropped() -> TestResult {
    let issuer = Issuer::bare().await;
    issuer
        .mount_metadata("/.well-known/oauth-authorization-server")
        .await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(serde_json::json!({ "error": format!("bad\"{MARKER}\n") })),
        )
        .mount(&issuer.server)
        .await;
    let auth = IntrospectionAuth::Client(Box::new(ClientCredentials::new(
        Endpoint::Issuer(issuer.uri()),
        String::from("ferro-rs"),
        SecretString::from("synthetic-secret"),
    )));
    let settings = IntrospectionSettings::new(issuer.uri(), AUDIENCE, auth, IssuerKind::Smart);
    let introspector = Introspector::discover(settings).await?;
    let outcome = introspector.authenticate("synthetic-opaque-token").await;
    let Err(Rejection::Upstream { source, .. }) = outcome else {
        return Err(format!("an upstream failure, got {outcome:?}").into());
    };
    let error = source
        .downcast_ref::<IntrospectionError>()
        .ok_or("an introspection error")?;
    assert!(
        matches!(error, IntrospectionError::Status { body, .. } if body.is_empty()),
        "{error:?}"
    );
    assert!(!rendered(error).contains(MARKER));
    Ok(())
}

#[tokio::test]
async fn a_refused_metadata_document_keeps_no_part_of_its_body() -> TestResult {
    let issuer = Issuer::bare().await;
    for location in [
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
    ] {
        Mock::given(method("GET"))
            .and(path(location))
            .respond_with(ResponseTemplate::new(404).set_body_json(body()))
            .mount(&issuer.server)
            .await;
    }
    let error = Http::new(Duration::from_secs(5))?
        .discover(&issuer.uri())
        .await
        .expect_err("no metadata answers");
    let DiscoveryError::Status { status, body, .. } = &error else {
        return Err(format!("{error:?}").into());
    };
    assert_eq!(StatusCode::NOT_FOUND, *status);
    assert!(body.is_empty(), "RFC 8414 §3.2 defines no error body");
    let text = rendered(&error);
    assert!(!text.contains(MARKER), "{text}");
    Ok(())
}
