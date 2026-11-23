// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A client's `resources`, the bases its tokens may name in `aud`
//! (`docs/architecture.md` §13.6 item 12): an authorization or token
//! request naming another base is refused `invalid_target` (RFC 8707 §2),
//! read again on every request.

use ferrosmart::admin::AdminError;
use ferrosmart::store::grant::Access;
use http::{Method, StatusCode, header};
use serde_json::{Value, json};

use crate::introspection::{Answer, ISSUER, Server};
use crate::support::RESOURCE;

/// A second FHIR server the cases configure.
const OTHER: &str = "https://other.example.org/fhir";

/// Starts the shared server with [`OTHER`] beside [`RESOURCE`], every client
/// reaching both.
async fn two_servers() -> Server {
    Server::start_with(&format!(
        "[[ferrosmart.resource]]\nbase = {RESOURCE:?}\n[[ferrosmart.resource]]\nbase = {OTHER:?}\n"
    ))
    .await
}

/// Sets the `resources` of the client `client_id` to `resources` through
/// the admin API.
async fn narrow(server: &Server, client_id: &str, resources: &[&str]) {
    let token = server.token("admin", "system/admin", ISSUER).await;
    let (_, _, mut client) = server
        .call(
            Method::GET,
            &format!("/admin/clients/{client_id}"),
            None,
            Some(&token),
        )
        .await;
    if let Some(members) = client.as_object_mut() {
        for computed in ["registered_by", "disabled_at"] {
            members.remove(computed);
        }
        members.insert(String::from("resources"), json!(resources));
    }
    let (status, _, body) = server
        .call(
            Method::PUT,
            &format!("/admin/clients/{client_id}"),
            Some(&client),
            Some(&token),
        )
        .await;
    assert_eq!(StatusCode::OK, status, "{body}");
}

/// Asks the client credentials grant of `export` for `resource`.
async fn backend(server: &Server, resource: Option<&str>) -> Answer {
    let mut form = server.credentials("export");
    form.extend([
        (
            String::from("grant_type"),
            String::from("client_credentials"),
        ),
        (String::from("scope"), String::from("system/Patient.rs")),
    ]);
    if let Some(resource) = resource {
        form.push((String::from("resource"), resource.to_owned()));
    }
    server.post("/token", &form, None).await
}

/// Returns the `error` of a token endpoint answer.
fn error(answer: &Answer) -> Value {
    answer.2.get("error").cloned().unwrap_or(Value::Null)
}

#[tokio::test]
async fn a_backend_token_names_only_a_base_the_client_lists() {
    let server = two_servers().await;
    let answer = backend(&server, Some(OTHER)).await;
    assert_eq!(StatusCode::OK, answer.0, "{:?}", answer.2);
    narrow(&server, "export", &[RESOURCE]).await;
    assert_eq!(
        json!("invalid_target"),
        error(&backend(&server, Some(OTHER)).await),
        "a base taken off the list is refused on the next request"
    );
    let answer = backend(&server, Some(RESOURCE)).await;
    assert_eq!(StatusCode::OK, answer.0, "{:?}", answer.2);
    let answer = backend(&server, None).await;
    assert_eq!(
        StatusCode::OK,
        answer.0,
        "the one listed base is the default: {:?}",
        answer.2
    );
    assert_eq!(
        json!("invalid_target"),
        error(&backend(&server, Some("https://elsewhere.example.org/fhir")).await)
    );
    narrow(&server, "export", &[]).await;
    assert_eq!(
        json!("invalid_target"),
        error(&backend(&server, None).await)
    );
    server.stop().await;
}

#[tokio::test]
async fn an_authorization_request_names_only_a_base_the_client_lists() {
    let server = two_servers().await;
    let path = |aud: &str| {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("response_type", "code"),
                ("client_id", "app"),
                ("redirect_uri", "https://app.example.org/callback"),
                ("state", "synthetic-state"),
                (
                    "code_challenge",
                    "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                ),
                ("code_challenge_method", "S256"),
                ("scope", "openid"),
                ("aud", aud),
            ])
            .finish();
        format!("/authorize?{query}")
    };
    let refused = |headers: &http::HeaderMap| {
        headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|location| location.contains("error=invalid_target"))
    };
    let (_, headers, _) = server.call(Method::GET, &path(OTHER), None, None).await;
    assert!(!refused(&headers), "a listed base: {headers:?}");
    narrow(&server, "app", &[RESOURCE]).await;
    let (status, headers, _) = server.call(Method::GET, &path(OTHER), None, None).await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    assert!(refused(&headers), "RFC 8707 §2: {headers:?}");
    server.stop().await;
}

#[tokio::test]
async fn a_refresh_names_only_a_base_the_client_still_lists() {
    let server = two_servers().await;
    let grant = server
        .grant("app", Some(Access::Offline), None, &json!({}))
        .await;
    let token = server.refresh(&grant, 3600).await;
    narrow(&server, "app", &[OTHER]).await;
    let form = vec![
        (String::from("grant_type"), String::from("refresh_token")),
        (String::from("refresh_token"), token),
        (String::from("client_id"), String::from("app")),
    ];
    let answer = server.post("/token", &form, None).await;
    assert_eq!(json!("invalid_target"), error(&answer), "{:?}", answer.2);
    server.stop().await;
}

#[tokio::test]
async fn client_apply_refuses_a_base_or_a_provider_the_configuration_lacks() {
    let server = Server::start().await;
    let settings = server.settings();
    let state = ferrosmart::server::AppState::new(
        settings.clone(),
        server.store.clone(),
        crate::support::audit(settings),
    );
    let document = json!({
        "client_id": "app",
        "token_endpoint_auth_method": "none",
        "redirect_uris": ["https://app.example.org/callback"],
        "grant_types": ["authorization_code"],
        "resources": ["https://elsewhere.example.org/fhir"],
    });
    let apply = |document: Value| {
        let document = serde_json::from_value(document).expect("a client document");
        ferrosmart::admin::apply(&state, document)
    };
    assert!(matches!(
        apply(document.clone()).await,
        Err(AdminError::UnknownResource { client_id, base })
            if client_id == "app" && base == "https://elsewhere.example.org/fhir"
    ));
    let mut elsewhere = document;
    elsewhere["resources"] = json!([RESOURCE]);
    elsewhere["upstreams"] = json!(["elsewhere"]);
    assert!(matches!(
        apply(elsewhere).await,
        Err(AdminError::UnknownUpstream { client_id, name })
            if client_id == "app" && name == "elsewhere"
    ));
    server.stop().await;
}

#[tokio::test]
async fn the_admin_api_refuses_a_base_no_resource_table_configures() {
    let server = Server::start().await;
    let token = server.token("admin", "system/admin", ISSUER).await;
    let document = json!({
        "client_id": "elsewhere",
        "token_endpoint_auth_method": "none",
        "redirect_uris": ["https://elsewhere.example.org/callback"],
        "grant_types": ["authorization_code"],
        "resources": ["https://elsewhere.example.org/fhir"],
    });
    let (status, _, body) = server
        .call(
            Method::POST,
            "/admin/clients",
            Some(&document),
            Some(&token),
        )
        .await;
    assert_eq!(StatusCode::BAD_REQUEST, status);
    assert_eq!(json!("invalid_client_metadata"), body["error"]);
    server.stop().await;
}
