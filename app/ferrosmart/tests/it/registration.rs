// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Client registration (RFC 7591) and its management (RFC 7592) through the
//! whole stack against a real PostgreSQL: an administrator's registration,
//! an app's own one held to `[ferrosmart.registration]`, and the
//! configuration endpoint with the registration access token.

use http::{Method, StatusCode, header};
use serde_json::{Value, json};

use crate::introspection::{ISSUER, Server};
use crate::support::{RESOURCE, events, records};

/// The configuration of a deployment that lets apps register themselves.
const OPEN: &str = "[ferrosmart.registration]\nopen = true\n\
                    scope = \"openid fhirUser launch/patient patient/Observation.rs offline_access\"\n";

/// Returns an app's own registration request.
fn own_app() -> Value {
    json!({
        "client_name": "My health app",
        "token_endpoint_auth_method": "none",
        "redirect_uris": ["https://myhealth.example.org/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "scope": "openid patient/Observation.rs",
        "software_id": "an unknown member, ignored",
    })
}

/// Returns the `error` of `answer`, asserting its status.
fn refused(answer: &crate::introspection::Answer, status: StatusCode) -> String {
    assert_eq!(status, answer.0, "{:?}", answer.2);
    answer
        .2
        .get("error")
        .and_then(Value::as_str)
        .expect("an error code")
        .to_owned()
}

// NOTE: RFC 8414 §2 and OpenID Connect Discovery 1.0 §3, registration_endpoint.
#[tokio::test]
async fn the_metadata_names_the_registration_endpoint() {
    let server = Server::start().await;
    let (status, _, body) = server
        .call(
            Method::GET,
            "/.well-known/oauth-authorization-server",
            None,
            None,
        )
        .await;
    assert_eq!(StatusCode::OK, status);
    assert_eq!(
        json!(format!("{ISSUER}/register")),
        body["registration_endpoint"]
    );
    server.stop().await;
}

// NOTE: RFC 7591 §3, an initial access token may be required: without
// `[ferrosmart.registration] open` it is.
#[tokio::test]
async fn a_closed_registration_answers_only_an_administrator() {
    let server = Server::start().await;
    let answer = server
        .call(Method::POST, "/register", Some(&own_app()), None)
        .await;
    assert_eq!("invalid_token", refused(&answer, StatusCode::UNAUTHORIZED));
    assert!(answer.1.get(header::WWW_AUTHENTICATE).is_some());
    let not_admin = server.token("export", "system/Patient.rs", RESOURCE).await;
    let answer = server
        .call(
            Method::POST,
            "/register",
            Some(&own_app()),
            Some(&not_admin),
        )
        .await;
    assert_eq!("invalid_token", refused(&answer, StatusCode::UNAUTHORIZED));
    server.stop().await;
}

// NOTE: RFC 7591 §3.2.1, the server issues client_id and answers the metadata;
// §2, a member it does not understand is ignored; RFC 7592 §3, the token.
#[tokio::test]
async fn an_app_registers_itself_within_the_open_scope_and_manages_itself() {
    let server = Server::start_with(OPEN).await;
    let (status, _, created) = server
        .call(Method::POST, "/register", Some(&own_app()), None)
        .await;
    assert_eq!(StatusCode::CREATED, status, "{created}");
    let client_id = created["client_id"]
        .as_str()
        .expect("a client_id")
        .to_owned();
    let token = created["registration_access_token"]
        .as_str()
        .expect("a registration access token")
        .to_owned();
    assert_eq!(json!("self"), created["registered_by"]);
    assert_eq!(json!([RESOURCE]), created["resources"]);
    assert_eq!(
        json!(format!("{ISSUER}/register/{client_id}")),
        created["registration_client_uri"]
    );
    assert!(created["client_id_issued_at"].is_i64());
    assert!(created.get("software_id").is_none(), "{created}");
    let stored = server
        .store
        .client(&client_id)
        .await
        .expect("reads")
        .expect("registered");
    assert!(stored.registered_itself());

    let path = format!("/register/{client_id}");
    let (status, _, read) = server.call(Method::GET, &path, None, Some(&token)).await;
    assert_eq!(StatusCode::OK, status, "{read}");
    assert_eq!(json!("My health app"), read["client_name"]);
    let mut changed = own_app();
    changed["client_id"] = json!(client_id);
    changed["client_name"] = json!("My health app, renamed");
    let (status, _, updated) = server
        .call(Method::PUT, &path, Some(&changed), Some(&token))
        .await;
    assert_eq!(StatusCode::OK, status, "{updated}");
    assert_eq!(json!("My health app, renamed"), updated["client_name"]);
    changed["scope"] = json!("openid user/Observation.rs");
    let answer = server
        .call(Method::PUT, &path, Some(&changed), Some(&token))
        .await;
    assert_eq!(
        "invalid_client_metadata",
        refused(&answer, StatusCode::BAD_REQUEST)
    );
    let answer = server
        .call(Method::GET, &path, None, Some("not-the-token"))
        .await;
    assert_eq!("invalid_token", refused(&answer, StatusCode::UNAUTHORIZED));

    // NOTE: RFC 7592 §2.3, a deleted client is gone and its token with it.
    let (status, _, _) = server.call(Method::DELETE, &path, None, Some(&token)).await;
    assert_eq!(StatusCode::NO_CONTENT, status);
    assert!(
        server
            .store
            .client(&client_id)
            .await
            .expect("reads")
            .is_none()
    );
    let answer = server.call(Method::GET, &path, None, Some(&token)).await;
    assert_eq!("invalid_token", refused(&answer, StatusCode::UNAUTHORIZED));
    let kept = records(&server.store).await;
    for event in ["client-created", "client-updated", "client-deleted"] {
        assert!(events(&kept).contains(&String::from(event)), "{event}");
    }
    server.stop().await;
}

// NOTE: RFC 7591 §5, an app's metadata is self-asserted: the scope stays within
// the open ceiling, and the members an administrator sets are refused.
#[tokio::test]
async fn an_app_is_refused_a_wider_scope_or_an_administrator_s_member() {
    let server = Server::start_with(OPEN).await;
    let mut wide = own_app();
    wide["scope"] = json!("openid user/Observation.rs");
    let answer = server
        .call(Method::POST, "/register", Some(&wide), None)
        .await;
    assert_eq!(
        "invalid_client_metadata",
        refused(&answer, StatusCode::BAD_REQUEST)
    );
    for (member, value) in [
        ("first_party", json!(true)),
        ("resources", json!([RESOURCE])),
        ("launch_uri", json!("https://myhealth.example.org/launch")),
        ("upstreams", json!(["idp"])),
    ] {
        let mut asked = own_app();
        asked[member] = value;
        let answer = server
            .call(Method::POST, "/register", Some(&asked), None)
            .await;
        assert_eq!(
            "invalid_client_metadata",
            refused(&answer, StatusCode::BAD_REQUEST),
            "{member}"
        );
    }
    let mut unscoped = own_app();
    unscoped["scope"] = json!("");
    let (status, _, created) = server
        .call(Method::POST, "/register", Some(&unscoped), None)
        .await;
    assert_eq!(StatusCode::CREATED, status, "{created}");
    assert_eq!(
        json!("openid fhirUser launch/patient patient/Observation.rs offline_access"),
        created["scope"],
        "no scope asked takes the open ceiling"
    );
    server.stop().await;
}

// NOTE: RFC 7591 §2, an omitted token_endpoint_auth_method is client_secret_basic
// and §3.2.1, the secret is answered once with client_secret_expires_at.
#[tokio::test]
async fn an_administrator_registers_with_the_rfc_7591_defaults() {
    let server = Server::start().await;
    let token = server.token("admin", "system/admin", ISSUER).await;
    let document = json!({
        "client_id": "patient-portal",
        "client_name": "Patient portal",
        "redirect_uris": ["https://portal.example.org/callback"],
        "resources": [RESOURCE],
        "first_party": true,
    });
    let (status, _, created) = server
        .call(Method::POST, "/register", Some(&document), Some(&token))
        .await;
    assert_eq!(StatusCode::CREATED, status, "{created}");
    assert_eq!(
        json!("client_secret_basic"),
        created["token_endpoint_auth_method"]
    );
    assert_eq!(json!(["authorization_code"]), created["grant_types"]);
    assert!(created["client_secret"].is_string());
    assert_eq!(json!(0), created["client_secret_expires_at"]);
    assert!(
        created.get("registration_access_token").is_none(),
        "an administrator manages it with its own token"
    );
    assert_eq!(json!(true), created["first_party"]);
    server.stop().await;
}
