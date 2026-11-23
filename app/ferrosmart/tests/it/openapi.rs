// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The OpenAPI document of the administration API (#824): served without a
//! token for the deployment's issuer, naming exactly the operations the
//! router serves, and each answer held to its schema.

use std::collections::BTreeSet;

use http::{Method, StatusCode};
use serde_json::{Value, json};

use crate::introspection::{Answer, ISSUER, Server};

/// The configuration of a deployment that lets apps register themselves.
const OPEN: &str = "[ferrosmart.registration]\nopen = true\n\
                    scope = \"openid launch/patient patient/Observation.rs\"\n";

/// Returns the document the server answers, asserting it answers without
/// a token.
pub(crate) async fn served(server: &Server) -> Value {
    let (status, headers, body) = server
        .call(Method::GET, "/admin/openapi.json", None, None)
        .await;
    assert_eq!(
        StatusCode::OK,
        status,
        "the document answers without a token"
    );
    assert_eq!(
        Some("application/json"),
        headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        "the document is JSON"
    );
    body
}

/// Returns every operation `document` names, as method and path.
fn documented(document: &Value) -> BTreeSet<(String, String)> {
    let paths = document["paths"].as_object().expect("paths");
    paths
        .iter()
        .flat_map(|(path, item)| {
            item.as_object()
                .expect("a path item")
                .keys()
                .filter(|key| *key != "parameters")
                .map(|method| (method.to_ascii_uppercase(), path.clone()))
        })
        .collect()
}

/// Returns `template` with each `{name}` filled in.
fn filled(template: &str) -> String {
    template.replace("{client_id}", "nobody")
}

#[tokio::test]
async fn the_document_answers_for_the_deployment_without_a_token() {
    let server = Server::start().await;
    let document = served(&server).await;
    assert_eq!(json!("3.1.0"), document["openapi"]);
    assert_eq!(
        json!(env!("CARGO_PKG_VERSION")),
        document["info"]["version"]
    );
    assert_eq!(
        json!([{ "url": ISSUER, "description": "The issuer." }]),
        document["servers"]
    );
    assert_eq!(
        json!(format!("{ISSUER}/token")),
        document["components"]["securitySchemes"]["admin"]["flows"]["clientCredentials"]["tokenUrl"]
    );
    assert!(
        !document.to_string().contains("issuer.invalid"),
        "every placeholder is filled in"
    );
    server.stop().await;
}

#[tokio::test]
async fn the_document_names_exactly_the_operations_the_router_serves() {
    let server = Server::start().await;
    let document = served(&server).await;
    let routed: BTreeSet<(String, String)> = ferrosmart::admin::openapi::operations()
        .into_iter()
        .map(|(method, path)| (method.as_str().to_owned(), path.to_owned()))
        .collect();
    let named = documented(&document);
    assert_eq!(
        routed.difference(&named).collect::<Vec<_>>(),
        Vec::<&(String, String)>::new(),
        "every routed operation is in the document"
    );
    assert_eq!(
        named.difference(&routed).collect::<Vec<_>>(),
        Vec::<&(String, String)>::new(),
        "the document names no operation the router lacks"
    );
    for (method, path) in &named {
        let method = Method::from_bytes(method.as_bytes()).expect("a method");
        let (status, _, _) = server.call(method.clone(), &filled(path), None, None).await;
        assert!(
            status != StatusCode::NOT_FOUND && status != StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path} answers {status}, so the router serves no such operation"
        );
    }
    server.stop().await;
}

/// Asserts `answer` holds to the schema `document` gives `method` `path`
/// for its status and `media` type.
pub(crate) fn holds(document: &Value, method: &str, path: &str, media: &str, answer: &Answer) {
    let status = answer.0.as_str();
    let escaped = path.replace('~', "~0").replace('/', "~1");
    let mut response = document
        .pointer(&format!("/paths/{escaped}/{method}/responses/{status}"))
        .cloned()
        .unwrap_or_default();
    if let Some(reference) = response.get("$ref").and_then(Value::as_str) {
        let pointer = reference.trim_start_matches('#');
        response = document.pointer(pointer).expect("the response").clone();
    }
    let media = media.replace('~', "~0").replace('/', "~1");
    let schema = response
        .pointer(&format!("/content/{media}/schema"))
        .cloned()
        .unwrap_or_default();
    assert!(
        schema.is_object(),
        "{method} {path} documents a {media} answer for {status}"
    );
    let mut root = document.clone();
    if let Some(members) = root.as_object_mut() {
        members.insert(String::from("$ref"), Value::from("#/$defs/answer"));
        members.insert(String::from("$defs"), json!({ "answer": schema }));
    }
    let validator = jsonschema::draft202012::options()
        .build(&root)
        .expect("the schema compiles");
    let errors: Vec<String> = validator
        .iter_errors(&answer.2)
        .map(|error| format!("{} at {}", error, error.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "{method} {path} {status}: {errors:?} in {}",
        answer.2
    );
}

/// The answers' media type, but the audit records'.
const JSON: &str = "application/json";

/// Returns an app's own registration request.
fn own_app() -> Value {
    json!({
        "client_name": "My health app",
        "token_endpoint_auth_method": "none",
        "redirect_uris": ["https://myhealth.example.org/callback"],
        "grant_types": ["authorization_code"],
        "scope": "openid patient/Observation.rs",
    })
}

#[tokio::test]
async fn each_registration_answer_holds_to_its_schema() {
    let server = Server::start_with(OPEN).await;
    let document = served(&server).await;
    let admin = server.token("admin", "system/admin", ISSUER).await;
    let created = server
        .call(Method::POST, "/register", Some(&own_app()), None)
        .await;
    assert_eq!(StatusCode::CREATED, created.0, "{}", created.2);
    holds(&document, "post", "/register", JSON, &created);
    let client_id = created.2["client_id"].as_str().expect("an id").to_owned();
    let own = created.2["registration_access_token"]
        .as_str()
        .expect("a registration access token")
        .to_owned();
    let configuration = format!("/register/{client_id}");
    let read = server
        .call(Method::GET, &configuration, None, Some(&own))
        .await;
    assert_eq!(StatusCode::OK, read.0, "{}", read.2);
    holds(&document, "get", "/register/{client_id}", JSON, &read);
    let mut changed = own_app();
    changed["client_id"] = Value::from(client_id.as_str());
    changed["client_name"] = Value::from("My renamed health app");
    let updated = server
        .call(Method::PUT, &configuration, Some(&changed), Some(&own))
        .await;
    assert_eq!(StatusCode::OK, updated.0, "{}", updated.2);
    holds(&document, "put", "/register/{client_id}", JSON, &updated);
    let symmetric = json!({
        "client_name": "Ward app",
        "token_endpoint_auth_method": "client_secret_basic",
        "redirect_uris": ["https://ward.example.org/callback"],
        "grant_types": ["authorization_code"],
        "scope": "openid user/Observation.rs",
    });
    let issued = server
        .call(Method::POST, "/register", Some(&symmetric), Some(&admin))
        .await;
    assert_eq!(StatusCode::CREATED, issued.0, "{}", issued.2);
    assert!(issued.2["client_secret"].is_string(), "the secret, once");
    holds(&document, "post", "/register", JSON, &issued);
    let refused = server
        .call(Method::POST, "/register", Some(&json!(["no object"])), None)
        .await;
    assert_eq!(StatusCode::BAD_REQUEST, refused.0, "{}", refused.2);
    holds(&document, "post", "/register", JSON, &refused);
    let removed = server
        .call(Method::DELETE, &configuration, None, Some(&own))
        .await;
    assert_eq!(StatusCode::NO_CONTENT, removed.0, "{}", removed.2);
    assert!(
        document["paths"]["/register/{client_id}"]["delete"]["responses"]["204"]
            .get("content")
            .is_none(),
        "a deletion answers no body"
    );
    server.stop().await;
}

#[tokio::test]
async fn each_registry_answer_holds_to_its_schema() {
    let server = Server::start().await;
    let document = served(&server).await;
    let admin = server.token("admin", "system/admin", ISSUER).await;
    let list = server
        .call(Method::GET, "/admin/clients", None, Some(&admin))
        .await;
    assert_eq!(StatusCode::OK, list.0, "{}", list.2);
    holds(&document, "get", "/admin/clients", JSON, &list);
    let unauthorized = server.call(Method::GET, "/admin/clients", None, None).await;
    holds(&document, "get", "/admin/clients", JSON, &unauthorized);
    let reader = server.token("rs", "system/introspect", ISSUER).await;
    let forbidden = server
        .call(Method::GET, "/admin/clients", None, Some(&reader))
        .await;
    holds(&document, "get", "/admin/clients", JSON, &forbidden);
    let disable = "/admin/clients/app/disable";
    let disabled = server.call(Method::POST, disable, None, Some(&admin)).await;
    assert_eq!(StatusCode::OK, disabled.0, "{}", disabled.2);
    holds(
        &document,
        "post",
        "/admin/clients/{client_id}/disable",
        JSON,
        &disabled,
    );
    let again = server.call(Method::POST, disable, None, Some(&admin)).await;
    assert_eq!(StatusCode::CONFLICT, again.0, "{}", again.2);
    holds(
        &document,
        "post",
        "/admin/clients/{client_id}/disable",
        JSON,
        &again,
    );
    let enabled = server
        .call(
            Method::POST,
            "/admin/clients/app/enable",
            None,
            Some(&admin),
        )
        .await;
    assert_eq!(StatusCode::OK, enabled.0, "{}", enabled.2);
    holds(
        &document,
        "post",
        "/admin/clients/{client_id}/enable",
        JSON,
        &enabled,
    );
    let unknown = server
        .call(
            Method::POST,
            "/admin/clients/nobody/enable",
            None,
            Some(&admin),
        )
        .await;
    assert_eq!(StatusCode::NOT_FOUND, unknown.0, "{}", unknown.2);
    holds(
        &document,
        "post",
        "/admin/clients/{client_id}/enable",
        JSON,
        &unknown,
    );
    let keys = server
        .call(Method::GET, "/admin/keys", None, Some(&admin))
        .await;
    assert_eq!(StatusCode::OK, keys.0, "{}", keys.2);
    holds(&document, "get", "/admin/keys", JSON, &keys);
    server.stop().await;
}

#[tokio::test]
async fn the_audit_answer_holds_to_its_schema() {
    let server = Server::start().await;
    let document = served(&server).await;
    let admin = server.token("admin", "system/admin", ISSUER).await;
    let (_, _, listed) = server
        .call(Method::GET, "/admin/clients", None, Some(&admin))
        .await;
    let export = listed["clients"]
        .as_array()
        .and_then(|clients| {
            clients
                .iter()
                .find(|client| client["client_id"] == "export")
        })
        .expect("the export client");
    let reader_of_records = json!({
        "client_id": "auditor",
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks": export["jwks"],
        "scope": "system/AuditEvent.rs",
        "grant_types": ["client_credentials"],
    });
    let registered = server
        .call(
            Method::POST,
            "/register",
            Some(&reader_of_records),
            Some(&admin),
        )
        .await;
    assert_eq!(StatusCode::CREATED, registered.0, "{}", registered.2);
    let auditor = server
        .token("auditor", "system/AuditEvent.rs", ISSUER)
        .await;
    let records = server
        .call(Method::GET, "/audit?_count=5", None, Some(&auditor))
        .await;
    assert_eq!(StatusCode::OK, records.0, "{}", records.2);
    assert!(
        records.2["entry"]
            .as_array()
            .is_some_and(|entry| !entry.is_empty()),
        "the registration above is recorded"
    );
    holds(
        &document,
        "get",
        "/audit",
        "application/fhir+json",
        &records,
    );
    server.stop().await;
}
