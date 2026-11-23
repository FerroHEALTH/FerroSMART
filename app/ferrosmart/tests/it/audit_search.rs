// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The audit search by client, event and outcome with its `next` link
//! (FHIR R4 Bundle.link), and a confidential symmetric client's new secret
//! through the admin API (#832).

use std::collections::BTreeSet;

use base64::Engine as _;
use http::{Method, StatusCode};
use serde_json::{Value, json};

use crate::introspection::{GATEWAY_SECRET, ISSUER, Server};
use crate::support::{RESOURCE, events, records};

/// Returns the search `query` answers, with the auditor's `token`.
async fn search(server: &Server, query: &str, token: &str) -> (StatusCode, Value) {
    let (status, _, body) = server
        .call(Method::GET, &format!("/audit?{query}"), None, Some(token))
        .await;
    (status, body)
}

/// Returns the `url` of the link `relation` of `bundle`.
fn link<'a>(bundle: &'a Value, relation: &str) -> Option<&'a str> {
    bundle["link"]
        .as_array()?
        .iter()
        .find(|link| link["relation"] == relation)?["url"]
        .as_str()
}

/// Returns the `AuditEvent`s of `bundle`.
fn ids(bundle: &Value) -> Vec<Value> {
    bundle["entry"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|entry| entry["resource"].clone())
        .collect()
}

/// Returns a server with an `auditor` client registered through the admin
/// API, and its token.
async fn audited() -> (Server, String, String) {
    let server = Server::start().await;
    let admin = server.token("admin", "system/admin", ISSUER).await;
    let (_, _, listed) = server
        .call(Method::GET, "/admin/clients", None, Some(&admin))
        .await;
    let export = listed
        .get("clients")
        .and_then(Value::as_array)
        .and_then(|clients| {
            clients
                .iter()
                .find(|client| client["client_id"] == "export")
        })
        .expect("the export client");
    let auditor = json!({
        "client_id": "auditor",
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks": export.get("jwks"),
        "scope": "system/AuditEvent.rs",
        "grant_types": ["client_credentials"],
    });
    let (status, _, body) = server
        .call(Method::POST, "/register", Some(&auditor), Some(&admin))
        .await;
    assert_eq!(StatusCode::CREATED, status, "{body}");
    let token = server
        .token("auditor", "system/AuditEvent.rs", ISSUER)
        .await;
    (server, admin, token)
}

#[tokio::test]
async fn the_search_filters_by_client_event_and_outcome() {
    let (server, _admin, token) = audited().await;
    for _ in 0..3 {
        server.token("export", "system/Patient.rs", RESOURCE).await;
    }
    let (status, body) = search(&server, "client=export", &token).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let found = body["entry"].as_array().expect("entries");
    assert_eq!(3, found.len(), "{body}");
    assert!(
        found
            .iter()
            .all(|entry| entry.to_string().contains("export")),
        "every record names the client"
    );
    let (_, body) = search(&server, "client=export&event=token&outcome=0", &token).await;
    assert_eq!(3, body["entry"].as_array().map_or(0, Vec::len));
    let (_, body) = search(&server, "client=export&outcome=8", &token).await;
    assert_eq!(json!([]), body["entry"]);
    let (_, body) = search(&server, "event=client-created&client=admin", &token).await;
    assert_eq!(
        1,
        body["entry"].as_array().map_or(0, Vec::len),
        "the auditor's registration by the admin client"
    );
    for query in [
        "outcome=5",
        "cursor=nonsense",
        "cursor=1",
        "client=a&client=b",
    ] {
        let (status, _) = search(&server, query, &token).await;
        assert_eq!(StatusCode::BAD_REQUEST, status, "{query}");
    }
    server.stop().await;
}

#[tokio::test]
async fn the_next_link_reads_every_record_once() {
    let (server, _admin, token) = audited().await;
    for _ in 0..4 {
        server.token("export", "system/Patient.rs", RESOURCE).await;
    }
    let (_, whole) = search(&server, "_count=1000", &token).await;
    let every = ids(&whole);
    assert!(every.len() >= 7, "{}", every.len());
    assert!(link(&whole, "next").is_none(), "one page holds them all");
    let mut paged = Vec::new();
    let (status, mut page) = search(&server, "_count=2", &token).await;
    assert_eq!(StatusCode::OK, status);
    assert_eq!(
        Some(format!("{ISSUER}/audit?_count=2").as_str()),
        link(&page, "self")
    );
    loop {
        let found = ids(&page);
        assert!(found.len() <= 2);
        paged.extend(found);
        let Some(next) = link(&page, "next") else {
            break;
        };
        let path = next.strip_prefix(ISSUER).expect("a link under the issuer");
        assert!(path.contains("_count=2"), "{path}");
        let (status, _, body) = server.call(Method::GET, path, None, Some(&token)).await;
        assert_eq!(StatusCode::OK, status, "{body}");
        page = body;
    }
    assert_eq!(
        every, paged,
        "the pages read the records once, newest first"
    );
    let (_, filtered) = search(&server, "client=export&_count=3", &token).await;
    let next = link(&filtered, "next").expect("a next page");
    assert!(
        next.contains("client=export"),
        "the link keeps the filter: {next}"
    );
    server.stop().await;
}

/// Returns HTTP Basic credentials of `client_id` with `secret`.
fn basic(client_id: &str, secret: &str) -> String {
    let pair = format!(
        "{client_id}:{}",
        url::form_urlencoded::byte_serialize(secret.as_bytes()).collect::<String>()
    );
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(pair)
    )
}

/// Returns whether `gateway` authenticates at the introspection endpoint
/// with `secret`.
async fn introspects(server: &Server, secret: &str) -> StatusCode {
    let form = vec![(String::from("token"), String::from("unknown"))];
    let (status, _, _) = server
        .post_authorized("/introspect", &form, Some(basic("gateway", secret)))
        .await;
    status
}

#[tokio::test]
async fn a_symmetric_client_gets_a_new_secret_once_and_others_are_refused() {
    let server = Server::start().await;
    let admin = server.token("admin", "system/admin", ISSUER).await;
    assert_eq!(StatusCode::OK, introspects(&server, GATEWAY_SECRET).await);
    let (status, headers, body) = server
        .call(
            Method::POST,
            "/admin/clients/gateway/secret",
            None,
            Some(&admin),
        )
        .await;
    assert_eq!(StatusCode::OK, status, "{body}");
    assert_eq!(
        Some("no-store"),
        headers
            .get(http::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
    );
    assert_eq!(json!("gateway"), body["client_id"]);
    assert_eq!(json!(0), body["client_secret_expires_at"]);
    let secret = body["client_secret"].as_str().expect("the secret, once");
    assert_eq!(StatusCode::OK, introspects(&server, secret).await);
    assert_eq!(
        StatusCode::UNAUTHORIZED,
        introspects(&server, GATEWAY_SECRET).await,
        "the old secret no longer authenticates"
    );
    let (_, _, listed) = server
        .call(Method::GET, "/admin/clients", None, Some(&admin))
        .await;
    assert!(
        !listed.to_string().contains(secret),
        "no other answer repeats it"
    );

    for (client, status, error) in [
        ("export", StatusCode::BAD_REQUEST, "invalid_request"),
        ("app", StatusCode::BAD_REQUEST, "invalid_request"),
        ("nobody", StatusCode::NOT_FOUND, "not_found"),
    ] {
        let (answered, _, body) = server
            .call(
                Method::POST,
                &format!("/admin/clients/{client}/secret"),
                None,
                Some(&admin),
            )
            .await;
        assert_eq!(status, answered, "{client}: {body}");
        assert_eq!(json!(error), body["error"], "{client}");
    }
    let (status, _, _) = server
        .call(Method::POST, "/admin/clients/gateway/secret", None, None)
        .await;
    assert_eq!(StatusCode::UNAUTHORIZED, status);

    let kept = records(&server.store).await;
    let changes: BTreeSet<String> = events(&kept).into_iter().collect();
    assert!(changes.contains("client-updated"), "{changes:?}");
    let issued = kept
        .iter()
        .find(|record| events(std::slice::from_ref(record)) == ["client-updated"])
        .expect("the new secret is recorded");
    assert_eq!(
        json!("admin"),
        issued["agent"][0]["who"]["display"],
        "{issued}"
    );
    assert!(
        !issued.to_string().contains(secret),
        "the record never holds the secret"
    );
    server.stop().await;
}
