// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The admin API through the whole stack against a real PostgreSQL
//! (`docs/architecture.md` §13.8): the guard, the registry's reads and
//! writes with their typed refusals, the record of every change,
//! `ferrosmart client apply`, and a withdrawal or a disable that every
//! replica honours on its next request.

use ferrosmart::store::grant::{Access, NewGrant};
use http::{Method, StatusCode, header};
use serde_json::{Value, json};

use crate::introspection::{Answer, ISSUER, Server, inactive, unique};
use crate::support::{RESOURCE, audit, events, records};

/// The admin scope.
const ADMIN_SCOPE: &str = "system/admin";

/// The approval time every approving document names.
/// Returns an access token of the `admin` client for FerroSMART's own
/// issuer, carrying the admin scope.
async fn admin_token(server: &Server) -> String {
    server.token("admin", ADMIN_SCOPE, ISSUER).await
}

/// Returns a public app an administrator registered, first party when
/// `first_party`.
fn staff_app(first_party: bool) -> Value {
    json!({
        "client_id": "staff-app",
        "client_name": "Staff app",
        "token_endpoint_auth_method": "none",
        "redirect_uris": ["https://staff.example.org/callback"],
        "resources": [RESOURCE],
        "scope": "openid fhirUser launch user/Observation.rs offline_access",
        "grant_types": ["authorization_code", "refresh_token"],
        "first_party": first_party,
    })
}

/// Returns the `error` of `answer`, asserting its status.
fn refused(answer: &Answer, status: StatusCode) -> String {
    assert_eq!(status, answer.0, "{:?}", answer.2);
    answer
        .2
        .get("error")
        .and_then(Value::as_str)
        .expect("an error code")
        .to_owned()
}

/// Records an `offline_access` grant of `client` for `alice`, issued on
/// `basis`, with a refresh token and an access token; returns the grant id
/// and both tokens.
async fn granted(server: &Server, client: &str, basis: &str) -> (String, String, String) {
    let id = unique();
    server
        .store
        .create_grant(&NewGrant {
            id: &id,
            client_id: client,
            subject: "alice",
            fhir_user: Some("Patient/7"),
            audience: RESOURCE,
            scope: "openid launch user/Observation.rs offline_access",
            context: &json!({}),
            auth_time: Some(jiff::Timestamp::now().as_second()),
            access: Some(Access::Offline),
            upstream_session: None,
            basis: Some(basis),
            roles: &[],
            acr: None,
            dpop_jkt: None,
        })
        .await
        .expect("recorded");
    let refresh = server.refresh(&id, 3600).await;
    let access = server.access(client, Some(&id), 300).await;
    (id, refresh, access)
}

/// Returns the form that refreshes `token` for the public client `client`.
fn refresh_form(client: &str, token: &str) -> Vec<(String, String)> {
    vec![
        (String::from("grant_type"), String::from("refresh_token")),
        (String::from("refresh_token"), token.to_owned()),
        (String::from("client_id"), client.to_owned()),
    ]
}

#[tokio::test]
async fn the_admin_api_admits_only_an_active_own_token_with_the_admin_scope() {
    let server = Server::start().await;
    let (status, headers, body) = server.call(Method::GET, "/admin/clients", None, None).await;
    assert_eq!(StatusCode::UNAUTHORIZED, status, "no token");
    assert!(
        headers
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("Bearer")),
        "RFC 6750 §3, the challenge names the scheme"
    );
    assert_eq!(json!("invalid_token"), body["error"]);
    // NOTE: RFC 6750 §3.1, a token without the scope answers 403.
    let introspector = server.token("rs", "system/introspect", ISSUER).await;
    let answer = server
        .call(Method::GET, "/admin/clients", None, Some(&introspector))
        .await;
    assert_eq!(
        "insufficient_scope",
        refused(&answer, StatusCode::FORBIDDEN)
    );
    let elsewhere = server.token("export", "system/Patient.rs", RESOURCE).await;
    let answer = server
        .call(Method::GET, "/admin/clients", None, Some(&elsewhere))
        .await;
    assert_eq!(
        "invalid_token",
        refused(&answer, StatusCode::UNAUTHORIZED),
        "a token for another audience"
    );
    let forged = "eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K2p3dCJ9.e30.c2ln";
    let answer = server
        .call(Method::GET, "/admin/clients", None, Some(forged))
        .await;
    assert_eq!("invalid_token", refused(&answer, StatusCode::UNAUTHORIZED));
    let token = admin_token(&server).await;
    let (status, headers, body) = server
        .call(Method::GET, "/admin/clients", None, Some(&token))
        .await;
    assert_eq!(StatusCode::OK, status, "{body}");
    assert_eq!(
        Some("no-store"),
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
    );
    // NOTE: RFC 7009 §2, a revoked token is refused on the next request.
    let mut form = server.credentials("admin");
    form.push((String::from("token"), token.clone()));
    let (status, _, _) = server.post("/revoke", &form, None).await;
    assert_eq!(StatusCode::OK, status);
    let answer = server
        .call(Method::GET, "/admin/clients", None, Some(&token))
        .await;
    assert_eq!("invalid_token", refused(&answer, StatusCode::UNAUTHORIZED));
    server.stop().await;
}

#[tokio::test]
async fn the_registry_is_listed_read_created_and_updated() {
    let server = Server::start().await;
    let token = admin_token(&server).await;
    let (status, _, body) = server
        .call(Method::GET, "/admin/clients", None, Some(&token))
        .await;
    assert_eq!(StatusCode::OK, status);
    let ids: Vec<&str> = body["clients"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(|client| client["client_id"].as_str())
        .collect();
    assert_eq!(
        vec!["admin", "app", "export", "gateway", "portal", "rs", "vault"],
        ids
    );
    let (status, _, vault) = server
        .call(Method::GET, "/register/vault", None, Some(&token))
        .await;
    assert_eq!(StatusCode::OK, status);
    assert_eq!(json!("admin"), vault["registered_by"]);
    assert_eq!(
        json!("client_secret_basic"),
        vault["token_endpoint_auth_method"]
    );
    assert!(
        vault.get("secret_hash").is_none(),
        "the answer never carries the secret hash"
    );
    let (status, headers, created) = server
        .call(
            Method::POST,
            "/register",
            Some(&staff_app(false)),
            Some(&token),
        )
        .await;
    assert_eq!(StatusCode::CREATED, status, "{created}");
    assert_eq!(
        Some("https://smart.example.org/register/staff-app"),
        headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
    );
    assert_eq!(json!("admin"), created["registered_by"]);
    assert_eq!(json!("Staff app"), created["client_name"]);
    let client = server
        .store
        .client("staff-app")
        .await
        .expect("reads")
        .expect("every request finds it at once");
    assert_eq!(
        vec![String::from("https://staff.example.org/callback")],
        client.redirect_uris
    );
    let answer = server
        .call(
            Method::POST,
            "/register",
            Some(&staff_app(false)),
            Some(&token),
        )
        .await;
    assert_eq!("client_exists", refused(&answer, StatusCode::CONFLICT));
    let mut renamed = staff_app(false);
    renamed["client_name"] = json!("Staff app 2");
    let (status, _, updated) = server
        .call(
            Method::PUT,
            "/register/staff-app",
            Some(&renamed),
            Some(&token),
        )
        .await;
    assert_eq!(StatusCode::OK, status, "{updated}");
    assert_eq!(json!("Staff app 2"), updated["client_name"]);
    server.stop().await;
}

#[tokio::test]
async fn a_registration_breaking_a_rule_is_refused_with_its_error_code() {
    let server = Server::start().await;
    let token = admin_token(&server).await;
    let (status, _, _) = server
        .call(
            Method::POST,
            "/register",
            Some(&staff_app(false)),
            Some(&token),
        )
        .await;
    assert_eq!(StatusCode::CREATED, status);
    // NOTE: RFC 7591 §3.2.2, the registration error codes.
    let mut fragment = staff_app(false);
    fragment["client_id"] = json!("fragment");
    fragment["redirect_uris"] = json!(["https://staff.example.org/callback#here"]);
    let answer = server
        .call(Method::POST, "/register", Some(&fragment), Some(&token))
        .await;
    assert_eq!(
        "invalid_redirect_uri",
        refused(&answer, StatusCode::BAD_REQUEST)
    );
    let mut keyed = staff_app(false);
    keyed["client_id"] = json!("keyed");
    keyed["jwks_uri"] = json!("https://keyed.example.org/jwks.json");
    let answer = server
        .call(Method::POST, "/register", Some(&keyed), Some(&token))
        .await;
    assert_eq!(
        "invalid_client_metadata",
        refused(&answer, StatusCode::BAD_REQUEST)
    );
    let mut unknown = staff_app(false);
    unknown["client_id"] = json!("unknown");
    unknown["upstreams"] = json!(["nowhere"]);
    let answer = server
        .call(Method::POST, "/register", Some(&unknown), Some(&token))
        .await;
    assert_eq!(
        "invalid_client_metadata",
        refused(&answer, StatusCode::BAD_REQUEST)
    );
    // NOTE: RFC 7591 §2, a member the endpoint does not read is ignored.
    let mut extra = staff_app(false);
    extra["client_id"] = json!("extra");
    extra["software_version"] = json!("1.0");
    let (status, _, created) = server
        .call(Method::POST, "/register", Some(&extra), Some(&token))
        .await;
    assert_eq!(StatusCode::CREATED, status, "{created}");
    assert!(created.get("software_version").is_none(), "{created}");
    let answer = server
        .call(
            Method::PUT,
            "/register/portal",
            Some(&staff_app(false)),
            Some(&token),
        )
        .await;
    assert_eq!("invalid_request", refused(&answer, StatusCode::BAD_REQUEST));
    // NOTE: RFC 7592 §2.1, an unknown client answers 401.
    let answer = server
        .call(Method::GET, "/register/nobody", None, Some(&token))
        .await;
    assert_eq!("invalid_token", refused(&answer, StatusCode::UNAUTHORIZED));
    let mut launched = staff_app(false);
    launched["launch_uri"] = json!("https://staff.example.org/launch");
    let (status, _, _) = server
        .call(
            Method::PUT,
            "/register/staff-app",
            Some(&launched),
            Some(&token),
        )
        .await;
    assert_eq!(StatusCode::OK, status);
    let mut twin = staff_app(false);
    twin["client_id"] = json!("twin");
    twin["launch_uri"] = json!("https://STAFF.example.org:443/launch");
    let answer = server
        .call(Method::POST, "/register", Some(&twin), Some(&token))
        .await;
    assert_eq!("launch_uri_taken", refused(&answer, StatusCode::CONFLICT));
    server.stop().await;
}

// NOTE: our own design, the document is read only as a bounded application/json
// body into the closed client document, never as any other shape.
#[tokio::test]
async fn a_body_that_is_no_bounded_json_client_document_is_refused_unread() {
    let server = Server::start().await;
    let token = admin_token(&server).await;
    let form = vec![(String::from("client_id"), String::from("form-client"))];
    let (status, _, body) = server
        .post_authorized("/register", &form, Some(format!("Bearer {token}")))
        .await;
    assert_eq!(StatusCode::UNSUPPORTED_MEDIA_TYPE, status, "{body}");
    assert_eq!(json!("invalid_request"), body["error"]);
    let mut huge = staff_app(false);
    huge["client_name"] = json!("x".repeat(ferrosmart::admin::DOCUMENT_LIMIT));
    let (status, _, body) = server
        .call(Method::POST, "/register", Some(&huge), Some(&token))
        .await;
    assert_eq!(StatusCode::PAYLOAD_TOO_LARGE, status, "{body}");
    assert_eq!(json!("invalid_request"), body["error"]);
    let (status, _, body) = server
        .call(
            Method::POST,
            "/register",
            Some(&json!(["staff-app"])),
            Some(&token),
        )
        .await;
    // NOTE: RFC 7591 §3.2.2, a body that is no metadata object.
    assert_eq!(
        "invalid_client_metadata",
        refused(
            &(status, http::HeaderMap::new(), body),
            StatusCode::BAD_REQUEST
        )
    );
    assert!(
        server
            .store
            .client("staff-app")
            .await
            .expect("reads")
            .is_none()
            && server
                .store
                .client("form-client")
                .await
                .expect("reads")
                .is_none(),
        "nothing is stored"
    );
    server.stop().await;
}

// NOTE: RFC 7591 §3.2.1, the server issues client_secret, answers it once with
// client_secret_expires_at, and the document never carries a hash.
#[tokio::test]
async fn a_symmetric_client_is_issued_its_secret_once_and_keeps_its_hash() {
    let server = Server::start().await;
    let token = admin_token(&server).await;
    let mut document = json!({
        "client_id": "ledger",
        "token_endpoint_auth_method": "client_secret_basic",
        "client_name": "Ledger",
        "redirect_uris": ["https://ledger.example.org/callback"],
        "grant_types": ["authorization_code"],
    });
    let (status, _, created) = server
        .call(Method::POST, "/register", Some(&document), Some(&token))
        .await;
    assert_eq!(StatusCode::CREATED, status, "{created}");
    assert!(created["client_secret"].is_string(), "{created}");
    assert_eq!(json!(0), created["client_secret_expires_at"]);
    let stored = server
        .store
        .client("ledger")
        .await
        .expect("reads")
        .expect("registered");
    document["client_name"] = json!("Ledger, renamed");
    let (status, _, updated) = server
        .call(
            Method::PUT,
            "/register/ledger",
            Some(&document),
            Some(&token),
        )
        .await;
    assert_eq!(StatusCode::OK, status, "{updated}");
    assert!(updated.get("client_secret").is_none(), "issued once");
    let kept = server
        .store
        .client("ledger")
        .await
        .expect("reads")
        .expect("registered");
    assert_eq!(stored.secret_hash, kept.secret_hash);
    // NOTE: RFC 7591 §2, a hash the request names is no member the endpoint
    // reads: it is ignored and the stored secret stays.
    let mut hashed = document.clone();
    hashed["secret_hash"] = json!("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo");
    let (status, _, _) = server
        .call(Method::PUT, "/register/ledger", Some(&hashed), Some(&token))
        .await;
    assert_eq!(StatusCode::OK, status);
    let unchanged = server
        .store
        .client("ledger")
        .await
        .expect("reads")
        .expect("registered");
    assert_eq!(stored.secret_hash, unchanged.secret_hash);
    // NOTE: RFC 7592 §2.2, a client_secret the request names is the one held.
    let mut wrong = document.clone();
    wrong["client_secret"] = json!("not the secret");
    let answer = server
        .call(Method::PUT, "/register/ledger", Some(&wrong), Some(&token))
        .await;
    assert_eq!(
        "invalid_client_metadata",
        refused(&answer, StatusCode::BAD_REQUEST)
    );
    let mut right = document.clone();
    right["client_secret"] = created["client_secret"].clone();
    let (status, _, _) = server
        .call(Method::PUT, "/register/ledger", Some(&right), Some(&token))
        .await;
    assert_eq!(StatusCode::OK, status);
    server.stop().await;
}

#[tokio::test]
async fn every_change_is_recorded_naming_the_admin_client_and_the_client_changed() {
    let server = Server::start().await;
    let token = admin_token(&server).await;
    for (method, path, body) in [
        (Method::POST, "/register", Some(staff_app(true))),
        (Method::PUT, "/register/staff-app", Some(staff_app(false))),
        (Method::POST, "/admin/clients/staff-app/disable", None),
        (Method::POST, "/admin/clients/staff-app/enable", None),
    ] {
        let (status, _, answer) = server.call(method, path, body.as_ref(), Some(&token)).await;
        assert!(status.is_success(), "{answer}");
    }
    let kept = records(&server.store).await;
    let codes = events(&kept);
    for code in [
        "client-created",
        "client-updated",
        "client-disabled",
        "client-enabled",
    ] {
        assert!(codes.iter().any(|kept| kept == code), "{code} in {codes:?}");
    }
    let disabled = kept
        .iter()
        .find(|record| events(std::slice::from_ref(record)) == ["client-disabled"])
        .expect("the disable is recorded");
    assert_eq!(
        json!("admin"),
        disabled["agent"][0]["who"]["display"],
        "{disabled}"
    );
    assert!(
        disabled.to_string().contains("staff-app"),
        "the record names the client changed"
    );
    // NOTE: our own design, a change that changes nothing is refused and writes no record.
    let answer = server
        .call(
            Method::POST,
            "/admin/clients/staff-app/enable",
            None,
            Some(&token),
        )
        .await;
    assert_eq!("unchanged", refused(&answer, StatusCode::CONFLICT));
    assert_eq!(kept.len(), records(&server.store).await.len());
    server.stop().await;
}

#[tokio::test]
async fn disabling_a_client_revokes_its_grants_and_tokens_at_once_at_every_replica() {
    let server = Server::start().await;
    let replica = server.replica().await;
    let token = admin_token(&server).await;
    let (_, refresh, access) = granted(&server, "app", "page").await;
    let backend = replica.token("export", "system/Patient.rs", RESOURCE).await;
    let (status, _, _) = server
        .call(
            Method::POST,
            "/admin/clients/app/disable",
            None,
            Some(&token),
        )
        .await;
    assert_eq!(StatusCode::OK, status);
    let (status, _, _) = server
        .call(
            Method::POST,
            "/admin/clients/export/disable",
            None,
            Some(&token),
        )
        .await;
    assert_eq!(StatusCode::OK, status);
    assert_eq!(inactive(), replica.introspect(&access).await);
    assert_eq!(inactive(), replica.introspect(&backend).await);
    let (status, _, body) = replica
        .post("/token", &refresh_form("app", &refresh), None)
        .await;
    assert_eq!(json!("invalid_client"), body["error"], "{status} {body}");
    let mut form = replica.credentials("export");
    form.extend([
        (
            String::from("grant_type"),
            String::from("client_credentials"),
        ),
        (String::from("scope"), String::from("system/Patient.rs")),
        (String::from("resource"), String::from(RESOURCE)),
    ]);
    let (status, _, body) = replica.post("/token", &form, None).await;
    assert_eq!(json!("invalid_client"), body["error"], "{status} {body}");
    let (_, _, listed) = replica
        .call(Method::GET, "/register/export", None, Some(&token))
        .await;
    assert!(listed["disabled_at"].is_string(), "{listed}");
    assert_eq!(json!("admin"), listed["registered_by"]);
    let (status, _, _) = replica
        .call(
            Method::POST,
            "/admin/clients/export/enable",
            None,
            Some(&token),
        )
        .await;
    assert_eq!(StatusCode::OK, status);
    let renewed = server.token("export", "system/Patient.rs", RESOURCE).await;
    assert_eq!(json!(true), server.introspect(&renewed).await["active"]);
    assert_eq!(
        inactive(),
        server.introspect(&backend).await,
        "a revoked token stays revoked"
    );
    // NOTE: our own design, the admin client's own disable ends its token too.
    let (status, _, _) = server
        .call(
            Method::POST,
            "/admin/clients/admin/disable",
            None,
            Some(&token),
        )
        .await;
    assert_eq!(StatusCode::OK, status);
    let answer = replica
        .call(Method::GET, "/admin/clients", None, Some(&token))
        .await;
    assert_eq!("invalid_token", refused(&answer, StatusCode::UNAUTHORIZED));
    replica.stop().await;
    server.stop().await;
}

// NOTE: docs/architecture.md §13.6 item 6, clearing first_party revokes the grants
// issued with no page on it, in the change's transaction.
#[tokio::test]
async fn clearing_first_party_revokes_what_was_issued_on_it_at_every_replica() {
    let server = Server::start().await;
    let replica = server.replica().await;
    let token = admin_token(&server).await;
    for (method, path, body) in [
        (Method::POST, "/register", staff_app(true)),
        (Method::PUT, "/register/staff-app", staff_app(true)),
    ] {
        let (status, _, answer) = server.call(method, path, Some(&body), Some(&token)).await;
        assert!(status.is_success(), "{answer}");
        assert_eq!(json!(true), answer["first_party"], "{answer}");
    }
    let (_, refresh, access) = granted(&server, "staff-app", "first-party").await;
    let (_, _, consented) = granted(&server, "staff-app", "page").await;
    let (_, _, staff) = granted(&server, "staff-app", "administrative").await;
    assert_eq!(
        json!(true),
        replica.introspect(&access).await["active"],
        "an update that keeps the mark keeps its grants"
    );
    let (status, _, _) = server
        .call(
            Method::PUT,
            "/register/staff-app",
            Some(&staff_app(false)),
            Some(&token),
        )
        .await;
    assert_eq!(StatusCode::OK, status);
    assert_eq!(inactive(), replica.introspect(&access).await);
    let (status, _, body) = replica
        .post("/token", &refresh_form("staff-app", &refresh), None)
        .await;
    assert_eq!(json!("invalid_grant"), body["error"], "{status} {body}");
    for (kept, what) in [
        (&consented, "a grant the person consented to"),
        (&staff, "a professional's grant"),
    ] {
        assert_eq!(
            json!(true),
            replica.introspect(kept).await["active"],
            "{what} is not the mark's"
        );
    }
    let updated = records(&server.store).await;
    assert!(
        updated
            .iter()
            .any(|record| record.to_string().contains("\"cleared\"")),
        "the change records the cleared mark"
    );
    replica.stop().await;
    server.stop().await;
}

#[tokio::test]
async fn client_apply_creates_then_replaces_a_client_and_records_the_command() {
    let server = Server::start().await;
    let settings = server.settings();
    let state =
        ferrosmart::server::AppState::new(settings.clone(), server.store.clone(), audit(settings));
    let mut kiosk = json!({
        "client_id": "kiosk",
        "token_endpoint_auth_method": "none",
        "client_name": "Kiosk",
        "redirect_uris": ["https://kiosk.example.org/callback"],
        "grant_types": ["authorization_code"],
        "scope": "openid",
    });
    let apply = |document: &Value| {
        let document = serde_json::from_value(document.clone()).expect("a client document");
        ferrosmart::admin::apply(&state, document)
    };
    let applied = apply(&kiosk).await.expect("applies");
    assert!(applied.created, "a new client is created");
    kiosk["client_name"] = json!("Kiosk, changed");
    let applied = apply(&kiosk).await.expect("applies again");
    assert!(!applied.created, "the client with the id is replaced");
    assert_eq!("Kiosk, changed", applied.registered.client.name);
    let token = admin_token(&server).await;
    let (_, _, read) = server
        .call(Method::GET, "/register/kiosk", None, Some(&token))
        .await;
    assert_eq!(json!("admin"), read["registered_by"]);
    let kept = crate::support::all_records(&server.store).await;
    let applied: Vec<&Value> = kept
        .iter()
        .filter(|record| record.to_string().contains("kiosk"))
        .collect();
    assert_eq!(
        vec![
            vec![String::from("client-created")],
            vec![String::from("client-updated")]
        ],
        applied
            .iter()
            .map(|record| events(std::slice::from_ref(*record)))
            .collect::<Vec<_>>()
    );
    for record in applied {
        assert_eq!(
            json!(ferrosmart::admin::APPLY_REQUESTER),
            record["agent"][0]["who"]["display"],
            "{record}"
        );
    }
    let mut other = kiosk.clone();
    other["client_id"] = json!("kiosk-2");
    other["launch_uri"] = json!("https://kiosk.example.org/launch");
    kiosk["launch_uri"] = json!("https://kiosk.example.org/launch");
    apply(&kiosk).await.expect("the launch URL is the kiosk's");
    assert!(
        matches!(
            apply(&other).await,
            Err(ferrosmart::admin::AdminError::LaunchUriTaken)
        ),
        "a launch URL names one client"
    );
    server.stop().await;
}

#[tokio::test]
async fn the_key_ring_lists_each_public_key_with_its_state() {
    let server = Server::start().await;
    let token = admin_token(&server).await;
    let (status, _, body) = server
        .call(Method::GET, "/admin/keys", None, Some(&token))
        .await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let keys = body["keys"].as_array().expect("a list");
    assert_eq!(json!("active"), keys[0]["state"]);
    let (_, _, published) = server.call(Method::GET, "/jwks", None, None).await;
    assert_eq!(published["keys"][0]["kid"], keys[0]["jwk"]["kid"]);
    assert!(
        keys.iter().all(|key| key["jwk"].get("d").is_none()),
        "no private member"
    );
    server.stop().await;
}
