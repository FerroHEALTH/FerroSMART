// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A person's grants, consents and sessions through the admin API (#831)
//! against a real PostgreSQL: the lookup of their subject, the listing,
//! and each withdrawal with its record naming the admin client.

use ferrosmart::store::grant::{Access, NewGrant};
use http::{Method, StatusCode};
use serde_json::{Value, json};

use crate::authorize::Provider;
use crate::introspection::{ISSUER, Server, unique};
use crate::support::{ASSURANCE, RESOURCE, events, records};

/// The person every case changes.
const ALICE: &str = "alice";

/// Records a grant of `app` for `subject` with `access`, in the upstream
/// session `session` when one is named, with a refresh token and an access
/// token; returns the grant id and the refresh token.
async fn granted(
    server: &Server,
    subject: &str,
    access: Access,
    session: Option<&str>,
) -> (String, String) {
    let id = unique();
    server
        .store
        .create_grant(&NewGrant {
            id: &id,
            client_id: "app",
            subject,
            fhir_user: Some("Patient/7"),
            audience: RESOURCE,
            scope: "openid launch patient/Observation.rs offline_access",
            context: &json!({}),
            auth_time: Some(jiff::Timestamp::now().as_second()),
            access: Some(access),
            upstream_session: session,
            basis: Some("page"),
            roles: &[],
            acr: None,
            dpop_jkt: None,
            person_claims: None,
        })
        .await
        .expect("recorded");
    let refresh = server.refresh(&id, 3600).await;
    server.access("app", Some(&id), 300).await;
    (id, refresh)
}

/// Returns the answer of refreshing `token` for the public `app`.
async fn refreshed(server: &Server, token: &str) -> (StatusCode, Value) {
    let form = vec![
        (String::from("grant_type"), String::from("refresh_token")),
        (String::from("refresh_token"), token.to_owned()),
        (String::from("client_id"), String::from("app")),
    ];
    let (status, _, body) = server.post("/token", &form, None).await;
    (status, body)
}

/// Sends `method` to `path` with the admin `token` and holds the answer to
/// the schema the OpenAPI document gives `template` for its status.
async fn checked(
    server: &Server,
    method: Method,
    template: &str,
    path: &str,
    token: &str,
) -> (StatusCode, http::HeaderMap, Value) {
    let described = crate::openapi::served(server).await;
    let answer = server.call(method.clone(), path, None, Some(token)).await;
    if answer.0 != StatusCode::NO_CONTENT {
        crate::openapi::holds(
            &described,
            &method.as_str().to_ascii_lowercase(),
            template,
            "application/json",
            &answer,
        );
    }
    answer
}

/// Returns the ids of the grants `body` lists.
fn grant_ids(body: &Value) -> Vec<&str> {
    body["grants"]
        .as_array()
        .expect("grants")
        .iter()
        .filter_map(|grant| grant["grant_id"].as_str())
        .collect()
}

#[tokio::test]
async fn a_person_s_subject_is_found_by_provider_and_upstream_sub() {
    let provider = Provider::start().await;
    let server = Server::start_with(&format!(
        "[[ferrosmart.upstream]]\nname = \"idp\"\n[ferrosmart.upstream.oidc]\nissuer = {:?}\n\
         client_id = \"ferrosmart\"\n[ferrosmart.upstream.oidc.client_secret_basic]\nsecret = \"synthetic\"\n\
         {ASSURANCE}",
        provider.server.uri()
    ))
    .await;
    let admin = server.token("admin", "system/admin", ISSUER).await;
    let (status, _, body) = checked(
        &server,
        Method::GET,
        "/admin/subjects",
        "/admin/subjects?upstream=idp&sub=person-7",
        &admin,
    )
    .await;
    assert_eq!(StatusCode::OK, status, "{body}");
    assert_eq!(
        json!(ferrosmart::upstream::pairwise(
            &provider.server.uri(),
            "person-7"
        )),
        body["subject"]
    );
    for (query, status) in [
        ("upstream=nowhere&sub=person-7", StatusCode::NOT_FOUND),
        ("upstream=idp", StatusCode::BAD_REQUEST),
        ("upstream=idp&sub=", StatusCode::BAD_REQUEST),
        ("upstream=idp&sub=a&sub=b", StatusCode::BAD_REQUEST),
        ("upstream=idp&sub=a&other=b", StatusCode::BAD_REQUEST),
    ] {
        let (answered, _, body) = checked(
            &server,
            Method::GET,
            "/admin/subjects",
            &format!("/admin/subjects?{query}"),
            &admin,
        )
        .await;
        assert_eq!(status, answered, "{query}: {body}");
    }
    let (status, _, _) = server
        .call(
            Method::GET,
            "/admin/subjects?upstream=idp&sub=person-7",
            None,
            None,
        )
        .await;
    assert_eq!(StatusCode::UNAUTHORIZED, status);
    server.stop().await;
}

#[tokio::test]
async fn a_revoked_grant_s_refresh_token_is_refused_and_the_record_names_the_admin() {
    let server = Server::start().await;
    let admin = server.token("admin", "system/admin", ISSUER).await;
    let (kept, kept_refresh) = granted(&server, ALICE, Access::Offline, None).await;
    let (ended, ended_refresh) = granted(&server, ALICE, Access::Offline, None).await;
    let (bob_s, _) = granted(&server, "bob", Access::Offline, None).await;

    let (status, _, body) = checked(
        &server,
        Method::GET,
        "/admin/subjects/{sub}/grants",
        "/admin/subjects/alice/grants",
        &admin,
    )
    .await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let mut listed = grant_ids(&body);
    listed.sort_unstable();
    let mut expected = vec![kept.as_str(), ended.as_str()];
    expected.sort_unstable();
    assert_eq!(expected, listed, "alice's live grants alone");
    let grant = &body["grants"][0];
    assert_eq!(json!("app"), grant["client_id"]);
    assert_eq!(json!(RESOURCE), grant["aud"]);
    assert_eq!(json!("page"), grant["basis"]);
    assert_eq!(json!("offline"), grant["access"]);
    assert!(
        grant["issued_at"].is_string() && grant["last_used_at"].is_string(),
        "{grant}"
    );

    let (status, _, _) = checked(
        &server,
        Method::DELETE,
        "/admin/subjects/{sub}/grants/{grant_id}",
        &format!("/admin/subjects/alice/grants/{bob_s}"),
        &admin,
    )
    .await;
    assert_eq!(
        StatusCode::NOT_FOUND,
        status,
        "another person's grant is not alice's"
    );
    let (status, _, _) = checked(
        &server,
        Method::DELETE,
        "/admin/subjects/{sub}/grants/{grant_id}",
        &format!("/admin/subjects/alice/grants/{ended}"),
        &admin,
    )
    .await;
    assert_eq!(StatusCode::NO_CONTENT, status);
    let (status, body) = refreshed(&server, &ended_refresh).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{body}");
    assert_eq!(json!("invalid_grant"), body["error"]);
    let (status, body) = refreshed(&server, &kept_refresh).await;
    assert_eq!(
        StatusCode::OK,
        status,
        "the other grant still refreshes: {body}"
    );
    let (status, _, _) = checked(
        &server,
        Method::DELETE,
        "/admin/subjects/{sub}/grants/{grant_id}",
        &format!("/admin/subjects/alice/grants/{ended}"),
        &admin,
    )
    .await;
    assert_eq!(
        StatusCode::NOT_FOUND,
        status,
        "a revoked grant is no longer live"
    );

    let kept_records = records(&server.store).await;
    let revoked = kept_records
        .iter()
        .find(|record| events(std::slice::from_ref(record)) == ["grant-revoked"])
        .expect("the revocation is recorded");
    let text = revoked.to_string();
    assert!(
        text.contains("\"admin\""),
        "the record names the admin client: {text}"
    );
    assert!(text.contains(&ended), "the record names the grant: {text}");
    server.stop().await;
}

#[tokio::test]
async fn withdrawing_a_consent_forgets_it_and_revokes_the_client_s_grants() {
    let server = Server::start().await;
    let admin = server.token("admin", "system/admin", ISSUER).await;
    let (_grant, refresh) = granted(&server, ALICE, Access::Offline, None).await;
    let pool = sqlx::PgPool::connect(&server.database_url())
        .await
        .expect("connects");
    sqlx::query(
        "INSERT INTO consent (subject, client_id, audience, scope) VALUES ($1, 'app', $2, $3)",
    )
    .bind(ALICE)
    .bind(RESOURCE)
    .bind("patient/Observation.rs")
    .execute(&pool)
    .await
    .expect("remembered");
    pool.close().await;

    let (_, _, body) = checked(
        &server,
        Method::GET,
        "/admin/subjects/{sub}/grants",
        "/admin/subjects/alice/grants",
        &admin,
    )
    .await;
    assert_eq!(
        json!([{ "client_id": "app", "aud": RESOURCE, "scope": "patient/Observation.rs",
                 "granted_at": body["consents"][0]["granted_at"] }]),
        body["consents"]
    );
    let (status, _, body) = checked(
        &server,
        Method::DELETE,
        "/admin/subjects/{sub}/consents/{client_id}",
        "/admin/subjects/alice/consents/app",
        &admin,
    )
    .await;
    assert_eq!(StatusCode::OK, status, "{body}");
    assert_eq!(json!({ "remembered": true, "grants": 1 }), body);
    let (status, _) = refreshed(&server, &refresh).await;
    assert_eq!(StatusCode::BAD_REQUEST, status);
    let (_, _, body) = checked(
        &server,
        Method::GET,
        "/admin/subjects/{sub}/grants",
        "/admin/subjects/alice/grants",
        &admin,
    )
    .await;
    assert_eq!(
        json!({ "subject": ALICE, "grants": [], "consents": [] }),
        body
    );
    assert!(
        events(&records(&server.store).await).contains(&String::from("consent-withdrawn")),
        "the withdrawal is recorded"
    );
    server.stop().await;
}

#[tokio::test]
async fn ending_a_person_s_sessions_ends_their_online_access_alone() {
    let server = Server::start().await;
    let admin = server.token("admin", "system/admin", ISSUER).await;
    let session = unique();
    server
        .store
        .begin_session(
            &session,
            "https://idp.example.org",
            "person-7",
            Some("sid-1"),
        )
        .await
        .expect("recorded");
    let (_online, online_refresh) = granted(&server, ALICE, Access::Online, Some(&session)).await;
    let (_offline, offline_refresh) =
        granted(&server, ALICE, Access::Offline, Some(&session)).await;
    let (status, _, body) = checked(
        &server,
        Method::DELETE,
        "/admin/subjects/{sub}/sessions",
        "/admin/subjects/alice/sessions",
        &admin,
    )
    .await;
    assert_eq!(StatusCode::OK, status, "{body}");
    assert_eq!(json!({ "sessions": 1, "grants": 1 }), body);
    let (status, _) = refreshed(&server, &online_refresh).await;
    assert_eq!(
        StatusCode::BAD_REQUEST,
        status,
        "online access ends with the session"
    );
    let (status, body) = refreshed(&server, &offline_refresh).await;
    assert_eq!(StatusCode::OK, status, "offline access outlives it: {body}");
    let (_, _, body) = checked(
        &server,
        Method::DELETE,
        "/admin/subjects/{sub}/sessions",
        "/admin/subjects/alice/sessions",
        &admin,
    )
    .await;
    assert_eq!(json!({ "sessions": 0, "grants": 0 }), body);
    assert!(
        events(&records(&server.store).await).contains(&String::from("session-ended")),
        "the end is recorded"
    );
    server.stop().await;
}
