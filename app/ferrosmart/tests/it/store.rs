// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The store against a real PostgreSQL: a fresh schema per case in a shared
//! database on the server `FERROSMART_TEST_PG_URL` names, a URL whose role
//! may `CREATE DATABASE` for the first case. CI sets it (the `nextest (core and axum)` job's PostgreSQL
//! service); a run without it fails the case, never skips it.

use ferrosmart::clients::{ClientKind, ClientSection, GrantType, resolve};
use ferrosmart::store::Store;
use secrecy::SecretString;

use crate::support::Database;

/// Returns a configured Backend Services client.
fn backend(client_id: &str, scope: &str) -> ClientSection {
    ClientSection {
        client_id: client_id.to_owned(),
        kind: ClientKind::ConfidentialAsymmetric,
        jwks_uri: String::from("https://export.example.org/jwks.json"),
        scopes: vec![scope.to_owned()],
        grant_types: vec![GrantType::ClientCredentials],
        ..ClientSection::default()
    }
}

#[tokio::test]
async fn the_configured_clients_are_registered_replaced_and_removed() {
    let database = Database::create().await;
    let store = Store::connect(&database.url, 2).await.expect("connects");
    store.migrate().await.expect("migrates");
    store
        .migrate()
        .await
        .expect("a second run migrates nothing");
    store.ping().await.expect("answers");

    let first = resolve(&[
        backend("export", "system/Patient.rs"),
        backend("audit", "system/AuditEvent.rs"),
    ])
    .expect("admitted");
    store.register(&first).await.expect("registered");
    assert_eq!(
        Some(first[0].clone()),
        store.client("export").await.expect("read")
    );
    assert_eq!(
        Some(first[1].clone()),
        store.client("audit").await.expect("read")
    );
    assert_eq!(None, store.client("unknown").await.expect("read"));

    let second = resolve(&[backend("export", "system/Observation.rs")]).expect("admitted");
    store.register(&second).await.expect("registered again");
    assert_eq!(
        Some(second[0].clone()),
        store.client("export").await.expect("read"),
        "replaced"
    );
    assert_eq!(
        None,
        store.client("audit").await.expect("read"),
        "no longer configured"
    );

    database.drop(store).await;
}

#[tokio::test]
async fn an_unreachable_database_is_an_error() {
    let url = SecretString::from(String::from(crate::support::UNREACHED_DATABASE));
    assert!(Store::connect(&url, 1).await.is_err());
}

#[tokio::test]
async fn the_sweep_deletes_lapsed_refresh_tokens_and_keeps_a_fresh_grant() {
    use ferrosmart::store::grant::{Access, NewGrant};
    let database = Database::create().await;
    let store = Store::connect(&database.url, 2).await.expect("connects");
    store.migrate().await.expect("migrates");
    let context = serde_json::json!({});
    store
        .create_grant(&NewGrant {
            id: "grant-1",
            client_id: "app",
            subject: "alice",
            fhir_user: None,
            audience: "https://ehr.example.org/fhir",
            scope: "patient/Observation.rs offline_access",
            context: &context,
            auth_time: None,
            access: Some(Access::Offline),
            upstream_session: None,
            approved_at: None,
            roles: &[],
            acr: None,
        })
        .await
        .expect("recorded");
    let now = jiff::Timestamp::now().as_second();
    store
        .issue_refresh("lapsed", "grant-1", now - 10)
        .await
        .expect("recorded");
    store
        .issue_refresh("live", "grant-1", now + 3600)
        .await
        .expect("recorded");
    store.sweep().await.expect("swept");
    assert_eq!(None, store.refresh_token("lapsed").await.expect("read"));
    let live = store.refresh_token("live").await.expect("read");
    assert!(
        live.is_some_and(|record| record.active),
        "kept with its grant"
    );
    database.drop(store).await;
}
