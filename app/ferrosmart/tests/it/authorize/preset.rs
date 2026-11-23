// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A person's token from a standalone launch, read by a resource server
//! under `ferrohealth-smart`'s `ferrosmart` preset (RFC 9068 §2.2; SMART App
//! Launch 2.2.0, Scopes and Launch Context).

use ferrohealth_smart::kind::{CallerKind, IssuerKind};
use ferrohealth_smart::profile::ProfileKeys;

use super::*;

// NOTE: RFC 9068 §4 and RFC 8707: a token whose `aud` names the resource server was
// issued for it, so the resource server reads the signed-in person through any app.
#[tokio::test]
async fn a_person_s_token_is_read_under_the_ferrosmart_preset() {
    let (smart, body) = launch_with("offline_access").await;
    let token = body["access_token"].as_str().expect("a token");
    let (status, _, jwks) = smart.get("/jwks", None).await;
    assert_eq!(StatusCode::OK, status);
    let jwks: Value = serde_json::from_str(&jwks).expect("a JWK Set");
    let claims: Value = jsonwebtoken::dangerous::insecure_decode_claims(token).expect("claims");
    let audience = claims["aud"].as_str().expect("one audience");
    // NOTE: docs/architecture.md §13.21, the one `persons` table that also reads
    // the Backend Services tokens (token::a_backend_services_token_is_read_...).
    let keys = ProfileKeys::default();
    let caller = crate::support::read_under_preset(
        &jwks,
        ISSUER,
        audience,
        IssuerKind::Persons,
        &keys,
        token,
    )
    .await
    .expect("admitted");
    assert_eq!(&CallerKind::Person, caller.kind());
    // NOTE: RFC 9068 §2.2, `sub` is the person, and the app is `client_id`.
    assert_eq!(claims["sub"].as_str(), Some(caller.subject()));
    assert_eq!(Some("app"), caller.client_id());
    assert!(
        caller
            .scope()
            .contains(&String::from("user/Observation.rs")),
        "{:?}",
        caller.scope()
    );
    let elsewhere = crate::support::read_under_preset(
        &jwks,
        "https://other-issuer.example.org",
        audience,
        IssuerKind::Persons,
        &keys,
        token,
    )
    .await;
    assert!(elsewhere.is_err(), "another issuer");
    smart.stop().await;
}
