// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A confidential symmetric client at the token, revocation and
//! introspection endpoints:
//! SMART App Launch 2.2.0, Client Authentication: Symmetric, with the
//! client secret sent by HTTP Basic or in the form (RFC 6749 §2.3.1).

use base64::Engine as _;
use ferrosmart::clients::{AuthMethod, ClientMetadata, GrantType, Material, SecretHash, resolve};
use ferrosmart::store::grant::Access;
use http::{StatusCode, header};
use serde_json::{Value, json};
use sqlx::Connection as _;

use crate::introspection::{Answer, GATEWAY_SECRET, Server, VAULT_SECRET, inactive, phc};
use crate::support::RESOURCE;

/// Returns the `Authorization` value of `client_id` and `secret` by HTTP
/// Basic, each form-urlencoded first (RFC 6749 §2.3.1).
fn basic(client_id: &str, secret: &str) -> String {
    let encode = |value: &str| -> String {
        url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
    };
    let pair = format!("{}:{}", encode(client_id), encode(secret));
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(pair)
    )
}

/// Returns the form refreshing `token`.
fn refresh(token: &str) -> Vec<(String, String)> {
    vec![
        (String::from("grant_type"), String::from("refresh_token")),
        (String::from("refresh_token"), token.to_owned()),
    ]
}

/// Starts a server with one offline grant of `vault` and its refresh token.
async fn vault() -> (Server, String) {
    let server = Server::start().await;
    let grant = server
        .grant("vault", Some(Access::Offline), None, &json!({}))
        .await;
    let token = server.refresh(&grant, 3600).await;
    (server, token)
}

/// Returns the `error` of `answer`.
fn error(answer: &Answer) -> Value {
    answer.2.get("error").cloned().unwrap_or(Value::Null)
}

#[tokio::test]
async fn a_symmetric_client_authenticates_by_http_basic() {
    let (server, token) = vault().await;
    let answer = server
        .post_authorized(
            "/token",
            &refresh(&token),
            Some(basic("vault", VAULT_SECRET)),
        )
        .await;
    assert_eq!(StatusCode::OK, answer.0, "{:?}", answer.2);
    assert!(answer.2["access_token"].is_string());
    server.stop().await;
}

// NOTE: RFC 7591 §2, the client authenticates by the token_endpoint_auth_method
// it registered: `vault` registered client_secret_basic.
#[tokio::test]
async fn a_symmetric_client_authenticates_in_the_form_only_when_registered_so() {
    let (server, token) = vault().await;
    let mut form = refresh(&token);
    form.push((String::from("client_id"), String::from("vault")));
    form.push((String::from("client_secret"), String::from(VAULT_SECRET)));
    let refused = server.post("/token", &form, None).await;
    assert_eq!(json!("invalid_client"), error(&refused), "{:?}", refused.2);
    let mut connection = sqlx::PgConnection::connect(&server.database_url())
        .await
        .expect("connects");
    sqlx::query(
        "UPDATE client SET token_endpoint_auth_method = 'client_secret_post' WHERE client_id = 'vault'",
    )
    .execute(&mut connection)
    .await
    .expect("registered for the form");
    let answer = server.post("/token", &form, None).await;
    assert_eq!(StatusCode::OK, answer.0, "{:?}", answer.2);
    let basic = server
        .post_authorized(
            "/token",
            &refresh(&token),
            Some(basic("vault", VAULT_SECRET)),
        )
        .await;
    assert_eq!(json!("invalid_client"), error(&basic), "{:?}", basic.2);
    server.stop().await;
}

// NOTE: RFC 6749 §5.2, invalid_client: a credential sent in the Authorization
// header answers 401 with the scheme in WWW-Authenticate.
#[tokio::test]
async fn a_wrong_secret_is_invalid_client() {
    let (server, token) = vault().await;
    for authorization in [
        basic("vault", "not the secret"),
        basic("unknown", VAULT_SECRET),
        basic("app", VAULT_SECRET),
    ] {
        let answer = server
            .post_authorized("/token", &refresh(&token), Some(authorization))
            .await;
        assert_eq!(StatusCode::UNAUTHORIZED, answer.0, "{:?}", answer.2);
        assert_eq!(json!("invalid_client"), error(&answer));
        assert_eq!(
            Some("Basic"),
            answer
                .1
                .get(header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok())
        );
    }
    let mut form = refresh(&token);
    form.push((String::from("client_id"), String::from("vault")));
    form.push((
        String::from("client_secret"),
        String::from("not the secret"),
    ));
    let answer = server.post("/token", &form, None).await;
    assert_eq!(StatusCode::BAD_REQUEST, answer.0);
    assert_eq!(json!("invalid_client"), error(&answer));
    server.stop().await;
}

// NOTE: RFC 6749 §2.3, "The client MUST NOT use more than one authentication
// method in each request".
#[tokio::test]
async fn two_authentication_methods_at_once_are_refused() {
    let (server, token) = vault().await;
    let mut form = refresh(&token);
    form.push((String::from("client_id"), String::from("vault")));
    form.push((String::from("client_secret"), String::from(VAULT_SECRET)));
    let answer = server
        .post_authorized("/token", &form, Some(basic("vault", VAULT_SECRET)))
        .await;
    assert_eq!(json!("invalid_request"), error(&answer), "{:?}", answer.2);
    server.stop().await;
}

// NOTE: RFC 7009 §2.1, a confidential client authenticates to revoke its token.
#[tokio::test]
async fn a_symmetric_client_revokes_its_refresh_token() {
    let (server, token) = vault().await;
    let form = vec![(String::from("token"), token.clone())];
    let answer = server
        .post_authorized("/revoke", &form, Some(basic("vault", VAULT_SECRET)))
        .await;
    assert_eq!(StatusCode::OK, answer.0);
    assert_eq!(inactive(), server.introspect(&token).await);
    server.stop().await;
}

// NOTE: SMART App Launch 2.2.0, Client Authentication: Symmetric, the profile
// "SHALL NOT be used" for Backend Services.
#[test]
fn a_symmetric_client_is_refused_the_client_credentials_grant_and_a_jwk_set() {
    let hash = phc(VAULT_SECRET);
    let admit = |section: &ClientMetadata, hash: &str| {
        resolve(
            section,
            Material {
                jwks: None,
                secret_hash: Some(SecretHash::from(hash.to_owned())),
            },
        )
    };
    let section = |grants: Vec<GrantType>, jwks_uri: &str| ClientMetadata {
        client_id: String::from("vault"),
        auth_method: AuthMethod::ClientSecretBasic,
        jwks_uri: jwks_uri.to_owned(),
        redirect_uris: vec![String::from("https://vault.example.org/callback")],
        grant_types: grants,
        ..ClientMetadata::default()
    };
    assert!(admit(&section(vec![GrantType::AuthorizationCode], ""), &hash).is_ok());
    assert!(admit(&section(vec![GrantType::ClientCredentials], ""), &hash).is_err());
    assert!(
        admit(
            &section(
                vec![GrantType::AuthorizationCode],
                "https://vault.example.org/jwks"
            ),
            &hash
        )
        .is_err()
    );
    let weak = "$argon2id$v=19$m=1024,t=1,p=1$c3ludGhldGljLXNhbHQtMTY$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert!(
        admit(&section(vec![GrantType::AuthorizationCode], ""), weak).is_err(),
        "a hash below the floor"
    );
    let mut public = section(vec![GrantType::AuthorizationCode], "");
    public.auth_method = AuthMethod::None;
    assert!(
        admit(&public, &hash).is_err(),
        "a secret on a public client"
    );
}

// NOTE: OWASP Password Storage Cheat Sheet, Argon2id at m=19456, t=2, p=1.
#[test]
fn an_issued_secret_is_hashed_at_the_floor_with_a_fresh_salt() {
    let one = phc(VAULT_SECRET);
    let other = phc(VAULT_SECRET);
    assert!(one.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{one}");
    assert_ne!(one, other, "a fresh salt each time");
}

/// Returns the form introspecting `token`.
fn introspect(token: &str) -> Vec<(String, String)> {
    vec![(String::from("token"), token.to_owned())]
}

/// Returns the `WWW-Authenticate` of `answer`.
fn challenge(answer: &Answer) -> Option<&str> {
    answer
        .1
        .get(header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
}

// NOTE: RFC 7662 §2.1, client authentication as RFC 6749 describes it, which
// docs/architecture.md §13.6 item 8 takes as at the token endpoint.
#[tokio::test]
async fn a_symmetric_client_with_the_right_introspects_by_its_secret() {
    let server = Server::start().await;
    let target = server.token("export", "system/Patient.rs", RESOURCE).await;
    let answer = server
        .post_authorized(
            "/introspect",
            &introspect(&target),
            Some(basic("gateway", GATEWAY_SECRET)),
        )
        .await;
    assert_eq!(StatusCode::OK, answer.0, "{:?}", answer.2);
    assert_eq!(json!(true), answer.2["active"]);
    assert_eq!(json!("export"), answer.2["client_id"]);
    let mut form = introspect(&target);
    form.push((String::from("client_id"), String::from("gateway")));
    form.push((String::from("client_secret"), String::from(GATEWAY_SECRET)));
    // NOTE: RFC 7591 §2, `gateway` registered client_secret_basic, so the form is
    // not its method.
    let answer = server.post("/introspect", &form, None).await;
    assert_eq!(json!("invalid_client"), answer.2["error"], "{:?}", answer.2);
    server.stop().await;
}

// NOTE: RFC 7662 §2.3, invalid client credentials answer 401 as RFC 6749 §5.2
// describes, with the Basic scheme challenged when the client used it.
#[tokio::test]
async fn a_symmetric_client_that_may_not_introspect_is_refused_with_a_401() {
    let server = Server::start().await;
    let target = server.token("export", "system/Patient.rs", RESOURCE).await;
    let cases = [
        (
            basic("gateway", "not the secret"),
            "invalid_client",
            "a wrong secret",
        ),
        (
            basic("app", GATEWAY_SECRET),
            "invalid_client",
            "a public client, which has no secret",
        ),
        (
            basic("vault", VAULT_SECRET),
            "unauthorized_client",
            "a client whose ceiling lacks system/introspect",
        ),
    ];
    for (authorization, expected, case) in cases {
        let answer = server
            .post_authorized("/introspect", &introspect(&target), Some(authorization))
            .await;
        assert_eq!(StatusCode::UNAUTHORIZED, answer.0, "{case}: {:?}", answer.2);
        assert_eq!(json!(expected), error(&answer), "{case}");
        assert_eq!(Some("Basic"), challenge(&answer), "{case}");
        assert_eq!(Value::Null, answer.2["active"], "{case}");
    }
    let mut form = introspect(&target);
    form.push((String::from("client_id"), String::from("gateway")));
    form.push((
        String::from("client_secret"),
        String::from("not the secret"),
    ));
    let answer = server.post("/introspect", &form, None).await;
    assert_eq!(StatusCode::UNAUTHORIZED, answer.0, "{:?}", answer.2);
    assert_eq!(json!("invalid_client"), error(&answer));
    let mut form = introspect(&target);
    form.push((String::from("client_id"), String::from("app")));
    let answer = server.post("/introspect", &form, None).await;
    assert_eq!(
        StatusCode::UNAUTHORIZED,
        answer.0,
        "a public client cannot authenticate"
    );
    assert_eq!(json!("invalid_client"), error(&answer));
    server.stop().await;
}

// NOTE: RFC 6749 §2.3, "The client MUST NOT use more than one authentication
// method in each request", at the introspection endpoint too.
#[tokio::test]
async fn introspection_with_two_authentication_methods_is_malformed() {
    let server = Server::start().await;
    let target = server.token("export", "system/Patient.rs", RESOURCE).await;
    let mut form = introspect(&target);
    form.extend(server.credentials("rs"));
    let answer = server
        .post_authorized("/introspect", &form, Some(basic("gateway", GATEWAY_SECRET)))
        .await;
    assert_eq!(StatusCode::BAD_REQUEST, answer.0, "{:?}", answer.2);
    assert_eq!(json!("invalid_request"), error(&answer));
    server.stop().await;
}
