// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The OpenID Connect relying-party client against a stub provider: the code
//! exchange, a state or PKCE mismatch refused, the ID Token checks, the
//! refresh grant, revocation and the end-session URL.

use std::collections::BTreeMap;
use std::time::Duration;

use ferrohealth_secret::secret::Secret;
use ferrohealth_smart::client::assertion::AssertionKey;
use ferrohealth_smart::jws::algorithm::Algorithm;
use ferrohealth_smart::jws::claims::Validation;
use ferrohealth_smart::jws::compact::Header;
use ferrohealth_smart::metadata::Http;
use ferrohealth_smart::oidc::{
    Callback, OidcError, PendingSignIn, Provider, RelyingParty, TokenTypeHint, challenge,
};
use secrecy::SecretString;
use url::Url;
use wiremock::matchers;
use wiremock::{Mock, ResponseTemplate};

use crate::support::{
    Issuer, JWKS_PATH, SigningKey, TOKEN_PATH, ec_key, ed_key, mint_with, now, rsa_key,
};

/// The console's client id at the provider.
const CLIENT: &str = "synthetic-console";

/// The console's redirection endpoint.
const REDIRECT: &str = "https://console.example.org/auth/callback";

/// A provider with an end-session and a revocation endpoint, and the client
/// of a confidential console at it.
async fn provider(key: &SigningKey) -> (Issuer, RelyingParty) {
    let (issuer, client) = unauthenticated(key).await;
    (
        issuer,
        client.with_client_secret(SecretString::from("synthetic-secret")),
    )
}

/// The provider of [`provider`] and a client at it that has not yet named
/// how it authenticates.
async fn unauthenticated(key: &SigningKey) -> (Issuer, RelyingParty) {
    let issuer = Issuer::bare().await;
    let uri = issuer.uri();
    issuer
        .mount_document(
            "/.well-known/oauth-authorization-server",
            serde_json::json!({
                "issuer": uri,
                "jwks_uri": format!("{uri}{JWKS_PATH}"),
                "authorization_endpoint": format!("{uri}/authorize?tenant=synthetic"),
                "token_endpoint": format!("{uri}{TOKEN_PATH}"),
                "end_session_endpoint": format!("{uri}/logout"),
                "revocation_endpoint": format!("{uri}/revoke"),
                "code_challenge_methods_supported": ["S256"]
            }),
        )
        .await;
    issuer.mount_keys(&[key], None).await;
    let http = Http::new(Duration::from_secs(5)).expect("the engine builds");
    let discovered = Provider::discover(&http, &uri)
        .await
        .expect("the provider is discovered");
    let client = RelyingParty::new(
        http,
        discovered,
        CLIENT,
        Url::parse(REDIRECT).expect("a URL"),
    )
    .with_scopes(["profile"])
    .with_post_logout_redirect_uri(Url::parse("https://console.example.org/").expect("a URL"));
    (issuer, client)
}

/// The query of `url`, by name.
fn query(url: &Url) -> BTreeMap<String, String> {
    url.query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

/// An ID Token for this client carrying `nonce`, signed by `key`.
fn id_token(issuer: &Issuer, key: &SigningKey, nonce: &str) -> String {
    let now = now();
    let mut header = Header::new(key.alg);
    header.kid = Some(key.kid.clone());
    mint_with(
        key,
        &header,
        &serde_json::json!({
            "iss": issuer.uri(),
            "aud": CLIENT,
            "azp": CLIENT,
            "sub": "synthetic-operator",
            "nonce": nonce,
            "iat": now,
            "exp": now + 300,
            "name": "  ",
            "preferred_username": "operator.one",
            "roles": ["mapping-admin"]
        }),
    )
}

/// Mounts the token endpoint answering the code exchange for `verifier`
/// with `id_token`, and `invalid_grant` for any other request.
async fn mount_exchange(issuer: &Issuer, verifier: &str, id_token: &str) {
    Mock::given(matchers::method("POST"))
        .and(matchers::path(TOKEN_PATH))
        .and(matchers::header(
            "authorization",
            "Basic c3ludGhldGljLWNvbnNvbGU6c3ludGhldGljLXNlY3JldA==",
        ))
        .and(matchers::body_string_contains(
            "grant_type=authorization_code",
        ))
        .and(matchers::body_string_contains("code=synthetic-code"))
        .and(matchers::body_string_contains(format!(
            "code_verifier={verifier}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "synthetic-access-1",
            "token_type": "Bearer",
            "expires_in": 300,
            "refresh_token": "synthetic-refresh-1",
            "id_token": id_token
        })))
        .with_priority(1)
        .mount(&issuer.server)
        .await;
    mount_invalid_grant(issuer).await;
}

/// Mounts the token endpoint's `invalid_grant` refusal (RFC 6749 §5.2).
async fn mount_invalid_grant(issuer: &Issuer) {
    Mock::given(matchers::method("POST"))
        .and(matchers::path(TOKEN_PATH))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "the grant does not verify"
        })))
        .with_priority(5)
        .mount(&issuer.server)
        .await;
}

#[tokio::test]
async fn the_authorization_request_carries_state_nonce_and_an_s256_challenge() {
    let key = ec_key("op-1", Algorithm::Es256);
    let (_issuer, client) = provider(&key).await;
    let request = client.authorization_request().expect("a sign-in is minted");
    let sent = query(&request.url);
    assert_eq!(
        Some("synthetic"),
        sent.get("tenant").map(String::as_str),
        "the endpoint's own query stays"
    );
    assert_eq!(Some("code"), sent.get("response_type").map(String::as_str));
    assert_eq!(Some(CLIENT), sent.get("client_id").map(String::as_str));
    assert_eq!(Some(REDIRECT), sent.get("redirect_uri").map(String::as_str));
    assert_eq!(
        Some("openid profile"),
        sent.get("scope").map(String::as_str)
    );
    assert_eq!(
        Some(request.pending.state()),
        sent.get("state").map(String::as_str)
    );
    assert_eq!(
        Some(request.pending.nonce()),
        sent.get("nonce").map(String::as_str)
    );
    assert_eq!(
        Some("S256"),
        sent.get("code_challenge_method").map(String::as_str)
    );
    assert_eq!(
        Some(challenge(request.pending.verifier().expose()).as_str()),
        sent.get("code_challenge").map(String::as_str)
    );
    assert!(
        !request
            .url
            .as_str()
            .contains(request.pending.verifier().expose()),
        "the verifier never travels in the browser"
    );
    assert!(!sent.contains_key("prompt"));
}

#[tokio::test]
async fn offline_access_asks_for_consent() {
    let key = ec_key("op-1", Algorithm::Es256);
    let (_issuer, client) = provider(&key).await;
    let request = client
        .with_offline_access()
        .authorization_request()
        .expect("a sign-in is minted");
    let sent = query(&request.url);
    assert_eq!(
        Some("openid profile offline_access"),
        sent.get("scope").map(String::as_str)
    );
    assert_eq!(Some("consent"), sent.get("prompt").map(String::as_str));
}

#[tokio::test]
async fn the_code_is_exchanged_and_the_id_token_checked() {
    let key = ec_key("op-1", Algorithm::Es256);
    let (issuer, client) = provider(&key).await;
    let request = client.authorization_request().expect("a sign-in is minted");
    let pending = request.pending;
    let token = id_token(&issuer, &key, pending.nonce());
    mount_exchange(&issuer, pending.verifier().expose(), &token).await;
    let signed_in = client
        .exchange(
            &pending,
            &Callback::granted("synthetic-code", pending.state()),
        )
        .await
        .expect("the sign-in completes");
    assert_eq!("synthetic-access-1", signed_in.access_token.expose());
    assert_eq!(
        Some("synthetic-refresh-1"),
        signed_in.refresh_token.as_ref().map(Secret::expose)
    );
    assert_eq!(token, signed_in.id_token.expose());
    assert_eq!(Some(Duration::from_secs(300)), signed_in.expires_in);
    assert_eq!(vec!["openid", "profile"], signed_in.scopes);
    assert_eq!("synthetic-operator", signed_in.claims.subject);
    assert_eq!(Some("operator.one"), signed_in.claims.display_name());
    assert_eq!(
        Some(&serde_json::json!(["mapping-admin"])),
        signed_in.claims.other.get("roles")
    );
    let rendered = format!("{signed_in:?}");
    for secret in ["synthetic-access-1", "synthetic-refresh-1", token.as_str()] {
        assert!(!rendered.contains(secret), "{rendered}");
    }
}

#[tokio::test]
async fn an_ml_dsa_id_token_verifies_when_the_client_accepts_its_algorithm() {
    for algorithm in [Algorithm::MlDsa44, Algorithm::MlDsa65, Algorithm::MlDsa87] {
        let key = crate::support::ml_dsa_key("op-pq", algorithm);
        let (issuer, client) = provider(&key).await;
        let request = client.authorization_request().expect("a sign-in is minted");
        let pending = request.pending;
        let token = id_token(&issuer, &key, pending.nonce());
        mount_exchange(&issuer, pending.verifier().expose(), &token).await;
        let callback = Callback::granted("synthetic-code", pending.state());
        assert!(
            matches!(
                client.exchange(&pending, &callback).await,
                Err(OidcError::Key)
            ),
            "{algorithm} outside the default set"
        );
        let client = client.with_algorithms([Algorithm::Es256, algorithm]);
        let signed_in = client
            .exchange(&pending, &callback)
            .await
            .expect("the ML-DSA ID Token verifies (RFC 9964)");
        assert_eq!(
            "synthetic-operator", signed_in.claims.subject,
            "{algorithm}"
        );
    }
}

#[tokio::test]
async fn a_state_mismatch_is_refused_before_the_token_endpoint_is_called() {
    let key = ec_key("op-1", Algorithm::Es256);
    let (issuer, client) = provider(&key).await;
    let pending = client.authorization_request().expect("a sign-in").pending;
    mount_invalid_grant(&issuer).await;
    for callback in [
        Callback::granted("synthetic-code", "another-state"),
        Callback::refused("access_denied", "another-state"),
        Callback::default(),
    ] {
        let refused = client.exchange(&pending, &callback).await;
        assert!(
            matches!(refused, Err(OidcError::StateMismatch)),
            "{refused:?}"
        );
        assert!(refused.is_err_and(|error| error.refuses_the_operator()));
    }
    assert_eq!(0, issuer.reads(TOKEN_PATH).await);
}

#[tokio::test]
async fn a_pkce_mismatch_is_refused_with_the_providers_error_code() {
    let key = ec_key("op-1", Algorithm::Es256);
    let (issuer, client) = provider(&key).await;
    let pending = client.authorization_request().expect("a sign-in").pending;
    mount_exchange(&issuer, pending.verifier().expose(), "unused").await;
    let forged = PendingSignIn::from_parts(
        pending.state().to_owned(),
        pending.nonce().to_owned(),
        Secret::new("a-verifier-of-another-sign-in-0000000000000"),
    );
    let refused = client
        .exchange(
            &forged,
            &Callback::granted("synthetic-code", pending.state()),
        )
        .await
        .expect_err("the provider refuses another verifier");
    assert_eq!(Some("invalid_grant"), refused.oauth_error());
    assert_eq!(Some(http::StatusCode::BAD_REQUEST), refused.status());
    assert!(refused.is_answered_refusal());
}

#[tokio::test]
async fn a_refused_authorization_carries_the_error_code() {
    let key = ec_key("op-1", Algorithm::Es256);
    let (issuer, client) = provider(&key).await;
    let pending = client.authorization_request().expect("a sign-in").pending;
    let refused = client
        .exchange(
            &pending,
            &Callback::refused("access_denied", pending.state()),
        )
        .await
        .expect_err("the redirect carries an error");
    assert_eq!(Some("access_denied"), refused.oauth_error());
    assert_eq!(0, issuer.reads(TOKEN_PATH).await);
    let no_code = client
        .exchange(&pending, &Callback::granted("", pending.state()))
        .await;
    assert!(no_code.is_err(), "an empty code is refused by the provider");
}

#[tokio::test]
async fn an_id_token_with_another_nonce_audience_or_key_is_refused() {
    let key = ec_key("op-1", Algorithm::Es256);
    let (issuer, client) = provider(&key).await;
    let pending = client.authorization_request().expect("a sign-in").pending;
    let callback = Callback::granted("synthetic-code", pending.state());

    let replayed = id_token(&issuer, &key, "a-nonce-of-another-sign-in");
    mount_exchange(&issuer, pending.verifier().expose(), &replayed).await;
    let refused = client.exchange(&pending, &callback).await;
    assert!(matches!(refused, Err(OidcError::Nonce)), "{refused:?}");

    issuer.server.reset().await;
    issuer.mount_keys(&[&key], None).await;
    let stranger = ec_key("op-2", Algorithm::Es256);
    let unknown = id_token(&issuer, &stranger, pending.nonce());
    mount_exchange(&issuer, pending.verifier().expose(), &unknown).await;
    let refused = client.exchange(&pending, &callback).await;
    assert!(matches!(refused, Err(OidcError::Key)), "{refused:?}");

    issuer.server.reset().await;
    issuer.mount_keys(&[&key], None).await;
    let now = now();
    let mut header = Header::new(key.alg);
    header.kid = Some(key.kid.clone());
    let wide = mint_with(
        &key,
        &header,
        &serde_json::json!({
            "iss": issuer.uri(), "aud": [CLIENT, "another-client"], "sub": "synthetic-operator",
            "nonce": pending.nonce(), "iat": now, "exp": now + 300
        }),
    );
    mount_exchange(&issuer, pending.verifier().expose(), &wide).await;
    let refused = client.exchange(&pending, &callback).await;
    assert!(matches!(refused, Err(OidcError::Audience)), "{refused:?}");
}

/// An ID Token for this client carrying `nonce` and `iat` (none when
/// `None`), signed by `key` with `kid` in its header.
fn id_token_with(
    issuer: &Issuer,
    key: &SigningKey,
    kid: Option<&str>,
    nonce: &str,
    iat: Option<serde_json::Value>,
) -> String {
    let now = now();
    let mut header = Header::new(key.alg);
    header.kid = kid.map(str::to_owned);
    let mut claims = serde_json::json!({
        "iss": issuer.uri(), "aud": CLIENT, "sub": "synthetic-operator",
        "nonce": nonce, "exp": now + 300
    });
    if let Some(iat) = iat {
        claims
            .as_object_mut()
            .expect("the claims are an object")
            .insert("iat".to_owned(), iat);
    }
    mint_with(key, &header, &claims)
}

// NOTE: OpenID Connect Core 1.0 §2: `iat` is REQUIRED in an ID Token, a NumericDate.
#[tokio::test]
async fn an_id_token_without_a_numeric_iat_is_refused() {
    let key = ec_key("op-1", Algorithm::Es256);
    let (issuer, client) = provider(&key).await;
    let pending = client.authorization_request().expect("a sign-in").pending;
    let callback = Callback::granted("synthetic-code", pending.state());
    for iat in [
        None,
        Some(serde_json::json!("1700000000")),
        Some(serde_json::Value::Null),
    ] {
        issuer.server.reset().await;
        issuer.mount_keys(&[&key], None).await;
        let token = id_token_with(&issuer, &key, Some(&key.kid), pending.nonce(), iat.clone());
        mount_exchange(&issuer, pending.verifier().expose(), &token).await;
        let refused = client.exchange(&pending, &callback).await;
        assert!(
            matches!(refused, Err(OidcError::IdToken { .. })),
            "iat {iat:?}: {refused:?}"
        );
    }
    issuer.server.reset().await;
    issuer.mount_keys(&[&key], None).await;
    let fractional = serde_json::json!(f64::from(u32::try_from(now()).expect("before 2106")) + 0.5);
    let token = id_token_with(
        &issuer,
        &key,
        Some(&key.kid),
        pending.nonce(),
        Some(fractional),
    );
    mount_exchange(&issuer, pending.verifier().expose(), &token).await;
    client
        .exchange(&pending, &callback)
        .await
        .expect("a NumericDate with a fraction is an iat");
}

// NOTE: RFC 7515 §4.1.4 makes `kid` OPTIONAL and OpenID Connect Core 1.0 §10.1 asks
// for one among several keys: without it, the set's one key that fits the algorithm.
#[tokio::test]
async fn without_a_kid_the_one_key_that_fits_the_algorithm_verifies() {
    let signer = rsa_key("op-rsa", Algorithm::Rs256);
    let (issuer, client) = provider(&signer).await;
    let pending = client.authorization_request().expect("a sign-in").pending;
    let callback = Callback::granted("synthetic-code", pending.state());
    let token = id_token_with(&issuer, &signer, None, pending.nonce(), Some(now().into()));

    let p256 = ec_key("op-p256", Algorithm::Es256);
    let ed25519 = ed_key("op-ed25519");
    let mut encryption = rsa_key("op-rsa-enc", Algorithm::Rs256);
    encryption
        .jwk
        .as_object_mut()
        .expect("a JWK is an object")
        .insert("use".to_owned(), serde_json::json!("enc"));
    let mut wrapping = rsa_key("op-rsa-wrap", Algorithm::Rs256);
    wrapping
        .jwk
        .as_object_mut()
        .expect("a JWK is an object")
        .insert("key_ops".to_owned(), serde_json::json!(["wrapKey"]));
    let mut other_alg = rsa_key("op-rsa-384", Algorithm::Rs384);
    other_alg
        .jwk
        .as_object_mut()
        .expect("a JWK is an object")
        .insert("alg".to_owned(), serde_json::json!("RS384"));
    issuer.server.reset().await;
    issuer
        .mount_keys(
            &[&p256, &encryption, &ed25519, &signer, &wrapping, &other_alg],
            None,
        )
        .await;
    mount_exchange(&issuer, pending.verifier().expose(), &token).await;
    let signed_in = client
        .exchange(&pending, &callback)
        .await
        .expect("the one RS256 signing key verifies the token");
    assert_eq!("synthetic-operator", signed_in.claims.subject);

    let second = rsa_key("op-rsa-2", Algorithm::Rs256);
    issuer.server.reset().await;
    issuer.mount_keys(&[&signer, &second, &p256], None).await;
    mount_exchange(&issuer, pending.verifier().expose(), &token).await;
    let refused = client.exchange(&pending, &callback).await;
    assert!(
        matches!(refused, Err(OidcError::Key)),
        "two keys fit: {refused:?}"
    );

    let p384 = ec_key("op-p384", Algorithm::Es384);
    let on_p384 = id_token_with(&issuer, &p384, None, pending.nonce(), Some(now().into()));
    issuer.server.reset().await;
    issuer.mount_keys(&[&signer, &p256], None).await;
    mount_exchange(&issuer, pending.verifier().expose(), &on_p384).await;
    let refused = client.exchange(&pending, &callback).await;
    assert!(
        matches!(refused, Err(OidcError::Key)),
        "no key fits: {refused:?}"
    );
}

// NOTE: OpenID Connect Core 1.0 §3.1.3.7 items 3 and 4: an audience the client trusts
// beside itself is accepted, and several audiences need an `azp` naming the client.
#[tokio::test]
async fn a_trusted_audience_is_accepted_with_an_azp_naming_the_client() {
    let key = ec_key("op-1", Algorithm::Es256);
    let (issuer, client) = provider(&key).await;
    let client = client.with_trusted_audiences(["synthetic-project"]);
    let pending = client.authorization_request().expect("a sign-in").pending;
    let callback = Callback::granted("synthetic-code", pending.state());
    let now = now();
    let mut header = Header::new(key.alg);
    header.kid = Some(key.kid.clone());
    let mint = |claims: serde_json::Value| mint_with(&key, &header, &claims);
    let base = serde_json::json!({
        "iss": issuer.uri(), "aud": [CLIENT, "synthetic-project"], "sub": "synthetic-operator",
        "nonce": pending.nonce(), "iat": now, "exp": now + 300
    });

    let mut with_azp = base.clone();
    with_azp["azp"] = serde_json::json!(CLIENT);
    mount_exchange(&issuer, pending.verifier().expose(), &mint(with_azp)).await;
    let signed_in = client.exchange(&pending, &callback).await;
    assert!(signed_in.is_ok(), "{signed_in:?}");

    issuer.server.reset().await;
    issuer.mount_keys(&[&key], None).await;
    mount_exchange(&issuer, pending.verifier().expose(), &mint(base.clone())).await;
    let refused = client.exchange(&pending, &callback).await;
    assert!(
        matches!(refused, Err(OidcError::AuthorizedParty)),
        "{refused:?}"
    );

    issuer.server.reset().await;
    issuer.mount_keys(&[&key], None).await;
    let mut stranger = base;
    stranger["aud"] = serde_json::json!([CLIENT, "synthetic-project", "another-client"]);
    stranger["azp"] = serde_json::json!(CLIENT);
    mount_exchange(&issuer, pending.verifier().expose(), &mint(stranger)).await;
    let refused = client.exchange(&pending, &callback).await;
    assert!(matches!(refused, Err(OidcError::Audience)), "{refused:?}");
}

#[tokio::test]
async fn the_refresh_grant_rotates_the_tokens_and_a_refusal_carries_its_code() {
    let key = ec_key("op-1", Algorithm::Es256);
    let (issuer, client) = provider(&key).await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path(TOKEN_PATH))
        .and(matchers::body_string_contains("grant_type=refresh_token"))
        .and(matchers::body_string_contains(
            "refresh_token=synthetic-refresh-1",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "synthetic-access-2",
            "token_type": "bearer",
            "expires_in": 600,
            "refresh_token": "synthetic-refresh-2",
            "scope": "openid profile"
        })))
        .with_priority(1)
        .mount(&issuer.server)
        .await;
    mount_invalid_grant(&issuer).await;
    let refreshed = client
        .refresh(&Secret::new("synthetic-refresh-1"))
        .await
        .expect("the refresh completes");
    assert_eq!("synthetic-access-2", refreshed.access_token.expose());
    assert_eq!(
        Some("synthetic-refresh-2"),
        refreshed.refresh_token.as_ref().map(Secret::expose)
    );
    assert_eq!(Some(Duration::from_secs(600)), refreshed.expires_in);
    assert_eq!(
        Some(vec![String::from("openid"), String::from("profile")]),
        refreshed.scopes
    );
    let refused = client
        .refresh(&Secret::new("synthetic-spent-token"))
        .await
        .expect_err("a spent refresh token is refused");
    assert_eq!(Some("invalid_grant"), refused.oauth_error());
    assert!(
        refused.is_answered_refusal(),
        "a refused refresh ends the session"
    );
    assert!(!refused.to_string().contains("synthetic-spent-token"));
}

#[tokio::test]
async fn a_refresh_for_a_resource_names_it_and_a_refused_target_carries_its_code() {
    let key = ec_key("op-1", Algorithm::Es256);
    let (issuer, client) = provider(&key).await;
    // NOTE: RFC 8707 §2.2, `resource` on a refresh_token request names the target.
    Mock::given(matchers::method("POST"))
        .and(matchers::path(TOKEN_PATH))
        .and(matchers::body_string_contains("grant_type=refresh_token"))
        .and(matchers::body_string_contains(
            "refresh_token=synthetic-refresh-1",
        ))
        .and(matchers::body_string_contains(
            "resource=https%3A%2F%2Fehr.example.org%2Ffhir",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "synthetic-fhir-1",
            "token_type": "bearer",
            "expires_in": 300,
            "refresh_token": "synthetic-refresh-2"
        })))
        .with_priority(1)
        .mount(&issuer.server)
        .await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path(TOKEN_PATH))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(serde_json::json!({ "error": "invalid_target" })),
        )
        .with_priority(2)
        .mount(&issuer.server)
        .await;
    let refreshed = client
        .refresh_for(
            &Secret::new("synthetic-refresh-1"),
            "https://ehr.example.org/fhir",
        )
        .await
        .expect("the refresh completes");
    assert_eq!("synthetic-fhir-1", refreshed.access_token.expose());
    assert_eq!(
        Some("synthetic-refresh-2"),
        refreshed.refresh_token.as_ref().map(Secret::expose)
    );
    let refused = client
        .refresh_for(
            &Secret::new("synthetic-refresh-1"),
            "https://other.example.org/fhir",
        )
        .await
        .expect_err("an unknown resource is refused");
    assert_eq!(Some("invalid_target"), refused.oauth_error(), "RFC 8707 §2");
}

#[tokio::test]
async fn a_provider_failing_on_its_side_is_no_answered_refusal() {
    let key = ec_key("op-1", Algorithm::Es256);
    let (issuer, client) = provider(&key).await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path(TOKEN_PATH))
        .respond_with(ResponseTemplate::new(503))
        .mount(&issuer.server)
        .await;
    let failed = client
        .refresh(&Secret::new("synthetic-refresh-1"))
        .await
        .expect_err("the provider fails");
    assert_eq!(Some(http::StatusCode::SERVICE_UNAVAILABLE), failed.status());
    assert_eq!(None, failed.oauth_error());
    assert!(
        !failed.is_answered_refusal(),
        "the session stays for a retry"
    );
}

#[tokio::test]
async fn logout_names_the_hint_and_the_redirect_and_revocation_posts_the_token() {
    let key = ec_key("op-1", Algorithm::Es256);
    let (issuer, client) = provider(&key).await;
    let hint = Secret::new("synthetic-id-token");
    let url = client
        .end_session_url(Some(&hint), Some("synthetic-logout-state"))
        .expect("the provider publishes an end-session endpoint");
    assert_eq!(
        format!("{}/logout", issuer.uri()),
        format!("{}://{}{}", url.scheme(), url.authority(), url.path())
    );
    let sent = query(&url);
    assert_eq!(
        Some("synthetic-id-token"),
        sent.get("id_token_hint").map(String::as_str)
    );
    assert_eq!(Some(CLIENT), sent.get("client_id").map(String::as_str));
    assert_eq!(
        Some("https://console.example.org/"),
        sent.get("post_logout_redirect_uri").map(String::as_str)
    );
    assert_eq!(
        Some("synthetic-logout-state"),
        sent.get("state").map(String::as_str)
    );

    Mock::given(matchers::method("POST"))
        .and(matchers::path("/revoke"))
        .and(matchers::body_string_contains("token=synthetic-refresh-1"))
        .and(matchers::body_string_contains(
            "token_type_hint=refresh_token",
        ))
        .respond_with(ResponseTemplate::new(200))
        .with_priority(1)
        .mount(&issuer.server)
        .await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/revoke"))
        .respond_with(ResponseTemplate::new(503))
        .with_priority(5)
        .mount(&issuer.server)
        .await;
    client
        .revoke(
            &Secret::new("synthetic-refresh-1"),
            TokenTypeHint::RefreshToken,
        )
        .await
        .expect("the provider revokes the token");
    let refused = client
        .revoke(
            &Secret::new("synthetic-access-1"),
            TokenTypeHint::AccessToken,
        )
        .await;
    assert!(
        matches!(refused, Err(OidcError::Revocation { status }) if status == http::StatusCode::SERVICE_UNAVAILABLE),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_provider_without_an_end_session_endpoint_has_no_logout_url() {
    let key = ec_key("op-1", Algorithm::Es256);
    let issuer = Issuer::start(&[&key]).await;
    let http = Http::new(Duration::from_secs(5)).expect("the engine builds");
    let discovered = Provider::discover(&http, &issuer.uri())
        .await
        .expect("the provider is discovered");
    let client = RelyingParty::new(
        http,
        discovered,
        CLIENT,
        Url::parse(REDIRECT).expect("a URL"),
    );
    assert_eq!(None, client.end_session_url(None, None));
    client
        .revoke(
            &Secret::new("synthetic-access-1"),
            TokenTypeHint::AccessToken,
        )
        .await
        .expect("no revocation endpoint is no failure");
}

/// A Logout Token for this client, with `claims` over the valid set, signed
/// by `key` and typed `logout+jwt`.
fn logout_token(issuer: &Issuer, key: &SigningKey, claims: &serde_json::Value) -> String {
    let now = now();
    let mut body = serde_json::json!({
        "iss": issuer.uri(),
        "aud": CLIENT,
        "sub": "synthetic-operator",
        "sid": "synthetic-session",
        "iat": now,
        "exp": now + 120,
        "jti": "synthetic-logout-1",
        "events": { ferrohealth_smart::oidc::logout::BACKCHANNEL_LOGOUT_EVENT: {} }
    });
    if let (Some(base), Some(over)) = (body.as_object_mut(), claims.as_object()) {
        for (name, value) in over {
            if value.is_null() && name != "nonce" {
                base.remove(name);
            } else {
                base.insert(name.clone(), value.clone());
            }
        }
    }
    let mut header = Header::new(key.alg);
    header.kid = Some(key.kid.clone());
    header.typ = Some(String::from("logout+jwt"));
    mint_with(key, &header, &body)
}

#[tokio::test]
async fn a_logout_token_is_checked_and_its_session_returned() {
    let key = ec_key("op-1", Algorithm::Es256);
    let (issuer, client) = provider(&key).await;
    let token = logout_token(&issuer, &key, &serde_json::json!({}));
    let claims = client.logout_token(&token).await.expect("a valid token");
    assert_eq!(issuer.uri(), claims.issuer);
    assert_eq!(Some("synthetic-operator"), claims.subject.as_deref());
    assert_eq!(Some("synthetic-session"), claims.session.as_deref());
    assert_eq!("synthetic-logout-1", claims.jti);
    assert!(!format!("{claims:?}").contains("synthetic-operator"));
    // NOTE: Back-Channel Logout 1.0 §2.4, sub or sid or both.
    let sid_only = logout_token(&issuer, &key, &serde_json::json!({"sub": null}));
    let claims = client.logout_token(&sid_only).await.expect("a valid token");
    assert_eq!(None, claims.subject);
}

#[tokio::test]
async fn a_logout_token_breaking_section_2_6_is_refused() {
    let key = ec_key("op-1", Algorithm::Es256);
    let (issuer, client) = provider(&key).await;
    let now = now();
    // NOTE: Back-Channel Logout 1.0 §2.6: each check refuses the token.
    let cases = [
        (
            serde_json::json!({"sub": null, "sid": null}),
            "neither sub nor sid",
        ),
        (serde_json::json!({"events": {}}), "no logout event"),
        (
            serde_json::json!({"events": {"http://schemas.openid.net/event/backchannel-logout": "yes"}}),
            "an event that is not an object",
        ),
        (serde_json::json!({"nonce": "n-1"}), "a nonce"),
        (
            serde_json::json!({"nonce": null}),
            "a null nonce is still a nonce",
        ),
        (
            serde_json::json!({"aud": "another-client"}),
            "another audience",
        ),
        (
            serde_json::json!({"aud": [CLIENT, "another-client"]}),
            "an audience beyond the client",
        ),
        (
            serde_json::json!({"iss": "https://other.example.org"}),
            "another issuer",
        ),
        (serde_json::json!({"exp": now - 600}), "expired"),
        (serde_json::json!({"iat": null}), "no iat"),
        (serde_json::json!({"jti": null}), "no jti"),
    ];
    for (claims, case) in cases {
        let token = logout_token(&issuer, &key, &claims);
        assert!(
            matches!(
                client.logout_token(&token).await,
                Err(OidcError::LogoutClaims { .. }
                    | OidcError::LogoutToken { .. }
                    | OidcError::Audience)
            ),
            "{case}"
        );
    }
    let stranger = ec_key("op-1", Algorithm::Es256);
    let forged = logout_token(&issuer, &stranger, &serde_json::json!({}));
    assert!(
        matches!(
            client.logout_token(&forged).await,
            Err(OidcError::LogoutToken { .. })
        ),
        "a key the provider does not hold under its kid"
    );
}

/// Returns the form fields of every request `issuer` received at `path`.
async fn forms(issuer: &Issuer, path: &str) -> Vec<BTreeMap<String, String>> {
    issuer
        .server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|request| request.url.path() == path)
        .map(|request| {
            url::form_urlencoded::parse(&request.body)
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect()
        })
        .collect()
}

// NOTE: OpenID Connect Core 1.0 §9, private_key_jwt; RFC 10070 §4; RFC 7515 §4.1.8.
/// Returns the P-256 public JWK of the uncompressed point `point` (SEC 1
/// §2.3.3, RFC 7518 §6.2.1).
fn p256_jwk(point: &[u8]) -> serde_json::Value {
    let coordinate = |range: std::ops::Range<usize>| {
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            point.get(range).expect("an uncompressed P-256 point"),
        )
    };
    serde_json::json!({
        "kty": "EC", "crv": "P-256", "x": coordinate(1..33), "y": coordinate(33..65)
    })
}

#[tokio::test]
async fn a_private_key_jwt_client_sends_a_fresh_assertion_at_every_call() {
    let key = ec_key("op-1", Algorithm::Es256);
    let (issuer, client) = unauthenticated(&key).await;
    let pair = rcgen::KeyPair::generate().expect("a key");
    let certificate = rcgen::CertificateParams::new(vec![String::from("smart.example.org")])
        .expect("parameters")
        .self_signed(&pair)
        .expect("a certificate");
    let signer = AssertionKey::from_pem(pair.serialize_pem().as_bytes(), None, None)
        .expect("a key")
        .with_certificate(certificate.pem().as_bytes())
        .expect("the certificate names the key");
    let public = p256_jwk(pair.public_key_raw());
    let client = client.with_private_key_jwt(signer);
    let request = client.authorization_request().expect("a sign-in is minted");
    let pending = request.pending;
    let token = id_token(&issuer, &key, pending.nonce());
    Mock::given(matchers::method("POST"))
        .and(matchers::path(TOKEN_PATH))
        .and(matchers::body_string_contains(
            "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "synthetic-access-1", "token_type": "Bearer", "id_token": token
        })))
        .mount(&issuer.server)
        .await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/revoke"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&issuer.server)
        .await;
    client
        .exchange(
            &pending,
            &Callback::granted("synthetic-code", pending.state()),
        )
        .await
        .expect("the sign-in completes");
    client
        .revoke(
            &Secret::new("synthetic-access-1"),
            TokenTypeHint::AccessToken,
        )
        .await
        .expect("the provider revokes the token");

    let sent: Vec<_> = forms(&issuer, TOKEN_PATH)
        .await
        .into_iter()
        .chain(forms(&issuer, "/revoke").await)
        .collect();
    assert_eq!(2, sent.len(), "the exchange and the revocation");
    let mut ids = Vec::new();
    for form in &sent {
        assert_eq!(Some(CLIENT), form.get("client_id").map(String::as_str));
        let assertion = form.get("client_assertion").expect("an assertion");
        let header = crate::support::header(assertion);
        assert_eq!(Some("client-authentication+jwt"), header.typ.as_deref());
        let thumbprint = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, certificate.der());
        assert_eq!(
            Some(base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                thumbprint.as_ref()
            )),
            header.x5t_s256
        );
        assert_eq!(Algorithm::Es256, header.alg);
        let claims = crate::support::verified(assertion, &public);
        Validation::default()
            .with_audiences([issuer.uri()])
            .with_issuer(CLIENT)
            .with_required(&["exp", "sub"])
            .check(&claims)
            .expect("the assertion verifies, for the issuer");
        assert_eq!(
            serde_json::json!(issuer.uri()),
            claims["aud"],
            "the issuer identifier as the sole audience, a string"
        );
        assert_eq!(serde_json::json!(CLIENT), claims["sub"]);
        ids.push(claims["jti"].as_str().expect("a jti").to_owned());
    }
    assert_ne!(ids[0], ids[1], "one assertion per request");
    assert!(
        issuer
            .server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .all(|request| !request.headers.contains_key("authorization")),
        "no secret beside the assertion"
    );
}
