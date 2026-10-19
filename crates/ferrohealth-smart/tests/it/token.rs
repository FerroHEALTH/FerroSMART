// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The token check: a valid token names its caller, and every token that
//! does not hold is the same [`Rejection::Invalid`], whose reason reaches
//! the debug log and never the caller.

use std::error::Error as StdError;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use ferrohealth_smart::metadata::DiscoveryError;
use ferrohealth_smart::refusal::Refusal;
use ferrohealth_smart::resource::Caller;
use ferrohealth_smart::resource::Compartment;
use ferrohealth_smart::resource::IssuerSet;
use ferrohealth_smart::resource::Rejection;
use ferrohealth_smart::resource::ResourceError;
use ferrohealth_smart::resource::ResourceServer;
use ferrohealth_smart::resource::Settings;
use ferrohealth_smart::resource::TokenProfile;
use ferrohealth_smart::resource::Verifier;
use ferrohealth_smart::resource::Via;
use ferrohealth_smart::resource::configuration::SmartOptions;
use ferrohealth_smart::scope::Permission;
use jsonwebtoken::Algorithm;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;

use crate::support::AUDIENCE;
use crate::support::Issuer;
use crate::support::JWKS_PATH;
use crate::support::SigningKey;
use crate::support::ec_key;
use crate::support::ed_key;
use crate::support::mint;
use crate::support::mint_with;
use crate::support::now;
use crate::support::rsa_key;
use crate::support::server;
use crate::support::temp_file;

/// Asserts that `outcome` is the one refusal of an invalid token, naming no
/// claim value in its display.
fn assert_invalid(outcome: &Result<Caller, Rejection>, case: &str) {
    match outcome {
        Err(Rejection::Invalid { reason }) => {
            let text = Refusal::from(&Rejection::Invalid { reason }).reason();
            assert_eq!("invalid_token", text, "{case}");
            for value in [AUDIENCE, "synthetic-client-sub", "synthetic-client"] {
                assert!(
                    !reason.contains(value),
                    "{case}: the reason carries {value}"
                );
            }
        }
        other => panic!("{case}: expected the invalid-token rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn a_valid_token_names_its_caller_and_claims() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let server = server(issuer.settings()).await;
    let mut claims = issuer.claims("openid system/Condition.rs __operator");
    claims["patient"] = serde_json::json!("p-1");
    claims["fhirUser"] = serde_json::json!("Practitioner/42");
    let caller = server.authenticate(&mint(&key, &claims)).await?;
    assert_eq!("synthetic-client-sub", caller.subject());
    assert_eq!(Some("synthetic-client"), caller.client_id());
    assert_eq!(Some("p-1"), caller.patient());
    assert_eq!(Via::Bearer, caller.via());
    assert_eq!(Some(issuer.uri().as_str()), caller.issuer());
    assert!(caller.has_scope("__operator"));
    assert!(caller.has_scope("openid"));
    assert_eq!(
        Some(Compartment::Any),
        caller.reach(Permission::Read, "Condition")
    );
    assert_eq!(None, caller.reach(Permission::Create, "Condition"));
    assert_eq!(
        Some(&serde_json::json!("Practitioner/42")),
        caller.claim("fhirUser")
    );
    assert_eq!(
        Some(&serde_json::json!("synthetic-jti-1")),
        caller.claim("jti")
    );
    Ok(())
}

#[tokio::test]
async fn every_asymmetric_algorithm_of_the_default_set_verifies() -> Result<(), Box<dyn StdError>> {
    let keys: Vec<SigningKey> = vec![
        rsa_key("rs256", Algorithm::RS256),
        rsa_key("rs384", Algorithm::RS384),
        rsa_key("ps256", Algorithm::PS256),
        rsa_key("ps384", Algorithm::PS384),
        ec_key("es256", Algorithm::ES256),
        ec_key("es384", Algorithm::ES384),
    ];
    let refs: Vec<&SigningKey> = keys.iter().collect();
    let issuer = Issuer::start(&refs).await;
    let server = server(issuer.settings()).await;
    for key in &keys {
        let caller = server
            .authenticate(&mint(key, &issuer.claims("system/Condition.r")))
            .await;
        assert!(caller.is_ok(), "{:?}: {caller:?}", key.alg);
    }
    Ok(())
}

#[tokio::test]
async fn eddsa_verifies_only_when_configured() -> Result<(), Box<dyn StdError>> {
    let key = ed_key("ed");
    let issuer = Issuer::start(&[&key]).await;
    let token = mint(&key, &issuer.claims("system/Condition.r"));
    let default = server(issuer.settings()).await;
    assert_invalid(
        &default.authenticate(&token).await,
        "EdDSA outside the default set",
    );
    let mut settings = issuer.settings();
    settings.algorithms.push(Algorithm::EdDSA);
    let configured = server(settings).await;
    assert!(configured.authenticate(&token).await.is_ok());
    Ok(())
}

#[tokio::test]
async fn every_invalid_claim_set_is_the_same_rejection() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let server = server(issuer.settings()).await;
    let now = now();
    let mut expired = issuer.claims("system/Condition.r");
    expired["iat"] = serde_json::json!(now - 7200);
    expired["exp"] = serde_json::json!(now - 3600);
    let mut early = issuer.claims("system/Condition.r");
    early["nbf"] = serde_json::json!(now + 3600);
    let mut foreign_issuer = issuer.claims("system/Condition.r");
    foreign_issuer["iss"] = serde_json::json!("https://another-issuer.invalid");
    let mut foreign_audience = issuer.claims("system/Condition.r");
    foreign_audience["aud"] = serde_json::json!("https://another-server.invalid/fhir");
    let mut no_audience = issuer.claims("system/Condition.r");
    no_audience
        .as_object_mut()
        .ok_or("claims are an object")?
        .remove("aud");
    let mut future = issuer.claims("system/Condition.r");
    future["iat"] = serde_json::json!(now + 3600);
    let mut no_client = issuer.claims("system/Condition.r");
    no_client
        .as_object_mut()
        .ok_or("claims are an object")?
        .remove("client_id");
    let mut no_subject = issuer.claims("system/Condition.r");
    no_subject
        .as_object_mut()
        .ok_or("claims are an object")?
        .remove("sub");
    let mut no_expiry = issuer.claims("system/Condition.r");
    no_expiry
        .as_object_mut()
        .ok_or("claims are an object")?
        .remove("exp");
    for (case, claims) in [
        ("expired", expired),
        ("not yet valid", early),
        ("another issuer", foreign_issuer),
        ("another audience", foreign_audience),
        ("no audience", no_audience),
        ("issued in the future", future),
        ("no client_id under RFC 9068", no_client),
        ("no sub", no_subject),
        ("no exp", no_expiry),
    ] {
        assert_invalid(&server.authenticate(&mint(&key, &claims)).await, case);
    }
    Ok(())
}

#[tokio::test]
async fn the_audience_list_admits_any_of_its_members() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let mut settings = issuer.settings();
    settings
        .audience
        .push(String::from("http://ferro.invalid/r4b"));
    let server = server(settings).await;
    let mut second = issuer.claims("system/Condition.r");
    second["aud"] = serde_json::json!("http://ferro.invalid/r4b");
    assert!(server.authenticate(&mint(&key, &second)).await.is_ok());
    let mut array = issuer.claims("system/Condition.r");
    array["aud"] = serde_json::json!(["https://other.invalid", AUDIENCE]);
    assert!(server.authenticate(&mint(&key, &array)).await.is_ok());
    let mut neither = issuer.claims("system/Condition.r");
    neither["aud"] = serde_json::json!(["https://other.invalid"]);
    assert_invalid(
        &server.authenticate(&mint(&key, &neither)).await,
        "no member",
    );
    Ok(())
}

#[tokio::test]
async fn the_clock_skew_admits_a_token_just_expired() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 7519 §4.1.4, "implementers MAY provide for some small leeway,
    // usually no more than a few minutes, to account for clock skew".
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let mut settings = issuer.settings();
    settings.clock_skew = Duration::from_secs(120);
    let server = server(settings).await;
    let mut claims = issuer.claims("system/Condition.r");
    claims["exp"] = serde_json::json!(now() - 60);
    assert!(server.authenticate(&mint(&key, &claims)).await.is_ok());
    let strict = {
        let mut settings = issuer.settings();
        settings.clock_skew = Duration::ZERO;
        crate::support::server(settings).await
    };
    assert_invalid(&strict.authenticate(&mint(&key, &claims)).await, "no skew");
    Ok(())
}

#[tokio::test]
async fn a_token_signed_by_another_key_under_a_known_kid_is_refused()
-> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let forger = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let server = server(issuer.settings()).await;
    let token = mint(&forger, &issuer.claims("system/Condition.r"));
    assert_invalid(&server.authenticate(&token).await, "forged signature");
    Ok(())
}

#[tokio::test]
async fn an_algorithm_outside_the_configured_set_is_refused() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k384", Algorithm::ES384);
    let issuer = Issuer::start(&[&key]).await;
    let mut settings = issuer.settings();
    settings.algorithms = vec![Algorithm::ES256];
    let server = server(settings).await;
    let token = mint(&key, &issuer.claims("system/Condition.r"));
    assert_invalid(&server.authenticate(&token).await, "ES384 outside the set");
    Ok(())
}

#[tokio::test]
async fn a_symmetric_token_is_refused() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 8725 §3.1, an HMAC over a published key is the algorithm
    // confusion a verifier closes by refusing every symmetric algorithm.
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let server = server(issuer.settings()).await;
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(String::from("k1"));
    header.typ = Some(String::from("at+jwt"));
    let token = jsonwebtoken::encode(
        &header,
        &issuer.claims("system/Condition.r"),
        &EncodingKey::from_secret(b"synthetic-shared-secret"),
    )?;
    assert_invalid(&server.authenticate(&token).await, "HS256");
    Ok(())
}

#[tokio::test]
async fn settings_that_break_a_rule_refuse_the_start() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let mut hmac = issuer.settings();
    hmac.algorithms.push(Algorithm::HS256);
    let error = ResourceServer::discover(hmac)
        .await
        .err()
        .ok_or("RFC 8725 §3.1 refuses HS256")?;
    assert!(
        matches!(
            error,
            ResourceError::SymmetricAlgorithm {
                algorithm: Algorithm::HS256
            }
        ),
        "{error:?}"
    );
    let mut none = issuer.settings();
    none.algorithms.clear();
    assert!(matches!(
        ResourceServer::discover(none).await,
        Err(ResourceError::NoAlgorithm)
    ));
    let mut skew = issuer.settings();
    skew.clock_skew = Duration::from_secs(301);
    assert!(matches!(
        ResourceServer::discover(skew).await,
        Err(ResourceError::ClockSkew { .. })
    ));
    let mut no_audience = issuer.settings();
    no_audience.audience.clear();
    assert!(matches!(
        ResourceServer::discover(no_audience).await,
        Err(ResourceError::NoAudience)
    ));
    Ok(())
}

#[tokio::test]
async fn an_unsigned_token_is_refused() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 8725 §3.2, the `none` algorithm is refused however the
    // token is otherwise well-formed.
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let server = server(issuer.settings()).await;
    let encode = |value: &serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
    };
    let header = serde_json::json!({ "alg": "none", "typ": "at+jwt", "kid": "k1" });
    let unsigned = format!(
        "{}.{}.",
        encode(&header),
        encode(&issuer.claims("system/Condition.r"))
    );
    assert_invalid(&server.authenticate(&unsigned).await, "alg none");
    Ok(())
}

#[tokio::test]
async fn a_token_that_is_no_jws_is_refused() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let server = server(issuer.settings()).await;
    assert_invalid(&server.authenticate("an-opaque-token").await, "opaque");
    assert_invalid(&server.authenticate("").await, "empty");
    // NOTE: RFC 9068 §4, an encrypted token is decrypted only with keys the
    // resource server registered, and none was; a five-part JWE is refused.
    let jwe = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.a.b.c.d";
    assert_invalid(&server.authenticate(jwe).await, "JWE");
    Ok(())
}

#[tokio::test]
async fn the_typ_rule_of_each_profile() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let claims = issuer.claims("system/Condition.r");
    let with_typ = |typ: Option<&str>| {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(String::from("k1"));
        header.typ = typ.map(str::to_owned);
        mint_with(&key, &header, &claims)
    };
    let strict = server(issuer.settings()).await;
    assert!(strict.authenticate(&with_typ(Some("at+jwt"))).await.is_ok());
    assert!(
        strict
            .authenticate(&with_typ(Some("application/AT+JWT")))
            .await
            .is_ok(),
        "RFC 9068 §4, compared case-insensitively"
    );
    assert_invalid(
        &strict.authenticate(&with_typ(None)).await,
        "no typ under RFC 9068",
    );
    assert_invalid(
        &strict.authenticate(&with_typ(Some("JWT"))).await,
        "JWT under RFC 9068",
    );
    let mut settings = issuer.settings();
    settings.profile = TokenProfile::Jwt;
    let lenient = server(settings).await;
    assert!(lenient.authenticate(&with_typ(None)).await.is_ok());
    assert!(lenient.authenticate(&with_typ(Some("JWT"))).await.is_ok());
    assert!(
        lenient
            .authenticate(&with_typ(Some("at+jwt")))
            .await
            .is_ok()
    );
    assert_invalid(
        &lenient.authenticate(&with_typ(Some("logout+jwt"))).await,
        "another kind under jwt",
    );
    Ok(())
}

#[tokio::test]
async fn the_jwt_profile_needs_no_rfc_9068_claims() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let mut claims = issuer.claims("system/Condition.r");
    let object = claims.as_object_mut().ok_or("claims are an object")?;
    object.remove("client_id");
    object.remove("jti");
    object.remove("iat");
    let token = mint(&key, &claims);
    let strict = server(issuer.settings()).await;
    assert_invalid(&strict.authenticate(&token).await, "no client_id, jti, iat");
    let mut settings = issuer.settings();
    settings.profile = TokenProfile::Jwt;
    let lenient = server(settings).await;
    let caller = lenient.authenticate(&token).await?;
    assert_eq!(None, caller.client_id());
    Ok(())
}

#[tokio::test]
async fn an_unknown_kid_reads_the_key_set_once_more_and_passes() -> Result<(), Box<dyn StdError>> {
    let old = ec_key("old", Algorithm::ES256);
    let rotated = ec_key("rotated", Algorithm::ES256);
    let issuer = Issuer::bare().await;
    issuer
        .mount_metadata("/.well-known/oauth-authorization-server")
        .await;
    issuer.mount_keys(&[&old], Some(1)).await;
    issuer.mount_keys(&[&old, &rotated], None).await;
    let server = server(issuer.settings()).await;
    let token = mint(&rotated, &issuer.claims("system/Condition.r"));
    assert!(server.authenticate(&token).await.is_ok());
    assert_eq!(
        2,
        issuer.reads(JWKS_PATH).await,
        "the boot read and one more"
    );
    Ok(())
}

#[tokio::test]
async fn an_unknown_kid_within_the_interval_reads_nothing_and_is_refused()
-> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let stranger = ec_key("stranger", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let mut settings = issuer.settings();
    settings.jwks_refresh_interval = Duration::from_secs(3600);
    let server = server(settings).await;
    for _ in 0..3 {
        let token = mint(&stranger, &issuer.claims("system/Condition.r"));
        assert_invalid(&server.authenticate(&token).await, "unknown kid");
    }
    assert_eq!(1, issuer.reads(JWKS_PATH).await, "only the boot read");
    Ok(())
}

#[tokio::test]
async fn a_held_set_older_than_its_max_age_is_read_again() -> Result<(), Box<dyn StdError>> {
    let old = ec_key("old", Algorithm::ES256);
    let withdrawn = ec_key("withdrawn", Algorithm::ES256);
    let issuer = Issuer::bare().await;
    issuer
        .mount_metadata("/.well-known/oauth-authorization-server")
        .await;
    issuer.mount_keys(&[&old, &withdrawn], Some(1)).await;
    issuer.mount_keys(&[&old], None).await;
    let mut settings = issuer.settings();
    settings.jwks_max_age = Duration::ZERO;
    settings.jwks_refresh_interval = Duration::from_secs(3600);
    let server = server(settings).await;
    let token = mint(&withdrawn, &issuer.claims("system/Condition.r"));
    assert_invalid(
        &server.authenticate(&token).await,
        "a withdrawn key stops verifying after the max age",
    );
    assert_eq!(
        2,
        issuer.reads(JWKS_PATH).await,
        "the boot read and the max-age read"
    );
    let still = mint(&old, &issuer.claims("system/Condition.r"));
    assert!(server.authenticate(&still).await.is_ok());
    Ok(())
}

#[tokio::test]
async fn a_key_set_that_cannot_be_read_again_is_unavailable_for_an_unknown_key()
-> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let stranger = ec_key("stranger", Algorithm::ES256);
    let issuer = Issuer::bare().await;
    issuer
        .mount_metadata("/.well-known/oauth-authorization-server")
        .await;
    issuer.mount_keys(&[&key], Some(1)).await;
    issuer.mount_failing_keys().await;
    let server = server(issuer.settings()).await;
    let token = mint(&stranger, &issuer.claims("system/Condition.r"));
    let outcome = server.authenticate(&token).await;
    assert!(
        matches!(outcome, Err(Rejection::Unavailable { .. })),
        "{outcome:?}"
    );
    let known = mint(&key, &issuer.claims("system/Condition.r"));
    assert!(
        server.authenticate(&known).await.is_ok(),
        "the held set still serves"
    );
    Ok(())
}

#[tokio::test]
async fn a_token_without_a_kid_verifies_with_the_sets_one_key() -> Result<(), Box<dyn StdError>> {
    // NOTE: RFC 7515 §4.1.4 makes `kid` optional, so the one key of its
    // family verifies it, and none does when the set holds several.
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let server = server(issuer.settings()).await;
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some(String::from("at+jwt"));
    let token = mint_with(&key, &header, &issuer.claims("system/Condition.r"));
    assert!(server.authenticate(&token).await.is_ok());
    let second = ec_key("k2", Algorithm::ES256);
    let two = Issuer::start(&[&key, &second]).await;
    let server = crate::support::server(two.settings()).await;
    let token = mint_with(&key, &header, &two.claims("system/Condition.r"));
    assert_invalid(&server.authenticate(&token).await, "two keys, no kid");
    Ok(())
}

#[tokio::test]
async fn a_key_of_another_use_or_without_verify_is_passed_over() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let mut encryption = ec_key("k1", Algorithm::ES256);
    encryption.jwk["use"] = serde_json::json!("enc");
    let mut signing_only = ec_key("k1", Algorithm::ES256);
    signing_only.jwk["use"] = serde_json::json!("sig");
    signing_only.jwk["key_ops"] = serde_json::json!(["sign"]);
    for (name, published) in [
        ("use enc", &encryption),
        ("key_ops without verify", &signing_only),
    ] {
        let issuer = Issuer::start(&[published]).await;
        let server = server(issuer.settings()).await;
        let token = mint(published, &issuer.claims("system/Condition.r"));
        assert_invalid(&server.authenticate(&token).await, name);
    }
    let issuer = Issuer::start(&[&key]).await;
    assert!(
        server(issuer.settings())
            .await
            .authenticate(&mint(&key, &issuer.claims("")))
            .await
            .is_ok()
    );
    Ok(())
}

#[tokio::test]
async fn a_key_set_file_replaces_discovery() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::bare().await;
    let set = serde_json::json!({ "keys": [key.jwk.clone()] }).to_string();
    let path = temp_file("jwks.json", set.as_bytes());
    let mut settings = issuer.settings();
    settings.jwks_file = Some(path.clone());
    let server = server(settings).await;
    assert_eq!(
        0,
        issuer
            .reads("/.well-known/oauth-authorization-server")
            .await
    );
    assert_eq!(issuer.uri(), server.metadata().issuer);
    assert_eq!(None, server.metadata().jwks_uri);
    let caller = server
        .authenticate(&mint(&key, &issuer.claims("system/Condition.r")))
        .await?;
    assert_eq!("synthetic-client-sub", caller.subject());
    std::fs::remove_file(path)?;
    let mut missing = issuer.settings();
    missing.jwks_file = Some(std::path::PathBuf::from("/nonexistent/ferro.jwks"));
    assert!(matches!(
        ResourceServer::discover(missing).await,
        Err(ResourceError::KeySetFile { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn discovery_falls_back_to_the_openid_connect_location() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::bare().await;
    issuer
        .mount_metadata("/.well-known/openid-configuration")
        .await;
    issuer.mount_keys(&[&key], None).await;
    let server = server(issuer.settings()).await;
    assert_eq!(issuer.uri(), server.metadata().issuer);
    assert_eq!(
        Some(format!("{}/token", issuer.uri())),
        server.metadata().token_endpoint
    );
    Ok(())
}

#[tokio::test]
async fn metadata_naming_another_issuer_no_key_set_or_an_insecure_one_refuses_the_start()
-> Result<(), Box<dyn StdError>> {
    let issuer = Issuer::bare().await;
    let mut foreign = issuer.metadata();
    foreign["issuer"] = serde_json::json!("https://attacker.invalid");
    issuer
        .mount_document("/.well-known/oauth-authorization-server", foreign)
        .await;
    let error = ResourceServer::discover(issuer.settings())
        .await
        .err()
        .ok_or("RFC 8414 §3.3 refuses a mismatched issuer")?;
    assert!(
        matches!(
            error,
            ResourceError::Discovery(DiscoveryError::IssuerMismatch { ref found, .. }) if found == "https://attacker.invalid"
        ),
        "{error:?}"
    );

    let keyless = Issuer::bare().await;
    let mut metadata = keyless.metadata();
    metadata
        .as_object_mut()
        .ok_or("an object")?
        .remove("jwks_uri");
    keyless
        .mount_document("/.well-known/oauth-authorization-server", metadata)
        .await;
    let error = ResourceServer::discover(keyless.settings())
        .await
        .err()
        .ok_or("no jwks_uri, no resource server")?;
    assert!(
        matches!(error, ResourceError::MissingMember { member: "jwks_uri" }),
        "{error:?}"
    );

    let insecure = Issuer::bare().await;
    let mut metadata = insecure.metadata();
    metadata["jwks_uri"] = serde_json::json!("http://keys.example.org/jwks");
    insecure
        .mount_document("/.well-known/oauth-authorization-server", metadata)
        .await;
    let error = ResourceServer::discover(insecure.settings())
        .await
        .err()
        .ok_or("OpenID Connect Discovery 1.0 §3, jwks_uri MUST use https")?;
    assert!(
        matches!(
            error,
            ResourceError::Discovery(DiscoveryError::Insecure {
                what: "the jwks_uri",
                ..
            })
        ),
        "{error:?}"
    );

    let unreachable = Settings::new("http://127.0.0.1:9/realm", AUDIENCE);
    assert!(matches!(
        ResourceServer::discover(unreachable).await,
        Err(ResourceError::Discovery(DiscoveryError::Transport { .. }))
    ));
    let public_http = Settings::new("http://as.example.org/realm", AUDIENCE);
    assert!(matches!(
        ResourceServer::discover(public_http).await,
        Err(ResourceError::Discovery(DiscoveryError::Insecure {
            what: "the issuer",
            ..
        }))
    ));
    Ok(())
}

#[tokio::test]
async fn the_scp_array_is_read_under_the_jwt_profile_alone() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let mut claims = issuer.claims("");
    claims.as_object_mut().ok_or("an object")?.remove("scope");
    claims["scp"] = serde_json::json!(["system/Observation.c", "__operator"]);
    let strict = server(issuer.settings()).await;
    let caller = strict.authenticate(&mint(&key, &claims)).await?;
    assert!(
        !caller.has_scope("__operator"),
        "RFC 9068 §2.2.3 names scope alone"
    );
    assert_eq!(None, caller.reach(Permission::Create, "Observation"));
    let mut settings = issuer.settings();
    settings.profile = TokenProfile::Jwt;
    let lenient = server(settings).await;
    let caller = lenient.authenticate(&mint(&key, &claims)).await?;
    assert!(caller.has_scope("__operator"));
    assert_eq!(
        Some(Compartment::Any),
        caller.reach(Permission::Create, "Observation")
    );
    Ok(())
}

#[tokio::test]
async fn a_scopeless_subject_on_the_allowlist_reaches_everything() -> Result<(), Box<dyn StdError>>
{
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let mut settings = issuer.settings();
    settings
        .scopeless_subjects
        .insert(String::from("synthetic-client-sub"));
    let server = server(settings).await;
    let caller = server
        .authenticate(&mint(&key, &issuer.claims("openid")))
        .await?;
    assert_eq!(
        Some(Compartment::Any),
        caller.reach(Permission::Delete, "Condition")
    );
    Ok(())
}

#[tokio::test]
async fn a_resource_table_narrows_the_clinical_scopes() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let server = ResourceServer::discover(issuer.settings())
        .await?
        .with_resource_types(|name| name == "Condition");
    let caller = server
        .authenticate(&mint(
            &key,
            &issuer.claims("system/Condition.r system/Imaginary.r"),
        ))
        .await?;
    assert!(caller.reach(Permission::Read, "Condition").is_some());
    assert!(caller.reach(Permission::Read, "Imaginary").is_none());
    assert!(
        caller.has_scope("system/Imaginary.r"),
        "the raw scope stays"
    );
    Ok(())
}

#[tokio::test]
async fn an_issuer_set_routes_each_token_to_its_issuer() -> Result<(), Box<dyn StdError>> {
    let one_key = ec_key("one", Algorithm::ES256);
    let two_key = ec_key("two", Algorithm::ES256);
    let one = Issuer::start(&[&one_key]).await;
    let two = Issuer::start(&[&two_key]).await;
    let set: Arc<dyn Verifier> = Arc::new(
        IssuerSet::new()
            .with(server(one.settings()).await)
            .with(server(two.settings()).await),
    );
    let from_one = set
        .verify(&mint(&one_key, &one.claims("system/Condition.r")))
        .await?;
    assert_eq!(Some(one.uri().as_str()), from_one.issuer());
    let from_two = set
        .verify(&mint(&two_key, &two.claims("system/Condition.r")))
        .await?;
    assert_eq!(Some(two.uri().as_str()), from_two.issuer());
    let crossed = mint(&two_key, &one.claims("system/Condition.r"));
    assert_invalid(
        &set.verify(&crossed).await,
        "signed by the other issuer's key",
    );
    let mut stranger = one.claims("system/Condition.r");
    stranger["iss"] = serde_json::json!("https://third.invalid");
    assert_invalid(
        &set.verify(&mint(&one_key, &stranger)).await,
        "an issuer not trusted",
    );
    assert_invalid(&set.verify("opaque").await, "no JWT");
    Ok(())
}

#[tokio::test]
async fn the_smart_configuration_republishes_the_issuer() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::ES256);
    let issuer = Issuer::start(&[&key]).await;
    let server = server(issuer.settings()).await;
    let options = SmartOptions {
        scopes_supported: vec![String::from("system/Condition.rs")],
        capabilities: vec![String::from("launch-ehr")],
        granular: false,
        ..SmartOptions::default()
    };
    let document = server.smart_configuration(&options);
    assert_eq!(serde_json::json!(issuer.uri()), document["issuer"]);
    assert_eq!(
        serde_json::json!(format!("{}/token", issuer.uri())),
        document["token_endpoint"]
    );
    assert_eq!(
        serde_json::json!(["S256"]),
        document["code_challenge_methods_supported"]
    );
    assert_eq!(
        serde_json::json!(["authorization_code", "client_credentials"]),
        document["grant_types_supported"]
    );
    assert_eq!(
        serde_json::json!(["client_secret_basic", "private_key_jwt"]),
        document["token_endpoint_auth_methods_supported"]
    );
    assert_eq!(
        serde_json::json!(["system/Condition.rs"]),
        document["scopes_supported"],
        "the product's scopes, never the issuer's"
    );
    let capabilities = document["capabilities"]
        .as_array()
        .ok_or("capabilities are a list")?;
    for expected in [
        "permission-v1",
        "permission-patient",
        "permission-user",
        "client-confidential-symmetric",
        "client-confidential-asymmetric",
        "launch-standalone",
        "launch-ehr",
    ] {
        assert!(
            capabilities.contains(&serde_json::json!(expected)),
            "{expected}"
        );
    }
    assert!(!capabilities.contains(&serde_json::json!("permission-v2")));
    Ok(())
}
