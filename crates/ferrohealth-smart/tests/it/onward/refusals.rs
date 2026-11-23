// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Every criterion of the onward check against the harness token endpoint,
//! run under the standards-only profile first and then the `entra` and
//! `keycloak` presets, every refusal an asserted typed error.

use ferrohealth_smart::client::TokenError;
use ferrohealth_smart::client::onward::ActorToken;
use ferrohealth_smart::client::onward::OnwardError;
use ferrohealth_smart::client::onward::Rejected;
use ferrohealth_smart::client::onward::SubjectToken;
use ferrohealth_smart::kind::Actor;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::profile::onward::PreviewVariant;
use ferrohealth_smart::resource::Caller;
use http::StatusCode;
use secrecy::SecretString;
use serde_json::Value;
use serde_json::json;
use wiremock::ResponseTemplate;

use super::harness::FLAVORS;
use super::harness::Flavor;
use super::harness::Harness;
use super::sign;

/// Returns the refusal `flavor` answers an issued token whose claims
/// `change` alters, with how many calls it made.
async fn refused(flavor: Flavor, change: impl Fn(&mut Value)) -> (OnwardError, usize) {
    let harness = Harness::start(flavor).await;
    let (subject, claims) = harness.person();
    let mut issued = flavor.issued_claims(&claims, harness.now());
    change(&mut issued);
    harness.issue(&issued, None).await;
    let error = harness
        .token(&subject, None)
        .await
        .expect_err("the issued token is refused");
    (error, harness.calls().await)
}

#[tokio::test]
async fn every_profile_accepts_the_token_its_exchange_issues() {
    for flavor in FLAVORS.into_iter().chain([Flavor::GenericJwtBearer]) {
        let harness = Harness::start(flavor).await;
        let (subject, claims) = harness.person();
        let issued = flavor.issued_claims(&claims, harness.now());
        let sent = harness.issue(&issued, None).await;
        let token = harness
            .token(&subject, None)
            .await
            .unwrap_or_else(|error| panic!("{flavor:?}: {error}"));
        assert_eq!(
            Some(format!("Bearer {sent}").as_str()),
            token.header().to_str().ok(),
            "{flavor:?}: the issued token is the bearer credential"
        );
        assert!(token.header().is_sensitive(), "{flavor:?}");
        assert_eq!(
            issued["exp"].as_i64(),
            Some(token.expires_at()),
            "{flavor:?}"
        );
    }
}

#[tokio::test]
async fn an_audience_outside_the_targets_is_refused() {
    for flavor in FLAVORS {
        let (error, _) = refused(flavor, |issued| {
            issued["aud"] = json!(["https://elsewhere.example.org"]);
        })
        .await;
        assert!(
            matches!(error, OnwardError::Rejected(Rejected::Audience)),
            "{flavor:?}: {error:?}"
        );
    }
}

#[tokio::test]
async fn an_audience_beside_the_targets_is_refused() {
    // NOTE: RFC 8707 §2, a token for one target is never handed to another,
    // so an `aud` naming a second service is refused.
    for flavor in FLAVORS {
        let (error, _) = refused(flavor, |issued| {
            let named = issued["aud"].clone();
            issued["aud"] = json!([named.as_str().or(named[0].as_str()), "other-service"]);
        })
        .await;
        assert!(
            matches!(error, OnwardError::Rejected(Rejected::Audience)),
            "{flavor:?}: {error:?}"
        );
    }
}

#[tokio::test]
async fn another_client_as_the_actor_is_refused() {
    for flavor in FLAVORS {
        let (error, _) = refused(flavor, |issued| {
            for claim in ["client_id", "azp"] {
                if issued.get(claim).is_some() {
                    issued[claim] = json!("another-client");
                }
            }
        })
        .await;
        assert!(
            matches!(error, OnwardError::Rejected(Rejected::Actor)),
            "{flavor:?}: {error:?}"
        );
    }
}

#[tokio::test]
async fn an_act_naming_another_actor_is_refused() {
    // NOTE: RFC 8693 §4.1, `act` names the current actor, which must be the
    // requesting client.
    for flavor in FLAVORS {
        let (error, _) = refused(flavor, |issued| {
            issued["act"] = json!({ "sub": "someone-else" });
        })
        .await;
        assert!(
            matches!(error, OnwardError::Rejected(Rejected::Actor)),
            "{flavor:?}: {error:?}"
        );
    }
}

#[tokio::test]
async fn an_exp_beyond_the_max_onward_lifetime_is_refused() {
    for flavor in FLAVORS {
        let (error, _) = refused(flavor, |issued| {
            let iat = issued["iat"].as_i64().expect("an iat");
            issued["exp"] = json!(iat + 3601);
        })
        .await;
        assert!(
            matches!(error, OnwardError::Rejected(Rejected::Lifetime)),
            "{flavor:?}: {error:?}"
        );
    }
}

#[tokio::test]
async fn an_issued_token_without_iat_or_exp_is_refused() {
    for flavor in FLAVORS {
        for claim in ["iat", "exp"] {
            let (error, _) = refused(flavor, |issued| {
                issued.as_object_mut().map(|claims| claims.remove(claim));
            })
            .await;
            assert!(
                matches!(&error, OnwardError::Rejected(Rejected::MissingClaim { claim: missing }) if *missing == claim),
                "{flavor:?} {claim}: {error:?}"
            );
        }
    }
}

#[tokio::test]
async fn an_expired_issued_token_is_refused() {
    for flavor in FLAVORS {
        let (error, _) = refused(flavor, |issued| {
            let iat = issued["iat"].as_i64().expect("an iat");
            issued["iat"] = json!(iat - 400);
            issued["exp"] = json!(iat - 100);
        })
        .await;
        assert!(
            matches!(error, OnwardError::Rejected(Rejected::Expired)),
            "{flavor:?}: {error:?}"
        );
    }
}

#[tokio::test]
async fn a_token_from_another_issuer_with_another_sub_is_refused() {
    for flavor in FLAVORS {
        let (error, _) = refused(flavor, |issued| {
            issued["iss"] = json!("https://other-issuer.example.net");
            issued["sub"] = json!("someone-else");
        })
        .await;
        assert!(
            matches!(error, OnwardError::Rejected(Rejected::Issuer)),
            "{flavor:?}: {error:?}"
        );
    }
}

#[tokio::test]
async fn under_the_standards_only_profile_another_sub_is_refused() {
    for flavor in FLAVORS {
        let (error, _) = refused(flavor, |issued| {
            issued["sub"] = json!("someone-else");
        })
        .await;
        assert!(
            matches!(&error, OnwardError::Rejected(Rejected::Person { claim }) if claim == "sub"),
            "{flavor:?}: {error:?}"
        );
    }
}

#[tokio::test]
async fn a_response_carrying_a_refresh_token_is_refused() {
    for flavor in FLAVORS {
        let harness = Harness::start(flavor).await;
        let (subject, claims) = harness.person();
        let token = sign(&harness.key, &flavor.issued_claims(&claims, harness.now()));
        let mut response = flavor.response(&token);
        response["refresh_token"] = json!("synthetic-refresh-token");
        harness
            .answer(ResponseTemplate::new(200).set_body_json(response))
            .await;
        let error = harness.token(&subject, None).await.expect_err("refused");
        assert!(
            matches!(error, OnwardError::RefreshToken),
            "{flavor:?}: {error:?}"
        );
        assert!(!format!("{error:?} {error}").contains("synthetic-refresh-token"));
    }
}

#[tokio::test]
async fn offline_access_is_never_asked_for() {
    for flavor in FLAVORS.into_iter().chain([Flavor::GenericJwtBearer]) {
        let harness = Harness::start(flavor).await;
        let (subject, _) = harness.person();
        let target = flavor.target().with_scope(format!(
            "{} offline_access",
            flavor.target().scope().unwrap_or("api")
        ));
        let error = harness
            .onward
            .token(&subject, None, &target)
            .await
            .expect_err("refused before sending");
        assert!(
            matches!(error, OnwardError::OfflineAccess),
            "{flavor:?}: {error:?}"
        );
        assert_eq!(0, harness.calls().await, "{flavor:?}: nothing is sent");
    }
}

#[tokio::test]
async fn the_jwt_bearer_grant_refuses_a_system_subject_before_sending() {
    // NOTE: RFC 7523 §3: the assertion's `sub` names the principal the token
    // is requested for, a user; a system authenticates for itself.
    for flavor in [Flavor::GenericJwtBearer] {
        let harness = Harness::start(flavor).await;
        let claims = flavor.subject_claims(harness.now());
        let subject = harness.subject(&claims, CallerKind::System);
        let error = harness.token(&subject, None).await.expect_err("refused");
        assert!(
            matches!(error, OnwardError::UserPrincipalRequired),
            "{flavor:?}: {error:?}"
        );
        assert_eq!(0, harness.calls().await, "{flavor:?}: nothing is sent");
    }
}

#[tokio::test]
async fn token_exchange_exchanges_a_system_subject() {
    let harness = Harness::start(Flavor::Generic).await;
    let claims = Flavor::Generic.subject_claims(harness.now());
    let subject = harness.subject(&claims, CallerKind::System);
    harness
        .issue(&Flavor::Generic.issued_claims(&claims, harness.now()), None)
        .await;
    assert!(harness.token(&subject, None).await.is_ok());
}

#[tokio::test]
async fn a_delegated_exchange_sends_the_actor_token_and_checks_act() {
    let harness = Harness::start(Flavor::Generic).await;
    let (subject, claims) = harness.person();
    let mut issued = Flavor::Generic.issued_claims(&claims, harness.now());
    issued["act"] = json!({ "sub": "bridge-service" });
    harness.issue(&issued, Some("bridge-service")).await;
    let actor_claims = json!({ "iss": Flavor::Generic.issuer(), "sub": "bridge-service" });
    let actor = ActorToken::new(
        SecretString::from(sign(&harness.key, &actor_claims)),
        Actor {
            issuer: Flavor::Generic.issuer(),
            sub: String::from("bridge-service"),
        },
    );
    assert!(harness.token(&subject, Some(&actor)).await.is_ok());
}

#[tokio::test]
async fn an_actor_token_without_an_act_in_the_issued_token_is_refused() {
    let harness = Harness::start(Flavor::Generic).await;
    let (subject, claims) = harness.person();
    let issued = Flavor::Generic.issued_claims(&claims, harness.now());
    harness.issue(&issued, Some("bridge-service")).await;
    let actor_claims = json!({ "iss": Flavor::Generic.issuer(), "sub": "bridge-service" });
    let actor = ActorToken::new(
        SecretString::from(sign(&harness.key, &actor_claims)),
        Actor {
            issuer: Flavor::Generic.issuer(),
            sub: String::from("bridge-service"),
        },
    );
    let error = harness
        .token(&subject, Some(&actor))
        .await
        .expect_err("refused");
    assert!(
        matches!(error, OnwardError::Rejected(Rejected::Actor)),
        "{error:?}"
    );
}

#[tokio::test]
async fn the_jwt_bearer_grant_carries_no_actor_token() {
    let harness = Harness::start(Flavor::GenericJwtBearer).await;
    let (subject, _) = harness.person();
    let actor = ActorToken::new(
        SecretString::from("synthetic-actor-token"),
        Actor {
            issuer: Flavor::GenericJwtBearer.issuer(),
            sub: String::from(Flavor::GenericJwtBearer.client_id()),
        },
    );
    let error = harness
        .token(&subject, Some(&actor))
        .await
        .expect_err("refused");
    assert!(matches!(error, OnwardError::ActorToken), "{error:?}");
    assert_eq!(0, harness.calls().await);
}

#[tokio::test]
async fn a_delegation_the_profile_labels_preview_is_refused() {
    let mut settings = Flavor::Generic.settings(3600);
    settings.profile.onward_preview = vec![PreviewVariant::ActorToken];
    let harness = Harness::with_settings(Flavor::Generic, settings).await;
    let (subject, _) = harness.person();
    let actor = ActorToken::new(
        SecretString::from("synthetic-actor-token"),
        Actor {
            issuer: Flavor::Generic.issuer(),
            sub: String::from("service-account-synthetic"),
        },
    );
    let error = harness
        .token(&subject, Some(&actor))
        .await
        .expect_err("refused");
    assert!(
        matches!(
            error,
            OnwardError::Preview {
                variant: PreviewVariant::ActorToken
            }
        ),
        "{error:?}"
    );
    assert_eq!(0, harness.calls().await);
}

#[tokio::test]
async fn a_subject_token_not_addressed_to_the_client_is_refused_where_the_profile_asks() {
    for flavor in FLAVORS {
        let mut settings = flavor.settings(3600);
        settings.profile.onward_subject_audience = true;
        let harness = Harness::with_settings(flavor, settings).await;
        let mut claims = flavor.subject_claims(harness.now());
        claims["aud"] = json!("someone-else");
        let subject = harness.subject(&claims, CallerKind::Person);
        let error = harness.token(&subject, None).await.expect_err("refused");
        assert!(
            matches!(error, OnwardError::SubjectAudience),
            "{flavor:?}: {error:?}"
        );
        assert_eq!(0, harness.calls().await, "{flavor:?}");
    }
}

#[tokio::test]
async fn a_caller_without_a_verified_token_is_refused_before_anything_is_sent() {
    let basic = Caller::basic(String::from("operator"), "user/*.rs");
    assert!(matches!(
        SubjectToken::from_caller(&basic, SecretString::from("anything")),
        Err(OnwardError::NoSubjectToken)
    ));
    let edge = Caller::new(
        String::from("person-1"),
        None,
        "user/*.rs",
        None,
        CallerKind::Person,
    );
    assert!(matches!(
        SubjectToken::from_caller(&edge, SecretString::from("anything")),
        Err(OnwardError::NoSubjectToken)
    ));
}

#[tokio::test]
async fn a_jwt_whose_claims_are_not_the_callers_is_refused() {
    let harness = Harness::start(Flavor::Generic).await;
    let claims = Flavor::Generic.subject_claims(harness.now());
    let mut other = claims.clone();
    other["sub"] = json!("someone-else");
    let caller = super::caller(&claims, CallerKind::Person);
    let token = SecretString::from(sign(&harness.key, &other));
    assert!(matches!(
        SubjectToken::from_caller(&caller, token),
        Err(OnwardError::NoSubjectToken)
    ));
}

#[tokio::test]
async fn a_refused_exchange_is_a_typed_error_with_the_upstream_status() {
    for flavor in FLAVORS {
        let harness = Harness::start(flavor).await;
        let (subject, _) = harness.person();
        harness
            .answer(ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_grant", "error_description": "the subject token is revoked"
            })))
            .await;
        let error = harness.token(&subject, None).await.expect_err("refused");
        assert_eq!(Some(StatusCode::BAD_REQUEST), error.status(), "{flavor:?}");
        assert!(
            matches!(&error, OnwardError::Token(TokenError::Refused { error: Some(oauth), .. }) if oauth.error == "invalid_grant"),
            "{flavor:?}: {error:?}"
        );
    }
}

#[tokio::test]
async fn a_server_error_is_refused_with_its_status_and_none_of_its_body() {
    let harness = Harness::start(Flavor::Generic).await;
    let (subject, _) = harness.person();
    harness
        .answer(ResponseTemplate::new(503).set_body_string("maintenance"))
        .await;
    let error = harness.token(&subject, None).await.expect_err("refused");
    assert_eq!(Some(StatusCode::SERVICE_UNAVAILABLE), error.status());
    assert!(
        matches!(
            &error,
            OnwardError::Token(TokenError::Refused { error: None, .. })
        ),
        "{error:?}"
    );
    assert!(
        !error.to_string().contains("maintenance") && !format!("{error:?}").contains("maintenance"),
        "the refusal keeps nothing of the body: {error:?}"
    );
}

#[tokio::test]
async fn an_exchange_answer_past_the_ceiling_is_refused_unread() {
    let harness = Harness::start(Flavor::Generic).await;
    let (subject, _) = harness.person();
    let oversized = "x".repeat(ferrohealth_smart::metadata::MAX_DOCUMENT_BYTES + 1);
    harness
        .answer(ResponseTemplate::new(200).set_body_string(oversized))
        .await;
    let error = harness.token(&subject, None).await.expect_err("refused");
    assert!(
        matches!(
            &error,
            OnwardError::Token(TokenError::Discovery(
                ferrohealth_smart::metadata::DiscoveryError::TooLarge { .. }
            ))
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_response_that_is_not_a_token_response_is_refused() {
    let harness = Harness::start(Flavor::Generic).await;
    let (subject, _) = harness.person();
    harness
        .answer(ResponseTemplate::new(200).set_body_string("{\"token\":1}"))
        .await;
    let error = harness.token(&subject, None).await.expect_err("refused");
    assert!(
        matches!(error, OnwardError::Token(TokenError::Malformed { .. })),
        "{error:?}"
    );
}

#[tokio::test]
async fn an_opaque_issued_token_is_refused() {
    let harness = Harness::start(Flavor::Generic).await;
    let (subject, _) = harness.person();
    harness
        .answer(ResponseTemplate::new(200).set_body_json(Flavor::Generic.response("opaque-token")))
        .await;
    let error = harness.token(&subject, None).await.expect_err("refused");
    assert!(
        matches!(error, OnwardError::Rejected(Rejected::NotJwt)),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_token_exchange_response_without_an_access_token_type_is_refused() {
    for issued_token_type in [
        None,
        Some("urn:ietf:params:oauth:token-type:refresh_token"),
        Some("urn:ietf:params:oauth:token-type:id_token"),
    ] {
        let harness = Harness::start(Flavor::Generic).await;
        let (subject, claims) = harness.person();
        let token = sign(
            &harness.key,
            &Flavor::Generic.issued_claims(&claims, harness.now()),
        );
        let mut response = Flavor::Generic.response(&token);
        match issued_token_type {
            Some(found) => response["issued_token_type"] = json!(found),
            None => {
                response
                    .as_object_mut()
                    .map(|members| members.remove("issued_token_type"));
            }
        }
        harness
            .answer(ResponseTemplate::new(200).set_body_json(response))
            .await;
        let error = harness.token(&subject, None).await.expect_err("refused");
        assert!(
            matches!(&error, OnwardError::IssuedTokenType { found } if found.as_deref() == issued_token_type),
            "{issued_token_type:?}: {error:?}"
        );
    }
}

#[tokio::test]
async fn a_relative_or_fragment_resource_is_refused_before_sending() {
    for indicator in ["/api", "https://ehr.example.org/api#part"] {
        let harness = Harness::start(Flavor::Generic).await;
        let (subject, _) = harness.person();
        let target = ferrohealth_smart::client::onward::Target::new(["https://ehr.example.org"])
            .with_indicator(indicator);
        let error = harness
            .onward
            .token(&subject, None, &target)
            .await
            .expect_err("refused");
        assert!(
            matches!(error, OnwardError::Resource),
            "{indicator}: {error:?}"
        );
        assert_eq!(0, harness.calls().await);
    }
}

#[tokio::test]
async fn a_target_without_audiences_is_refused_before_sending() {
    let harness = Harness::start(Flavor::Generic).await;
    let (subject, _) = harness.person();
    let target = ferrohealth_smart::client::onward::Target::new(Vec::<String>::new());
    let error = harness
        .onward
        .token(&subject, None, &target)
        .await
        .expect_err("refused");
    assert!(matches!(error, OnwardError::NoAudience), "{error:?}");
}

#[tokio::test]
async fn the_jwt_bearer_grant_names_its_target_in_scope_alone() {
    let harness = Harness::start(Flavor::GenericJwtBearer).await;
    let (subject, _) = harness.person();
    let unscoped = ferrohealth_smart::client::onward::Target::new(["https://ehr.example.org"]);
    let error = harness
        .onward
        .token(&subject, None, &unscoped)
        .await
        .expect_err("refused");
    assert!(matches!(error, OnwardError::NoScope), "{error:?}");
    let indicated = Flavor::GenericJwtBearer
        .target()
        .with_indicator("https://downstream.example.org");
    let error = harness
        .onward
        .token(&subject, None, &indicated)
        .await
        .expect_err("refused");
    assert!(matches!(error, OnwardError::Indicator), "{error:?}");
    assert_eq!(0, harness.calls().await);
}
