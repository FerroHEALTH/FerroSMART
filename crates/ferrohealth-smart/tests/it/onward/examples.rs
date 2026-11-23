// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The official examples of the two RFCs: RFC 8693 §2.3 Figures 2 and 3,
//! Appendix A.1 Figures 10 to 13 (impersonation) and A.2 Figures 14 to 18
//! (delegation), and RFC 7523 §4 with the client assertion of §2.2. Each
//! request is reproduced parameter for parameter and each response parsed;
//! a figure's past times are moved to now and the token signed again.

use ferrohealth_smart::client::ClientCredentials;
use ferrohealth_smart::client::TokenError;
use ferrohealth_smart::client::onward::ActorToken;
use ferrohealth_smart::client::onward::OnwardError;
use ferrohealth_smart::client::onward::Rejected;
use ferrohealth_smart::client::onward::Target;
use ferrohealth_smart::client::onward::TokenType;
use ferrohealth_smart::client::onward::exchange::Onward;
use ferrohealth_smart::kind::Actor;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::profile::ProfileKeys;
use ferrohealth_smart::profile::onward::OnwardGrant;
use ferrohealth_smart::resource::Settings;
use jsonwebtoken::Algorithm;
use secrecy::SecretString;
use serde_json::Value;
use serde_json::json;
use wiremock::MockServer;
use wiremock::ResponseTemplate;

use super::ClientKey;
use super::TestClock;
use super::answer;
use super::endpoint;
use super::figure_form;
use super::param;
use super::received;
use super::sign;
use super::sorted;
use super::subject_of;
use crate::support::ec_key;

/// The token endpoint route of RFC 8693 §2.3 and Appendix A.
const AS_ROUTE: &str = "/as/token.oauth2";

/// The authorization server of RFC 8693 §2.3 and Appendix A.
const AS: &str = "https://as.example.com";

/// The body of RFC 8693 Figure 2, its display line breaks removed.
const FIGURE_2: &str = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&resource=https%3A%2F%2Fbackend.example.com%2Fapi&subject_token=accVkjcJyb4BWCxGsndESCJQbdFMogUC5PbRDqceLTC&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token";

/// The `Authorization` field of RFC 8693 Figure 2: `rs08` and its secret.
const FIGURE_2_BASIC: &str = "Basic cnMwODpsb25nLXNlY3VyZS1yYW5kb20tc2VjcmV0";

/// The access token of RFC 8693 Figure 3, whose claims expired in 2015.
const FIGURE_3_TOKEN: &str = "eyJhbGciOiJFUzI1NiIsImtpZCI6IjllciJ9.eyJhdWQiOiJodHRwczovL2JhY2tlbmQuZXhhbXBsZS5jb20iLCJpc3MiOiJodHRwczovL2FzLmV4YW1wbGUuY29tIiwiZXhwIjoxNDQxOTE3NTkzLCJpYXQiOjE0NDE5MTc1MzMsInN1YiI6ImJkY0BleGFtcGxlLmNvbSIsInNjb3BlIjoiYXBpIn0.40y3ZgQedw6rxf59WlwHDD9jryFOr0_Wh3CGozQBihNBhnXEQgU85AI9x3KmsPottVMLPIWvmDCMy5-kdXjwhw";

/// The body of RFC 8693 Figure 10 without its `subject_token`, which the
/// case signs again with current times.
const FIGURE_10: &str = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&audience=urn%3Aexample%3Acooperation-context&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt";

/// The body of RFC 8693 Figure 14 without its two tokens, which the case
/// signs again with current times.
const FIGURE_14: &str = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&audience=urn%3Aexample%3Acooperation-context&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt&actor_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt";

/// Returns the settings of `https://as.example.com`, a standards-only
/// `persons` issuer whose onward tokens live at most an hour, the longest
/// lifetime the Appendix A responses name.
fn as_example_com(keys: ProfileKeys) -> Settings {
    let mut settings = Settings::new(AS, "rs08", IssuerKind::Smart);
    settings.profile = ferrohealth_smart::profile::Profile::default().with_keys(ProfileKeys {
        max_onward_lifetime: Some(ferrohealth_config::units::Duration::from_hours(1)),
        ..keys
    });
    settings
}

/// Returns the client of `server` authenticating as `rs08` with the
/// Figure 2 secret, over `settings`.
fn rs08(server: &MockServer, settings: Settings) -> Onward {
    let credentials = ClientCredentials::new(
        endpoint(server, AS_ROUTE),
        String::from("rs08"),
        SecretString::from("long-secure-random-secret"),
    );
    Onward::with_clock(settings, credentials, TestClock::now()).expect("the client builds")
}

/// Returns the subject of RFC 8693 Figure 1, whose opaque token the
/// resource server admitted with claims of its issuer.
fn figure_1_subject() -> ferrohealth_smart::client::onward::SubjectToken {
    let now = crate::support::now();
    let claims = json!({
        "iss": AS, "sub": "bdc@example.com", "aud": "https://frontend.example.com",
        "client_id": "frontend", "iat": now, "exp": now + 600
    });
    subject_of(
        "accVkjcJyb4BWCxGsndESCJQbdFMogUC5PbRDqceLTC",
        &claims,
        CallerKind::Person,
    )
}

/// Returns the target of RFC 8693 Figure 2.
fn backend() -> Target {
    Target::new(["https://backend.example.com"]).with_indicator("https://backend.example.com/api")
}

/// Returns the Figure 3 response carrying `access_token`.
fn figure_3(access_token: &str) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("Cache-Control", "no-cache, no-store")
        .set_body_json(json!({
            "access_token": access_token,
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": 60
        }))
}

#[tokio::test]
async fn rfc8693_figure_2_is_reproduced_byte_for_byte() {
    // NOTE: RFC 8693 §2.3 Figure 2, with HTTP Basic client authentication and
    // `resource` naming the backend.
    let server = MockServer::start().await;
    answer(&server, AS_ROUTE, figure_3(FIGURE_3_TOKEN)).await;
    let onward = rs08(&server, as_example_com(ProfileKeys::default()));
    let outcome = onward.token(&figure_1_subject(), None, &backend()).await;
    let requests = server.received_requests().await.unwrap_or_default();
    let request = requests.first().expect("one request");
    assert_eq!(FIGURE_2.as_bytes(), request.body.as_slice());
    assert_eq!(
        Some(FIGURE_2_BASIC),
        request
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
    );
    assert!(
        matches!(outcome, Err(OnwardError::Rejected(Rejected::Expired))),
        "Figure 3 as published expired in 2015: {outcome:?}"
    );
}

#[tokio::test]
async fn rfc8693_figure_3_signed_again_now_names_no_actor_and_is_refused() {
    // NOTE: RFC 8693 §2.3 Figure 3's claims carry no `client_id` and no `act`,
    // so the requesting client is named nowhere and the check refuses them.
    let server = MockServer::start().await;
    let key = ec_key("9er", Algorithm::ES256);
    let now = crate::support::now();
    let claims = json!({
        "aud": "https://backend.example.com", "iss": AS, "exp": now + 60,
        "iat": now, "sub": "bdc@example.com", "scope": "api"
    });
    answer(&server, AS_ROUTE, figure_3(&sign(&key, &claims))).await;
    let onward = rs08(&server, as_example_com(ProfileKeys::default()));
    let outcome = onward.token(&figure_1_subject(), None, &backend()).await;
    assert!(
        matches!(outcome, Err(OnwardError::Rejected(Rejected::Actor))),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn rfc8693_figure_3_with_the_rfc9068_client_id_is_accepted() {
    // NOTE: RFC 9068 §2.2 makes `client_id` REQUIRED in a JWT access token;
    // with it, Figure 3 signed again now passes every check.
    let server = MockServer::start().await;
    let key = ec_key("9er", Algorithm::ES256);
    let now = crate::support::now();
    let claims = json!({
        "aud": "https://backend.example.com", "iss": AS, "exp": now + 60,
        "iat": now, "sub": "bdc@example.com", "scope": "api", "client_id": "rs08"
    });
    let token = sign(&key, &claims);
    answer(&server, AS_ROUTE, figure_3(&token)).await;
    let onward = rs08(&server, as_example_com(ProfileKeys::default()));
    let issued = onward
        .token(&figure_1_subject(), None, &backend())
        .await
        .expect("accepted");
    assert_eq!(
        Some(format!("Bearer {token}").as_str()),
        issued.header().to_str().ok(),
        "RFC 8693 Figure 4 sends the issued token as a bearer token"
    );
    assert_eq!(now + 60, issued.expires_at());
}

/// Returns the claims of RFC 8693 Figure 11 with current times.
fn figure_11(now: i64) -> Value {
    json!({
        "aud": AS, "iss": "https://original-issuer.example.net",
        "exp": now + 1600, "nbf": now, "sub": "bdc@example.net",
        "scope": "orders profile history"
    })
}

#[tokio::test]
async fn rfc8693_figure_10_is_reproduced_and_figure_13_refused_for_its_missing_iat() {
    // NOTE: RFC 8693 Appendix A.1, impersonation: `audience` names the target
    // and the subject token is a JWT; Figure 13 carries no `iat`.
    let server = MockServer::start().await;
    let key = ec_key("72", Algorithm::ES256);
    let now = crate::support::now();
    let subject_claims = figure_11(now);
    let subject_token = sign(&key, &subject_claims);
    let issued = json!({
        "aud": "urn:example:cooperation-context", "iss": AS, "exp": now + 3600,
        "sub": "bdc@example.net", "scope": "orders profile history"
    });
    answer(
        &server,
        AS_ROUTE,
        ResponseTemplate::new(200).set_body_json(json!({
            "access_token": sign(&key, &issued),
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": 3600
        })),
    )
    .await;
    let onward = rs08(
        &server,
        as_example_com(ProfileKeys {
            onward_indicator: Some(ferrohealth_smart::profile::onward::OnwardIndicator::Audience),
            ..ProfileKeys::default()
        }),
    );
    let subject = subject_of(&subject_token, &subject_claims, CallerKind::Person)
        .with_token_type(TokenType::Jwt);
    let target = Target::new(["urn:example:cooperation-context"])
        .with_indicator("urn:example:cooperation-context");
    let outcome = onward.token(&subject, None, &target).await;
    let sent = received(&server).await;
    let form = sent.first().expect("one request");
    assert_eq!(Some(subject_token.as_str()), param(form, "subject_token"));
    assert_eq!(
        sorted(&figure_form(FIGURE_10), &[]),
        sorted(form, &["subject_token"]),
        "Figure 10 parameter for parameter"
    );
    assert!(
        matches!(
            outcome,
            Err(OnwardError::Rejected(Rejected::MissingClaim {
                claim: "iat"
            }))
        ),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn rfc8693_figure_13_with_an_iat_is_refused_for_naming_another_issuers_person() {
    // NOTE: RFC 8693 Appendix A.1: the subject token is of
    // original-issuer.example.net and Figure 13 of as.example.com, so `iss`
    // differs under the default `person_equality` of `iss` and `sub`.
    let server = MockServer::start().await;
    let key = ec_key("72", Algorithm::ES256);
    let now = crate::support::now();
    let subject_claims = figure_11(now);
    let issued = json!({
        "aud": "urn:example:cooperation-context", "iss": AS, "exp": now + 3600,
        "iat": now, "sub": "bdc@example.net", "scope": "orders profile history",
        "client_id": "rs08"
    });
    answer(
        &server,
        AS_ROUTE,
        ResponseTemplate::new(200).set_body_json(json!({
            "access_token": sign(&key, &issued),
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": 3600
        })),
    )
    .await;
    let onward = rs08(
        &server,
        as_example_com(ProfileKeys {
            onward_indicator: Some(ferrohealth_smart::profile::onward::OnwardIndicator::Audience),
            ..ProfileKeys::default()
        }),
    );
    let subject = subject_of(
        &sign(&key, &subject_claims),
        &subject_claims,
        CallerKind::Person,
    )
    .with_token_type(TokenType::Jwt);
    let target = Target::new(["urn:example:cooperation-context"])
        .with_indicator("urn:example:cooperation-context");
    let outcome = onward.token(&subject, None, &target).await;
    assert!(
        matches!(&outcome, Err(OnwardError::Rejected(Rejected::Person { claim })) if claim == "iss"),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn rfc8693_figure_14_is_reproduced_and_the_figure_17_n_a_token_refused() {
    // NOTE: RFC 8693 Appendix A.2, delegation: both tokens are JWTs, and
    // Figure 17 issues a JWT with `token_type` N_A, which no bearer request
    // can carry (RFC 8693 §2.2.1).
    let server = MockServer::start().await;
    let key = ec_key("16", Algorithm::ES256);
    let now = crate::support::now();
    let subject_claims = json!({
        "aud": AS, "iss": "https://original-issuer.example.net", "exp": now + 1060,
        "scope": "status feed", "sub": "user@example.net",
        "may_act": { "sub": "admin@example.net" }
    });
    let actor_claims = json!({
        "aud": AS, "iss": "https://original-issuer.example.net", "exp": now + 1060,
        "sub": "admin@example.net"
    });
    let issued = json!({
        "aud": "urn:example:cooperation-context", "iss": AS, "exp": now + 3600,
        "scope": "status feed", "sub": "user@example.net",
        "act": { "sub": "admin@example.net" }
    });
    answer(
        &server,
        AS_ROUTE,
        ResponseTemplate::new(200).set_body_json(json!({
            "access_token": sign(&key, &issued),
            "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "token_type": "N_A",
            "expires_in": 3600
        })),
    )
    .await;
    let onward = rs08(
        &server,
        as_example_com(ProfileKeys {
            onward_indicator: Some(ferrohealth_smart::profile::onward::OnwardIndicator::Audience),
            ..ProfileKeys::default()
        }),
    );
    let subject_token = sign(&key, &subject_claims);
    let actor_token = sign(&key, &actor_claims);
    let subject = subject_of(&subject_token, &subject_claims, CallerKind::Person)
        .with_token_type(TokenType::Jwt);
    let actor = ActorToken::new(
        SecretString::from(actor_token.clone()),
        Actor {
            issuer: String::from(AS),
            sub: String::from("admin@example.net"),
        },
    )
    .with_token_type(TokenType::Jwt);
    let target = Target::new(["urn:example:cooperation-context"])
        .with_indicator("urn:example:cooperation-context");
    let outcome = onward.token(&subject, Some(&actor), &target).await;
    let sent = received(&server).await;
    let form = sent.first().expect("one request");
    assert_eq!(Some(subject_token.as_str()), param(form, "subject_token"));
    assert_eq!(Some(actor_token.as_str()), param(form, "actor_token"));
    assert_eq!(
        sorted(&figure_form(FIGURE_14), &[]),
        sorted(form, &["subject_token", "actor_token"]),
        "Figure 14 parameter for parameter"
    );
    assert!(
        matches!(&outcome, Err(OnwardError::Token(TokenError::TokenType { found, expected: "Bearer" })) if found == "N_A"),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn rfc7523_section_4_is_reproduced_with_the_section_2_2_client_assertion() {
    // NOTE: RFC 7523 §4: `grant_type` jwt-bearer and the JWT as `assertion`;
    // §2.2 adds the client assertion, and the target is named in `scope`.
    let server = MockServer::start().await;
    let issuer_key = ec_key("16", Algorithm::ES256);
    let client = ClientKey::new();
    let now = crate::support::now();
    let assertion_claims = json!({
        "iss": "https://jwt-idp.example.com", "sub": "mailto:mike@example.com",
        "aud": "https://jwt-rp.example.net", "nbf": now, "exp": now + 3600,
        "http://claims.example.com/member": true
    });
    let assertion = sign(&issuer_key, &assertion_claims);
    let mut settings = Settings::new(
        "https://jwt-rp.example.net",
        "https://jwt-rp.example.net",
        IssuerKind::Smart,
    );
    settings.profile = ferrohealth_smart::profile::Profile::default().with_keys(ProfileKeys {
        onward_grant: Some(OnwardGrant::JwtBearer),
        max_onward_lifetime: Some(ferrohealth_config::units::Duration::from_hours(1)),
        ..ProfileKeys::default()
    });
    let issued = json!({
        "iss": "https://jwt-rp.example.net", "sub": "mailto:mike@example.com",
        "aud": "https://api.example.net", "client_id": "s6BhdRkqt3",
        "iat": now, "exp": now + 300, "jti": "issued-1"
    });
    answer(
        &server,
        "/token.oauth2",
        ResponseTemplate::new(200).set_body_json(json!({
            "access_token": sign(&issuer_key, &issued),
            "token_type": "Bearer",
            "expires_in": 300
        })),
    )
    .await;
    let onward = Onward::with_clock(
        settings,
        client.credentials(endpoint(&server, "/token.oauth2"), "s6BhdRkqt3"),
        TestClock::now(),
    )
    .expect("the client builds");
    let subject = subject_of(&assertion, &assertion_claims, CallerKind::Person);
    let target =
        Target::new(["https://api.example.net"]).with_scope("https://api.example.net/read");
    // NOTE: OpenID Connect Core 1.0 §5.7: `iss` and `sub` together name one user, so
    // the token the RP issues for another issuer's assertion names another person.
    let outcome = onward.token(&subject, None, &target).await;
    assert!(
        matches!(&outcome, Err(OnwardError::Rejected(Rejected::Person { claim })) if claim == "iss"),
        "{outcome:?}"
    );
    let sent = received(&server).await;
    let form = sent.first().expect("one request");
    assert_eq!(
        Some("urn:ietf:params:oauth:grant-type:jwt-bearer"),
        param(form, "grant_type")
    );
    assert_eq!(Some(assertion.as_str()), param(form, "assertion"));
    assert_eq!(Some("https://api.example.net/read"), param(form, "scope"));
    client.verify(
        form,
        "s6BhdRkqt3",
        &format!("{}/token.oauth2", server.uri()),
    );
    assert_eq!(
        vec![
            "assertion",
            "client_assertion",
            "client_assertion_type",
            "grant_type",
            "scope"
        ],
        sorted(form, &[])
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        "no subject_token, actor_token, resource or audience"
    );
}
