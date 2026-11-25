// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The token exchange of a patient's own token at a FHIR base for a token
//! at the openEHR base paired with it (RFC 8693 §2; `docs/architecture.md`
//! §13.29).

use super::ehr_picker::{EHR_ID, NAMESPACE, OpenEhr};
use super::*;

/// The exchanging client's secret.
const SECRET: &str = "synthetic-bridge-secret";
/// The scope the patient grants the app at the FHIR base.
const FHIR_SCOPE: &str = "openid fhirUser launch/patient patient/Observation.rs";
/// The token type of an access token (RFC 8693 §3).
const ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";

/// FerroSMART over a FHIR base paired with an openEHR base, with the
/// confidential client `bridge` that may exchange tokens.
struct Platform {
    /// The server.
    smart: Smart,
    /// The FHIR base.
    fhir_base: String,
    /// The openEHR base.
    openehr_base: String,
    /// The FHIR server, kept for the case's length.
    _fhir: MockServer,
    /// The openEHR server, kept for the case's length.
    _openehr: MockServer,
}

/// Starts the platform.
async fn platform() -> Platform {
    let fhir = MockServer::start().await;
    Mock::given(matchers::method("GET"))
        .respond_with(Fhir {
            seen: Arc::new(std::sync::Mutex::new(Vec::new())),
        })
        .mount(&fhir)
        .await;
    let openehr = MockServer::start().await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/openehr/v1/ehr"))
        .respond_with(OpenEhr {
            subject: "MRN-1",
            seen: Arc::new(std::sync::Mutex::new(Vec::new())),
        })
        .mount(&openehr)
        .await;
    let fhir_base = format!("{}/fhir", fhir.uri());
    let openehr_base = format!("{}/openehr/v1", openehr.uri());
    let grants = format!(
        "[\"authorization_code\"]\n\
         scope = [\"openid\", \"fhirUser\", \"launch/patient\", \"patient/Observation.rs\", \"user/Observation.rs\"]\n\
         [[client]]\nclient_id = \"bridge\"\ntoken_endpoint_auth_method = \"client_secret_post\"\n\
         resources = [{fhir_base:?}, {openehr_base:?}]\n\
         grant_types = [\"urn:ietf:params:oauth:grant-type:token-exchange\"]"
    );
    let smart = Smart::start_over(
        &grants,
        "[\"patient/composition-*.r\", \"patient/aql-*.s\", \"user/composition-*.r\", \"user/aql-*.s\"]",
        "[\"user/Observation.rs\"]",
        &format!(
            "[[ferrosmart.resource]]\nbase = {fhir_base:?}\n\
             [[ferrosmart.resource]]\nbase = {openehr_base:?}\nkind = \"openehr\"\n\
             subject_namespace = {NAMESPACE:?}\nfhir_base = {fhir_base:?}\n\
             subject_system = \"urn:example:mrn\"\n"
        ),
    )
    .await;
    crate::support::set_secret(&smart.store, "bridge", SECRET).await;
    Platform {
        smart,
        fhir_base,
        openehr_base,
        _fhir: fhir,
        _openehr: openehr,
    }
}

/// Logs the person whose `fhirUser` is `fhir_user` in at the FHIR base,
/// asking `scope`, approves every scope offered, and returns the token
/// response.
async fn token_at_fhir(platform: &Platform, scope: &str, fhir_user: &str) -> Value {
    let smart = &platform.smart;
    let path = authorize_path(&[("aud", &platform.fhir_base), ("scope", scope)]);
    let (_, headers, _) = smart.get(&path, None).await;
    let upstream = location(&headers);
    let cookie = set_cookie(&headers);
    smart
        .provider
        .answer_as(
            &param(&upstream, "nonce").expect("a nonce"),
            &["clinician"],
            "synthetic-person",
            fhir_user,
        )
        .await;
    let callback = format!(
        "/callback?code=synthetic-upstream-code&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, headers, body) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{body}");
    // NOTE: docs/architecture.md §13.6 item 6, a patient sees the page and a
    // professional's administered app spares it.
    let mut back = location(&headers);
    if back.path() == "/consent" {
        let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
        let token = form_token(&page);
        let mut form = vec![("form_token", token.as_str()), ("decision", "approve")];
        form.extend(scope.split(' ').map(|scope| ("scope", scope)));
        let (_, headers, _) = smart.post("/consent", &form, Some(&cookie)).await;
        back = location(&headers);
    }
    let code = param(&back, "code").expect("a code");
    let redeem = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("client_id", "app"),
    ];
    let (status, _, body) = smart.post("/token", &redeem, None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    serde_json::from_str(&body).expect("JSON")
}

/// Exchanges `subject_token` as `bridge` with `extra` parameters, and
/// returns the status and the JSON body.
async fn exchange(
    smart: &Smart,
    subject_token: &str,
    extra: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut form = vec![
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        ("client_id", "bridge"),
        ("client_secret", SECRET),
        ("subject_token", subject_token),
        ("subject_token_type", ACCESS_TOKEN),
    ];
    form.extend_from_slice(extra);
    let (status, _, body) = smart.post("/token", &form, None).await;
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn a_patient_s_own_token_is_exchanged_for_their_ehr_at_the_paired_base() {
    let platform = platform().await;
    let smart = &platform.smart;
    let subject = token_at_fhir(&platform, FHIR_SCOPE, "Patient/p-1").await;
    let subject_token = subject["access_token"].as_str().expect("a token");
    let (status, body) = exchange(smart, subject_token, &[]).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    // NOTE: RFC 8693 §2.2.1, issued_token_type names the token issued.
    assert_eq!(json!(ACCESS_TOKEN), body["issued_token_type"]);
    assert_eq!(json!("Bearer"), body["token_type"]);
    assert_eq!(
        json!("patient/composition-*.r patient/aql-*.s"),
        body["scope"]
    );
    let issued = jwt_claims(&body, "access_token");
    let original = jwt_claims(&subject, "access_token");
    assert_eq!(original["sub"], issued["sub"]);
    assert_eq!(json!(platform.openehr_base), issued["aud"]);
    assert_eq!(json!("bridge"), issued["client_id"]);
    assert!(issued.get("act").is_none(), "no actor: {issued}");
    assert_eq!(json!("p-1"), issued["patient"]);
    assert_eq!(json!(EHR_ID), issued["ehrId"]);
    assert_eq!(
        json!(format!("{}/Patient/p-1", platform.fhir_base)),
        issued["fhirUser"]
    );
    assert_eq!(original["acr"], issued["acr"]);
    assert_eq!(
        json!("http://eidas.europa.eu/LoA/substantial"),
        issued["acr"]
    );
    assert_eq!(original["auth_time"], issued["auth_time"]);
    let (issued_exp, original_exp) = (
        issued["exp"].as_i64().expect("exp"),
        original["exp"].as_i64().expect("exp"),
    );
    assert!(
        issued_exp <= original_exp,
        "never outlives its subject token"
    );
    // NOTE: docs/architecture.md §3.13, the openEHR server reads the issued token as
    // the person under the `ferrosmart` preset, with the exchanging client admitted.
    let (_, _, jwks) = smart.get("/jwks", None).await;
    let caller = crate::support::read_at_resource_server(
        &serde_json::from_str(&jwks).expect("a JWK Set"),
        ISSUER,
        &platform.openehr_base,
        ferrohealth_smart::kind::IssuerKind::Smart,
        &ferrohealth_smart::profile::ProfileKeys::default(),
        body["access_token"].as_str().expect("a token"),
    )
    .await
    .expect("admitted");
    assert_eq!(&ferrohealth_smart::kind::CallerKind::Patient, caller.kind());
    assert!(caller.is_the_person());
    platform.smart.stop().await;
}

// NOTE: RFC 8693 §2.1, a professional's own token is exchanged for one that
// names them at the paired openEHR base, within their own `user/` permissions.
#[tokio::test]
async fn a_professional_s_token_is_exchanged_as_them_with_user_scopes() {
    let platform = platform().await;
    let smart = &platform.smart;
    let professional = token_at_fhir(
        &platform,
        "openid fhirUser user/Observation.rs",
        "Practitioner/synthetic-1",
    )
    .await;
    let (status, body) = exchange(
        smart,
        professional["access_token"].as_str().expect("a token"),
        &[],
    )
    .await;
    assert_eq!(StatusCode::OK, status, "{body}");
    assert_eq!(json!("user/composition-*.r user/aql-*.s"), body["scope"]);
    let issued = jwt_claims(&body, "access_token");
    let original = jwt_claims(&professional, "access_token");
    assert_eq!(original["sub"], issued["sub"]);
    assert_eq!(json!(platform.openehr_base), issued["aud"]);
    assert_eq!(json!("bridge"), issued["client_id"]);
    assert_eq!(json!("Practitioner/synthetic-1"), issued["fhirUser"]);
    assert!(issued.get("act").is_none(), "no actor: {issued}");
    assert!(issued.get("patient").is_none(), "no patient: {issued}");
    assert!(issued.get("ehrId").is_none(), "no EHR: {issued}");
    let (status, body) = exchange(
        smart,
        professional["access_token"].as_str().expect("a token"),
        &[("scope", "patient/composition-*.r")],
    )
    .await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{body}");
    assert_eq!(
        json!("invalid_scope"),
        body["error"],
        "never the patient compartment"
    );
    platform.smart.stop().await;
}

#[tokio::test]
async fn a_machine_s_token_is_never_exchanged_and_is_recorded() {
    let platform = platform().await;
    let smart = &platform.smart;
    let now = jiff::Timestamp::now().as_second();
    let machine = smart
        .settings
        .keys
        .ring(ferrohealth_smart::jws::algorithm::Algorithm::Rs256).expect("the RS256 ring")
        .current()
        .sign(
            "at+jwt",
            &json!({
                "iss": ISSUER, "sub": "backend", "aud": platform.fhir_base, "exp": now + 300,
                "iat": now, "jti": "machine-1", "client_id": "backend", "scope": "system/Patient.rs",
            }),
        )
        .expect("signs");
    smart
        .store
        .record_token(&ferrosmart::store::IssuedToken {
            jti: "machine-1",
            client_id: "backend",
            subject: "backend",
            audience: &platform.fhir_base,
            scope: "system/Patient.rs",
            issued_at: now,
            expires_at: now + 300,
            code_hash: None,
            grant_id: None,
        })
        .await
        .expect("recorded");
    let (status, body) = exchange(smart, &machine, &[]).await;
    assert_eq!(StatusCode::BAD_REQUEST, status);
    assert_eq!(json!("invalid_request"), body["error"]);
    let refused = records(&smart.store)
        .await
        .iter()
        .filter(|record| record.to_string().contains("invalid_request"))
        .count();
    assert_eq!(1, refused, "the refusal is recorded");
    platform.smart.stop().await;
}

#[tokio::test]
async fn an_expired_revoked_or_foreign_subject_token_is_refused() {
    let platform = platform().await;
    let smart = &platform.smart;
    let subject = token_at_fhir(&platform, FHIR_SCOPE, "Patient/p-1").await;
    let subject_token = subject["access_token"].as_str().expect("a token");
    let revoke = [("token", subject_token), ("client_id", "app")];
    let (status, _, _) = smart.post("/revoke", &revoke, None).await;
    assert_eq!(StatusCode::OK, status, "revoked");
    let (status, body) = exchange(smart, subject_token, &[]).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "revoked: {body}");
    assert_eq!(json!("invalid_request"), body["error"]);
    let now = jiff::Timestamp::now().as_second();
    let expired = smart
        .settings
        .keys
        .ring(ferrohealth_smart::jws::algorithm::Algorithm::Rs256)
        .expect("the RS256 ring")
        .current()
        .sign(
            "at+jwt",
            &json!({
                "iss": ISSUER, "sub": "synthetic", "aud": platform.fhir_base, "exp": now - 10,
                "iat": now - 310, "jti": "expired-1", "client_id": "app",
            }),
        )
        .expect("signs");
    smart
        .store
        .record_token(&ferrosmart::store::IssuedToken {
            jti: "expired-1",
            client_id: "app",
            subject: "synthetic",
            audience: &platform.fhir_base,
            scope: "patient/Observation.rs",
            issued_at: now - 310,
            expires_at: now - 10,
            code_hash: None,
            grant_id: None,
        })
        .await
        .expect("recorded");
    for token in [expired.as_str(), "not-a-token"] {
        let (status, body) = exchange(smart, token, &[]).await;
        assert_eq!(StatusCode::BAD_REQUEST, status, "{body}");
        assert_eq!(json!("invalid_request"), body["error"]);
    }
    platform.smart.stop().await;
}

#[tokio::test]
async fn a_wider_scope_another_target_an_actor_or_a_public_client_is_refused() {
    let platform = platform().await;
    let smart = &platform.smart;
    let subject = token_at_fhir(&platform, FHIR_SCOPE, "Patient/p-1").await;
    let subject_token = subject["access_token"].as_str().expect("a token");
    for (extra, error) in [
        (
            vec![("scope", "patient/composition-*.crud")],
            "invalid_scope",
        ),
        (vec![("scope", "user/composition-*.r")], "invalid_scope"),
        (vec![("scope", "patient/aql-*.rs")], "invalid_scope"),
        (
            vec![("resource", platform.fhir_base.as_str())],
            "invalid_target",
        ),
        (vec![("actor_token", subject_token)], "invalid_request"),
        (
            vec![(
                "requested_token_type",
                "urn:ietf:params:oauth:token-type:refresh_token",
            )],
            "invalid_request",
        ),
    ] {
        let (status, body) = exchange(smart, subject_token, &extra).await;
        assert_eq!(StatusCode::BAD_REQUEST, status, "{extra:?}: {body}");
        assert_eq!(json!(error), body["error"], "{extra:?}");
    }
    let public = [
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        ("client_id", "app"),
        ("subject_token", subject_token),
        ("subject_token_type", ACCESS_TOKEN),
    ];
    let (status, _, body) = smart.post("/token", &public, None).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{body}");
    assert!(body.contains("unauthorized_client"), "{body}");
    let (status, body) = exchange(
        smart,
        subject_token,
        &[("resource", platform.openehr_base.as_str())],
    )
    .await;
    assert_eq!(StatusCode::OK, status, "the paired base named: {body}");
    platform.smart.stop().await;
}
