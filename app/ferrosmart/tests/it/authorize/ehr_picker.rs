// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The patient picker at an openEHR resource server: the EHR looked up by
//! the patient's identifier as the signed-in person, and its `ehrId` in the
//! launch context (SMART on openEHR draft, Context Selection).

use super::*;

/// The patient's identifier in the deployment's subject namespace.
pub(super) const SUBJECT: &str = "ins01";
/// The deployment's subject namespace.
pub(super) const NAMESPACE: &str = "examples";
/// The patient's EHR.
pub(super) const EHR_ID: &str = "7d44b88c-4199-4bad-97dc-d78268e01398";
/// The scope the app asks for at the openEHR server.
pub(super) const SCOPE: &str = "openid fhirUser launch/patient patient/composition-*.r";

/// An openEHR server that holds the EHR [`EHR_ID`] of one subject, which
/// only the person whose `fhirUser` is `Practitioner/synthetic-1` may see,
/// and keeps the claims of every token it was shown.
pub(super) struct OpenEhr {
    /// The subject id of the EHR, in [`NAMESPACE`].
    pub(super) subject: &'static str,
    /// The claims of the tokens it was shown.
    pub(super) seen: Arc<std::sync::Mutex<Vec<Value>>>,
}

impl wiremock::Respond for OpenEhr {
    fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
        let token = request
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .unwrap_or_default();
        let Ok(claims) = jsonwebtoken::dangerous::insecure_decode_claims::<Value>(token) else {
            return ResponseTemplate::new(401);
        };
        // The clinician sees every EHR; the patient p-1 sees their own.
        let allowed = claims.get("scope") == Some(&json!("user/composition-*.r"))
            && (claims.get("fhirUser") == Some(&json!("Practitioner/synthetic-1"))
                || claims.get("fhirUser") == Some(&json!("Patient/p-1")));
        self.seen.lock().expect("held").push(claims);
        let pairs: Vec<(String, String)> = request.url.query_pairs().into_owned().collect();
        let asks =
            |name: &str, value: &str| pairs.iter().any(|(key, text)| key == name && text == value);
        // NOTE: openEHR ITS-REST 1.1.0, ehr_get_by_subject, `404` when no EHR of
        // the subject exists, which a server also answers to whom may not see it.
        if !(allowed && asks("subject_id", self.subject) && asks("subject_namespace", NAMESPACE)) {
            return ResponseTemplate::new(404);
        }
        ResponseTemplate::new(200).set_body_json(json!({
            "system_id": {"value": "openEHRSys.example.com"},
            "ehr_id": {"value": EHR_ID},
            "time_created": {"value": "2015-01-20T19:30:22.765+01:00"}
        }))
    }
}

/// Starts FerroSMART over an openEHR server whose subjects are named in
/// [`NAMESPACE`], and returns them with the claims the server sees.
pub(super) async fn ehr_launch() -> (Smart, String, Arc<std::sync::Mutex<Vec<Value>>>, MockServer) {
    let openehr = MockServer::start().await;
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/openehr/v1/ehr"))
        .respond_with(OpenEhr {
            subject: SUBJECT,
            seen: Arc::clone(&seen),
        })
        .mount(&openehr)
        .await;
    let base = format!("{}/openehr/v1", openehr.uri());
    let smart = over(&base).await;
    (smart, base, seen, openehr)
}

/// Starts FerroSMART whose one resource server is the openEHR base `base`.
async fn over(base: &str) -> Smart {
    Smart::start_over(
        "[\"authorization_code\"]",
        "[\"openid\", \"fhirUser\", \"launch/patient\", \"patient/composition-*.r\"]",
        "[\"patient/composition-*.r\"]",
        &format!(
            "[[ferrosmart.resource]]\nbase = {base:?}\nkind = \"openehr\"\n\
             subject_namespace = {NAMESPACE:?}\n"
        ),
    )
    .await
}

/// Returns the access records of `stored` that look an EHR up by subject.
pub(super) fn lookups(stored: &[Value]) -> Vec<&Value> {
    stored
        .iter()
        .filter(|record| {
            record
                .get("subtype")
                .and_then(Value::as_array)
                .is_some_and(|subtypes| {
                    subtypes.iter().any(|coding| {
                        coding.get("code") == Some(&json!("ehr_get_by_subject"))
                            && coding.get("system")
                                == Some(&json!("urn:openehr:its-rest:operation"))
                    })
                })
        })
        .collect()
}

#[tokio::test]
async fn a_standalone_launch_at_an_openehr_server_picks_the_ehr_the_person_may_see() {
    let (smart, base, seen, _openehr) = ehr_launch().await;
    let cookie = to_picker_asking(
        &smart,
        &base,
        SCOPE,
        "synthetic-person",
        "Practitioner/synthetic-1",
    )
    .await;
    let (status, _, page) = smart.get("/picker", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(page.contains("name=\"subject_id\""), "{page}");
    assert!(seen.lock().expect("held").is_empty(), "nothing asked yet");
    let (status, _, page) = smart
        .get(&format!("/picker?subject_id={SUBJECT}"), Some(&cookie))
        .await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(page.contains(&format!("value=\"{EHR_ID}\"")), "{page}");
    let token = form_token(&page);
    let (status, headers, page) = smart
        .post(
            "/picker",
            &[
                ("form_token", token.as_str()),
                ("subject_id", SUBJECT),
                ("ehr_id", EHR_ID),
            ],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    assert_eq!("/consent", location(&headers).path());
    let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
    let token = form_token(&page);
    let (_, headers, _) = smart
        .post(
            "/consent",
            &[
                ("form_token", token.as_str()),
                ("decision", "approve"),
                ("scope", "openid"),
                ("scope", "launch/patient"),
                ("scope", "patient/composition-*.r"),
            ],
            Some(&cookie),
        )
        .await;
    let code = param(&location(&headers), "code").expect("a code");
    let exchange = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("client_id", "app"),
    ];
    let (status, _, body) = smart.post("/token", &exchange, None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let body: Value = serde_json::from_str(&body).expect("JSON");
    // NOTE: SMART on openEHR draft, Context Selection, the token response carries
    // `ehrId`; no FHIR Patient is known at an openEHR base, so no `patient`.
    assert_eq!(json!(EHR_ID), body["ehrId"]);
    assert!(body.get("patient").is_none(), "{body}");
    assert!(
        body["scope"]
            .as_str()
            .is_some_and(|scope| scope.contains("patient/composition-*.r")),
        "{body}"
    );
    let access: Value = jsonwebtoken::dangerous::insecure_decode_claims(
        body["access_token"].as_str().expect("a token"),
    )
    .expect("claims");
    assert_eq!(json!(EHR_ID), access["ehrId"], "the token carries it too");

    // The lookup and the lookup again ran as the person, each with a token
    // for that request alone, revoked once it was answered.
    let shown = seen.lock().expect("held").clone();
    assert_eq!(2, shown.len(), "the lookup and the lookup again");
    for claims in &shown {
        assert_eq!(access["sub"], claims["sub"], "the person, never a system");
        assert_eq!(json!("Practitioner/synthetic-1"), claims["fhirUser"]);
        assert_eq!(json!(base), claims["aud"]);
        assert_eq!(json!("user/composition-*.r"), claims["scope"]);
        let lifetime = claims["exp"].as_i64().expect("exp") - claims["iat"].as_i64().expect("iat");
        assert!(lifetime <= 30, "a minimal lifetime: {lifetime}");
        let jti = claims["jti"].as_str().expect("a jti");
        assert!(
            smart.store.revoked(jti).await.expect("read"),
            "revoked after use"
        );
    }
    // NOTE: Regulation (EU) 2025/327 Annex II 3.2, each lookup is an access
    // record that names the patient and the EHR it reached.
    let stored = records(&smart.store).await;
    let found = lookups(&stored);
    assert_eq!(2, found.len(), "{stored:?}");
    let text = serde_json::to_string(&found).expect("JSON");
    assert!(text.contains(EHR_ID), "the EHR reached: {text}");
    assert!(text.contains(SUBJECT), "the patient named: {text}");
    smart.stop().await;
}

#[tokio::test]
async fn a_person_never_sees_or_picks_an_ehr_they_may_not_see() {
    let (smart, base, _seen, _openehr) = ehr_launch().await;
    let cookie = to_picker_asking(
        &smart,
        &base,
        SCOPE,
        "other-person",
        "Practitioner/synthetic-2",
    )
    .await;
    let (status, _, page) = smart
        .get(&format!("/picker?subject_id={SUBJECT}"), Some(&cookie))
        .await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(!page.contains(EHR_ID), "no such EHR is shown: {page}");
    assert!(page.contains("No health record you may see belongs to this identifier."));
    let token = smart
        .store
        .pending(&cookie)
        .await
        .expect("read")
        .expect("pending")
        .form_token;
    let (status, _, _) = smart
        .post(
            "/picker",
            &[
                ("form_token", token.as_str()),
                ("subject_id", SUBJECT),
                ("ehr_id", EHR_ID),
            ],
            Some(&cookie),
        )
        .await;
    assert_eq!(
        StatusCode::BAD_REQUEST,
        status,
        "a forged choice is refused"
    );
    let (_, headers, _) = smart.get("/consent", Some(&cookie)).await;
    assert_eq!(
        "/picker",
        location(&headers).path(),
        "no EHR entered the context"
    );
    smart.stop().await;
}

#[tokio::test]
async fn a_failed_lookup_is_an_error_page_and_an_access_record() {
    let openehr = MockServer::start().await;
    Mock::given(matchers::method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&openehr)
        .await;
    let base = format!("{}/openehr/v1", openehr.uri());
    let smart = over(&base).await;
    let cookie = to_picker_asking(
        &smart,
        &base,
        SCOPE,
        "synthetic-person",
        "Practitioner/synthetic-1",
    )
    .await;
    let (status, _, page) = smart
        .get(&format!("/picker?subject_id={SUBJECT}"), Some(&cookie))
        .await;
    assert_eq!(StatusCode::INTERNAL_SERVER_ERROR, status, "{page}");
    assert!(
        !page.contains("No health record"),
        "a failure is no empty result"
    );
    let pending = smart
        .store
        .pending(&cookie)
        .await
        .expect("read")
        .expect("pending");
    assert!(pending.launch_context.is_none(), "no context entered");
    let stored = records(&smart.store).await;
    assert_eq!(1, lookups(&stored).len(), "the failed lookup is recorded");
    smart.stop().await;
}

#[tokio::test]
async fn an_openehr_base_without_a_subject_namespace_offers_no_picker() {
    let smart = Smart::start_over(
        "[\"authorization_code\"]",
        "[\"openid\", \"fhirUser\", \"launch/patient\", \"patient/composition-*.r\"]",
        "[\"patient/composition-*.r\"]",
        "[[ferrosmart.resource]]\nbase = \"https://ehr.example.org/openehr/v1\"\nkind = \"openehr\"\n",
    )
    .await;
    let path = authorize_path(&[
        ("aud", "https://ehr.example.org/openehr/v1"),
        ("scope", SCOPE),
    ]);
    let (_, headers, _) = smart.get(&path, None).await;
    let upstream = location(&headers);
    let cookie = set_cookie(&headers);
    smart
        .provider
        .answer(&param(&upstream, "nonce").expect("a nonce"), &["clinician"])
        .await;
    let callback = format!(
        "/callback?code=synthetic-upstream-code&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, headers, _) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    assert_eq!(
        "/consent",
        location(&headers).path(),
        "no EHR can be looked up, so launch/patient is not offered"
    );
    let pending = smart
        .store
        .pending(&cookie)
        .await
        .expect("read")
        .expect("pending");
    let offered = pending.offered_scope.unwrap_or_default();
    assert!(!offered.contains("launch/patient"), "{offered}");
    smart.stop().await;
}
