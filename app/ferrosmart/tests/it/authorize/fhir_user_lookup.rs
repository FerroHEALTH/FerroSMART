// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The person's `fhirUser` found by an identifier search when the provider
//! sends no `fhirUser` claim (`docs/architecture.md` §13.6 item 9, #674):
//! one match is the `fhirUser`, none or several leave it out and say so.

use super::*;

/// The system of the staff identifier the lookups search.
const STAFF: &str = "urn:example:staff";

/// A FHIR server whose `Practitioner` search answers `found` ids, and the
/// claims of the tokens it was shown.
struct Directory {
    /// The ids each search answers.
    found: Vec<&'static str>,
    /// The status it answers with.
    status: u16,
    /// The claims and query of each request.
    seen: Arc<std::sync::Mutex<Vec<(Value, String)>>>,
}

impl wiremock::Respond for Directory {
    fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
        let token = request
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .unwrap_or_default();
        let claims =
            jsonwebtoken::dangerous::insecure_decode_claims::<Value>(token).unwrap_or(Value::Null);
        self.seen.lock().expect("held").push((
            claims,
            format!(
                "{}?{}",
                request.url.path(),
                request.url.query().unwrap_or_default()
            ),
        ));
        let entry: Vec<Value> = self
            .found
            .iter()
            .map(|id| json!({ "resource": { "resourceType": "Practitioner", "id": id } }))
            .collect();
        ResponseTemplate::new(self.status)
            .set_body_json(json!({ "resourceType": "Bundle", "type": "searchset", "entry": entry }))
    }
}

/// Starts FerroSMART over a FHIR server answering as `directory`, with one
/// `Practitioner` lookup by the claim `staff_id`.
async fn directory(
    found: Vec<&'static str>,
    status: u16,
) -> (
    Smart,
    MockServer,
    Arc<std::sync::Mutex<Vec<(Value, String)>>>,
) {
    let fhir = MockServer::start().await;
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    Mock::given(matchers::method("GET"))
        .respond_with(Directory {
            found,
            status,
            seen: Arc::clone(&seen),
        })
        .mount(&fhir)
        .await;
    let base = format!("{}/fhir", fhir.uri());
    let smart = Smart::start_over(
        "[\"authorization_code\"]",
        "[\"openid\", \"fhirUser\", \"user/Observation.rs\"]",
        "[\"user/Observation.rs\"]",
        &format!(
            "[[ferrosmart.resource]]\nbase = {base:?}\n\
             [[ferrosmart.resource.fhir_user_lookup]]\nresource_type = \"Practitioner\"\n\
             claim = \"staff_id\"\nsystem = {STAFF:?}\n"
        ),
    )
    .await;
    (smart, fhir, seen)
}

/// Logs in with `claims` asking `openid fhirUser user/Observation.rs` at
/// `base`, and returns the consent page with the cookie and form token.
async fn consent_with(smart: &Smart, base: &str, claims: Value) -> (String, String, String) {
    // NOTE: OpenID Connect Core 1.0 §3.1.2.1, prompt=consent drives the page that a
    // professional's administered app would spare, where the cases read the fhirUser.
    let path = authorize_path(&[
        ("aud", base),
        ("scope", "openid fhirUser user/Observation.rs"),
        ("prompt", "consent"),
    ]);
    let (_, headers, _) = smart.get(&path, None).await;
    let upstream = location(&headers);
    let cookie = set_cookie(&headers);
    let mut claims = claims;
    if let Some(members) = claims.as_object_mut() {
        members.insert(
            String::from("nonce"),
            json!(param(&upstream, "nonce").expect("a nonce")),
        );
        members.insert(String::from("sub"), json!("synthetic-person"));
        members.insert(String::from("roles"), json!(["clinician"]));
    }
    smart.provider.answer_claims(&claims).await;
    let callback = format!(
        "/callback?code=synthetic-upstream-code&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, headers, body) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{body}");
    assert_eq!("/consent", location(&headers).path(), "to the consent page");
    let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
    let token = form_token(&page);
    (cookie, token, page)
}

/// Approves every offered scope and returns the ID Token's claims.
async fn id_token(smart: &Smart, cookie: &str, token: &str) -> Value {
    let (_, headers, _) = smart
        .post(
            "/consent",
            &[
                ("form_token", token),
                ("decision", "approve"),
                ("scope", "user/Observation.rs"),
            ],
            Some(cookie),
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
    let id_token = body
        .get("id_token")
        .and_then(Value::as_str)
        .expect("an ID Token");
    jsonwebtoken::dangerous::insecure_decode_claims(id_token).expect("claims")
}

#[tokio::test]
async fn one_match_is_the_person_s_fhir_user() {
    let (smart, fhir, seen) = directory(vec!["pr-7"], 200).await;
    let base = format!("{}/fhir", fhir.uri());
    let (cookie, token, page) = consent_with(&smart, &base, json!({ "staff_id": "S-42" })).await;
    assert!(!page.contains("is not told"), "{page}");
    let claims = id_token(&smart, &cookie, &token).await;
    // NOTE: SMART App Launch 2.2.0, fhirUser relative to the request's FHIR base.
    assert_eq!(json!("Practitioner/pr-7"), claims["fhirUser"]);
    let asked = seen.lock().expect("held").clone();
    assert_eq!(1, asked.len(), "{asked:?}");
    let (token_claims, query) = &asked[0];
    // NOTE: FHIR R4 search, token parameter identifier=[system]|[code].
    assert_eq!(
        "/fhir/Practitioner?identifier=urn%3Aexample%3Astaff%7CS-42",
        query
    );
    assert_eq!(
        json!("user/Practitioner.rs"),
        token_claims["scope"],
        "as the person"
    );
    assert_eq!(json!(base), token_claims["aud"]);
    smart.stop().await;
}

#[tokio::test]
async fn a_claim_wins_over_the_lookup() {
    let (smart, fhir, seen) = directory(vec!["pr-7"], 200).await;
    let base = format!("{}/fhir", fhir.uri());
    let (cookie, token, _) = consent_with(
        &smart,
        &base,
        json!({ "staff_id": "S-42", "fhir_user": "Practitioner/from-claim" }),
    )
    .await;
    let claims = id_token(&smart, &cookie, &token).await;
    assert_eq!(json!("Practitioner/from-claim"), claims["fhirUser"]);
    assert!(seen.lock().expect("held").is_empty(), "no search");
    smart.stop().await;
}

#[tokio::test]
async fn no_match_several_matches_or_a_refusal_leave_fhir_user_out_and_say_so() {
    for (found, status) in [
        (vec![], 200),
        (vec!["pr-7", "pr-8"], 200),
        (vec!["pr-7"], 403),
    ] {
        let (smart, fhir, _) = directory(found.clone(), status).await;
        let base = format!("{}/fhir", fhir.uri());
        let (_, _, page) = consent_with(&smart, &base, json!({ "staff_id": "S-42" })).await;
        assert!(
            page.contains("is linked to no single record here, so it is not told"),
            "{found:?} {status}: {page}"
        );
        assert!(
            !page.contains("<code class=\"fui-scope-raw\">fhirUser</code>")
                && !page.contains("value=\"fhirUser\""),
            "fhirUser not offered: {page}"
        );
        smart.stop().await;
    }
}

#[tokio::test]
async fn a_person_without_the_claim_is_not_searched() {
    let (smart, fhir, seen) = directory(vec!["pr-7"], 200).await;
    let base = format!("{}/fhir", fhir.uri());
    let (_, _, page) = consent_with(&smart, &base, json!({})).await;
    assert!(page.contains("is not told"), "{page}");
    assert!(seen.lock().expect("held").is_empty(), "no value, no search");
    smart.stop().await;
}
