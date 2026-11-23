// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The patients the picker offers before a search: the person's recent
//! choices at the base asked and, where the base names a search for them,
//! the patients assigned to them, each read as the person before the page
//! shows them (`docs/architecture.md` §13.6 item 4).

use super::*;

/// The patient on the care team of `Practitioner/synthetic-1`.
const ASSIGNED: &str = "p-2";

/// Chooses the patient `p-1` on the picker `cookie` holds, by a search.
async fn choose_p1(smart: &Smart, cookie: &str) {
    let (_, _, page) = smart.get("/picker?name=Synthetic", Some(cookie)).await;
    let token = form_token(&page);
    let (status, headers, _) = smart
        .post(
            "/picker",
            &[("form_token", &token), ("patient", "p-1")],
            Some(cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status, "the choice is taken");
    assert_eq!("/consent", location(&headers).path(), "on to the consent");
}

/// Returns the queries of the requests `fhir` received at `path`.
async fn asked(fhir: &MockServer, path: &str) -> Vec<String> {
    fhir.received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|request| request.url.path() == path)
        .map(|request| request.url.query().unwrap_or_default().to_owned())
        .collect()
}

#[tokio::test]
async fn the_picker_offers_the_person_s_recent_patients_read_again_as_them() {
    let (smart, fhir, seen) = picker_launch().await;
    let base = format!("{}/fhir", fhir.uri());
    let cookie = to_picker(
        &smart,
        &base,
        "synthetic-person",
        "Practitioner/synthetic-1",
    )
    .await;
    let (_, _, page) = smart.get("/picker", Some(&cookie)).await;
    assert!(
        !page.contains("Patients you chose lately"),
        "none yet: {page}"
    );
    choose_p1(&smart, &cookie).await;

    let cookie = to_picker(
        &smart,
        &base,
        "synthetic-person",
        "Practitioner/synthetic-1",
    )
    .await;
    seen.lock().expect("held").clear();
    let (status, _, page) = smart.get("/picker", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(
        page.contains("Patients you chose lately")
            && page.contains("value=\"p-1\"")
            && page.contains("Synthetic Patient"),
        "{page}"
    );
    let shown = seen.lock().expect("held").clone();
    assert_eq!(1, shown.len(), "one search reads the recent patients again");
    assert_eq!(json!("Practitioner/synthetic-1"), shown[0]["fhirUser"]);
    assert_eq!(json!("user/Patient.rs"), shown[0]["scope"]);
    assert!(
        asked(&fhir, "/fhir/Patient")
            .await
            .iter()
            .any(|query| query.contains("_id=p-1")),
        "by _id"
    );

    let cookie = to_picker(&smart, &base, "another-person", "Practitioner/synthetic-1").await;
    let (_, _, page) = smart.get("/picker", Some(&cookie)).await;
    assert!(
        !page.contains("value=\"p-1\""),
        "another person's list: {page}"
    );
    smart.stop().await;
}

#[tokio::test]
async fn a_recent_patient_the_person_may_no_longer_see_is_not_shown() {
    let (smart, fhir, _) = picker_launch().await;
    let base = format!("{}/fhir", fhir.uri());
    let cookie = to_picker(
        &smart,
        &base,
        "synthetic-person",
        "Practitioner/synthetic-1",
    )
    .await;
    choose_p1(&smart, &cookie).await;
    let cookie = to_picker(
        &smart,
        &base,
        "synthetic-person",
        "Practitioner/synthetic-9",
    )
    .await;
    let (status, _, page) = smart.get("/picker", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(
        !page.contains("value=\"p-1\""),
        "the read again finds none: {page}"
    );
    smart.stop().await;
}

#[tokio::test]
async fn the_recent_list_keeps_a_choice_for_the_retention_and_the_person_forgets_it() {
    let (smart, fhir, _) = picker_launch().await;
    let base = format!("{}/fhir", fhir.uri());
    let cookie = to_picker(
        &smart,
        &base,
        "synthetic-person",
        "Practitioner/synthetic-1",
    )
    .await;
    choose_p1(&smart, &cookie).await;
    let subject = smart
        .store
        .pending(&cookie)
        .await
        .expect("reads")
        .and_then(|pending| pending.subject)
        .expect("signed in");
    let day = std::time::Duration::from_hours(24);
    assert_eq!(
        vec![String::from("p-1")],
        smart
            .store
            .recent_patients(&subject, &base, day)
            .await
            .expect("reads")
    );
    smart.store.sweep_recent(day).await.expect("sweeps");
    assert_eq!(
        1,
        smart.store.recent_count(&subject).await.expect("counts"),
        "kept within it"
    );
    smart
        .store
        .sweep_recent(std::time::Duration::ZERO)
        .await
        .expect("sweeps");
    assert_eq!(
        0,
        smart.store.recent_count(&subject).await.expect("counts"),
        "gone past it"
    );

    let cookie = to_picker(
        &smart,
        &base,
        "synthetic-person",
        "Practitioner/synthetic-1",
    )
    .await;
    choose_p1(&smart, &cookie).await;
    let (cookie, page) = manage_visit(&smart).await;
    assert!(page.contains("keeps one patient you chose"), "{page}");
    let token = form_token(&page);
    let (status, headers, _) = smart
        .post(
            "/manage",
            &[("form_token", token.as_str()), ("forget", "recent")],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    assert_eq!("/manage", location(&headers).path());
    assert_eq!(0, smart.store.recent_count(&subject).await.expect("counts"));
    let happened = events(&records(&smart.store).await);
    assert!(
        happened.contains(&String::from("recent-patients-forgotten")),
        "{happened:?}"
    );
    smart.stop().await;
}

/// A FHIR server's care-team search: the care team of
/// `Practitioner/synthetic-1` with its patient [`ASSIGNED`] included, for a
/// token of the care-team scope alone.
struct CareTeams;

impl wiremock::Respond for CareTeams {
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
        let pairs: Vec<(String, String)> = request.url.query_pairs().into_owned().collect();
        let asks =
            |name: &str, value: &str| pairs.iter().any(|(key, text)| key == name && text == value);
        let entry = if claims.get("scope") == Some(&json!("user/CareTeam.rs user/Patient.rs"))
            && asks("participant", "Practitioner/synthetic-1")
            && asks("status", "active")
            && asks("_include", "CareTeam:patient")
        {
            vec![
                json!({"resource": {"resourceType": "CareTeam", "id": "t-1",
                    "subject": {"reference": format!("Patient/{ASSIGNED}")}},
                    "search": {"mode": "match"}}),
                json!({"resource": {"resourceType": "Patient", "id": ASSIGNED,
                    "name": [{"given": ["Assigned"], "family": "Patient"}]},
                    "search": {"mode": "include"}}),
            ]
        } else {
            Vec::new()
        };
        ResponseTemplate::new(200)
            .set_body_json(json!({"resourceType": "Bundle", "type": "searchset", "entry": entry}))
    }
}

#[tokio::test]
async fn the_picker_lists_the_patients_of_the_person_s_care_teams() {
    let fhir = MockServer::start().await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/fhir/CareTeam"))
        .respond_with(CareTeams)
        .with_priority(1)
        .mount(&fhir)
        .await;
    let base = format!("{}/fhir", fhir.uri());
    let smart = Smart::start_over(
        "[\"authorization_code\"]",
        "[\"openid\", \"fhirUser\", \"launch/patient\", \"patient/Observation.rs\"]",
        "[\"patient/Observation.rs\"]",
        &format!("[[ferrosmart.resource]]\nbase = {base:?}\nassigned = \"care_team\"\n"),
    )
    .await;
    let cookie = to_picker(
        &smart,
        &base,
        "synthetic-person",
        "Practitioner/synthetic-1",
    )
    .await;
    let (status, _, page) = smart.get("/picker", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(
        page.contains("Patients assigned to you")
            && page.contains(&format!("value=\"{ASSIGNED}\""))
            && page.contains("Assigned Patient"),
        "{page}"
    );
    let cookie = to_picker(&smart, &base, "another-person", "Practitioner/synthetic-9").await;
    let (_, _, page) = smart.get("/picker", Some(&cookie)).await;
    assert!(
        !page.contains("Patients assigned to you"),
        "on no care team: {page}"
    );
    smart.stop().await;
}

#[test]
fn an_assigned_search_is_for_a_fhir_base() {
    let keys = Keys::new();
    let text = "[ferrosmart]\nissuer = \"https://smart.example.org\"\n\
         [[ferrosmart.resource]]\nbase = \"https://ehr.example.org/openehr\"\nkind = \"openehr\"\n\
         assigned = \"encounter\"\n";
    assert!(matches!(
        config(text, &keys).resolve(),
        Err(ferrosmart::config::error::Error::Resource { .. })
    ));
}

#[tokio::test]
async fn the_openehr_picker_offers_the_recent_ehrs_looked_up_again_as_the_person() {
    use super::ehr_picker::{EHR_ID, SCOPE, SUBJECT, ehr_launch, lookups};
    let (smart, base, _seen, _openehr) = ehr_launch().await;
    let practitioner = "Practitioner/synthetic-1";
    let cookie = to_picker_asking(&smart, &base, SCOPE, "synthetic-person", practitioner).await;
    let (_, _, page) = smart.get("/picker", Some(&cookie)).await;
    assert!(
        !page.contains("Patients you chose lately"),
        "none yet: {page}"
    );
    let (_, _, page) = smart
        .get(&format!("/picker?subject_id={SUBJECT}"), Some(&cookie))
        .await;
    let token = form_token(&page);
    let choice = [
        ("form_token", token.as_str()),
        ("subject_id", SUBJECT),
        ("ehr_id", EHR_ID),
    ];
    let (status, _, _) = smart.post("/picker", &choice, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "the choice is taken");

    let cookie = to_picker_asking(&smart, &base, SCOPE, "synthetic-person", practitioner).await;
    let before = lookups(&records(&smart.store).await).len();
    let (status, _, page) = smart.get("/picker", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(
        page.contains("Patients you chose lately")
            && page.contains(&format!("name=\"ehr_id\" value=\"{EHR_ID}\"")),
        "{page}"
    );
    assert_eq!(
        before + 1,
        lookups(&records(&smart.store).await).len(),
        "looked up again as the person, with its access record"
    );
    smart.stop().await;
}
