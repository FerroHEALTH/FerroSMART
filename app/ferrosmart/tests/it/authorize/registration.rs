// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Whether the person sees the consent page, from who they are and how the
//! client was registered (`docs/architecture.md` §13.6 item 6): one case
//! per cell of the rule, and the flows each cell leads to.

use ferrosmart::authorize::consent::{Basis, Person, without_page};
use ferrosmart::clients::Registration;

use super::*;

/// The ceiling of the case's app.
const CEILING: &str = "[\"openid\", \"fhirUser\", \"offline_access\", \"user/Observation.rs\", \"patient/Observation.rs\"]";

/// Starts FerroSMART whose app an administrator registered, first party
/// when `first_party`.
async fn start(first_party: bool) -> Smart {
    Smart::start_with(
        "[\"authorization_code\", \"refresh_token\"]",
        &format!("{CEILING}\nfirst_party = {first_party}"),
        "[\"user/Observation.rs\", \"patient/Observation.rs\"]",
    )
    .await
}

/// Runs the authorization request asking for `scope` and the login of the
/// person whose `fhirUser` is `fhir_user`, and returns the cookie and where
/// the callback sends the browser.
async fn login(smart: &Smart, scope: &str, fhir_user: &str) -> (String, Url) {
    let (status, headers, _) = smart.get(&authorize_path(&[("scope", scope)]), None).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "on to the provider");
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
        "/callback?code=a&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, headers, _) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "the login returns");
    (cookie, location(&headers))
}

/// Exchanges the code `back` carries and returns the token response.
async fn exchange(smart: &Smart, back: &Url) -> Value {
    let code = param(back, "code").expect("a code");
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("client_id", "app"),
    ];
    let (status, _, body) = smart.post("/token", &form, None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    serde_json::from_str(&body).expect("JSON")
}

/// Returns the app of the rule's cases, first party when `first_party`.
fn app(first_party: bool) -> ferrosmart::clients::Client {
    resolve(
        &ClientMetadata {
            client_id: String::from("app"),
            auth_method: AuthMethod::None,
            redirect_uris: vec![String::from(REDIRECT)],
            grant_types: vec![GrantType::AuthorizationCode],
            scopes: vec![String::from("openid"), String::from("user/Observation.rs")],
            first_party,
            ..ClientMetadata::default()
        },
        Material::default(),
    )
    .expect("admitted")
}

// NOTE: RFC 6749 §4.1.1, OpenID Connect Core 1.0 §3.1.2.4, SMART App Launch 2.2.0
// Best Practices, RFC 7591 §5 and Regulation (EU) 2025/327 Art 3, 4(2), 7(1).
#[test]
fn the_page_follows_the_person_and_the_registration() {
    let administered = app(false);
    let first_party = app(true);
    let mut registered_itself = app(false);
    registered_itself.registration = Registration::Dynamic;
    let offered = ["openid", "user/Observation.rs"];
    for (fhir_user, cells) in [
        (
            Some("Practitioner/1"),
            [
                Some(Basis::Administrative),
                Some(Basis::Administrative),
                None,
            ],
        ),
        (
            Some("https://ehr.example.org/fhir/PractitionerRole/1"),
            [
                Some(Basis::Administrative),
                Some(Basis::Administrative),
                None,
            ],
        ),
        (Some("Patient/2"), [None, Some(Basis::FirstParty), None]),
        (
            Some("RelatedPerson/3"),
            [None, Some(Basis::FirstParty), None],
        ),
        (Some("Person/4"), [None, Some(Basis::FirstParty), None]),
        (None, [None, None, None]),
        (Some("Device/5"), [None, None, None]),
    ] {
        let person = Person::of(fhir_user);
        for (client, expected) in [&administered, &first_party, &registered_itself]
            .into_iter()
            .zip(cells)
        {
            assert_eq!(
                expected,
                without_page(client, person, &offered),
                "{fhir_user:?} for {:?}",
                client.registration
            );
        }
    }
    assert_eq!(
        None,
        without_page(
            &administered,
            Person::of(Some("Practitioner/1")),
            &["openid", "user/Patient.rs"]
        ),
        "a scope beyond the registration's ceiling"
    );
}

#[tokio::test]
async fn a_professional_s_login_of_an_administered_app_skips_the_page_within_its_bounds() {
    let smart = start(false).await;
    // NOTE: docs/architecture.md §13.6 item 6, the granted scope is the request,
    // the ceiling and the roles together: user/Encounter.rs is beyond the ceiling.
    let (_, back) = login(
        &smart,
        "openid fhirUser user/Observation.rs user/Encounter.rs",
        "Practitioner/synthetic-1",
    )
    .await;
    assert!(back.as_str().starts_with(REDIRECT), "no page: {back}");
    let body = exchange(&smart, &back).await;
    assert_eq!(json!("openid fhirUser user/Observation.rs"), body["scope"]);
    // NOTE: docs/architecture.md §13.2, the skipped page writes its record and the
    // code's record names its basis.
    let kept = records(&smart.store).await;
    assert!(
        events(&kept).contains(&String::from("consent-administrative")),
        "{:?}",
        events(&kept)
    );
    assert_eq!(vec![String::from("administrative")], bases(&kept));
    smart.stop().await;
}

#[tokio::test]
async fn a_patient_s_login_of_an_app_of_another_party_shows_the_page() {
    let smart = start(false).await;
    let (_, back) = login(&smart, "openid fhirUser", "Patient/synthetic-2").await;
    assert_eq!("/consent", back.path(), "the patient decides");
    smart.stop().await;
}

#[tokio::test]
async fn a_login_with_no_fhir_user_shows_the_page() {
    let smart = start(true).await;
    let (_, headers, _) = smart
        .get(
            &authorize_path(&[("scope", "openid user/Observation.rs")]),
            None,
        )
        .await;
    let upstream = location(&headers);
    let cookie = set_cookie(&headers);
    smart
        .provider
        .answer_as(
            &param(&upstream, "nonce").expect("a nonce"),
            &["clinician"],
            "synthetic-person",
            "",
        )
        .await;
    let callback = format!(
        "/callback?code=a&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (_, headers, _) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(
        "/consent",
        location(&headers).path(),
        "a person of no stated type"
    );
    smart.stop().await;
}

#[tokio::test]
async fn a_patient_s_login_of_a_first_party_app_skips_the_page_until_the_mark_is_cleared() {
    let smart = start(true).await;
    let (_, back) = login(
        &smart,
        "openid fhirUser offline_access",
        "Patient/synthetic-2",
    )
    .await;
    assert!(back.as_str().starts_with(REDIRECT), "no page: {back}");
    let body = exchange(&smart, &back).await;
    let token = body["refresh_token"].as_str().expect("a refresh token");
    let kept = records(&smart.store).await;
    assert!(events(&kept).contains(&String::from("consent-first-party")));
    assert_eq!(vec![String::from("first-party")], bases(&kept));
    let (_, page) = manage_visit(&smart).await;
    assert!(page.contains("This is your organisation"), "{page}");

    // NOTE: docs/architecture.md §13.6 item 6, clearing the mark revokes what was
    // issued on it, in the change's transaction.
    let administrator = AppState::new(
        smart.settings.clone(),
        smart.store.clone(),
        audit(&smart.settings),
    );
    let mut cleared = smart.clients.clone();
    for client in &mut cleared {
        client["first_party"] = json!(false);
    }
    crate::support::apply(&administrator, &cleared).await;
    let (status, refused) = refresh(&smart, token).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{refused}");
    assert_eq!(json!("invalid_grant"), refused["error"]);
    let (_, back) = login(
        &smart,
        "openid fhirUser offline_access",
        "Patient/synthetic-2",
    )
    .await;
    assert_eq!("/consent", back.path(), "the page once the mark is cleared");
    smart.stop().await;
}

// NOTE: docs/architecture.md §13.6 item 6, a remembered consent answers on the
// page path alone: a patient's for an app of another party.
#[tokio::test]
async fn a_remembered_consent_answers_a_patient_s_next_login() {
    let smart = start(false).await;
    let scope = "openid fhirUser offline_access";
    let (cookie, back) = login(&smart, scope, "Patient/synthetic-2").await;
    assert_eq!("/consent", back.path());
    let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
    let (status, headers, _) = smart
        .post(
            "/consent",
            &[
                ("form_token", form_token(&page).as_str()),
                ("decision", "approve"),
                ("remember", "yes"),
            ],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    assert!(location(&headers).as_str().starts_with(REDIRECT));
    let (_, back) = login(&smart, scope, "Patient/synthetic-2").await;
    assert!(back.as_str().starts_with(REDIRECT), "remembered: {back}");
    let kept = records(&smart.store).await;
    assert_eq!(
        vec![String::from("page"), String::from("remembered")],
        bases(&kept)
    );
    smart.stop().await;
}

#[tokio::test]
async fn a_patient_disconnects_the_organisation_s_own_app_and_its_registration_stays() {
    let smart = start(true).await;
    let (_, back) = login(
        &smart,
        "openid fhirUser offline_access",
        "Patient/synthetic-2",
    )
    .await;
    assert!(back.as_str().starts_with(REDIRECT), "no page: {back}");
    let body = exchange(&smart, &back).await;
    let token = body["refresh_token"].as_str().expect("a refresh token");
    // NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, offline_access lasts
    // "as long as the authorization server and end-user will allow".
    let (cookie, page) = manage_visit(&smart).await;
    assert!(
        page.contains("This is your organisation")
            && page.contains("This app stays connected after you sign out"),
        "{page}"
    );
    let (status, _, _) = smart
        .post(
            "/manage",
            &[
                ("form_token", form_token(&page).as_str()),
                ("client_id", "app"),
            ],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status, "disconnected");
    let (status, refused) = refresh(&smart, token).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{refused}");
    assert_eq!(json!("invalid_grant"), refused["error"]);
    let kept = records(&smart.store).await;
    assert!(events(&kept).contains(&String::from("consent-withdrawn")));
    let (_, back) = login(
        &smart,
        "openid fhirUser offline_access",
        "Patient/synthetic-2",
    )
    .await;
    assert!(
        back.as_str().starts_with(REDIRECT),
        "the registration answers the next sign-in: {back}"
    );
    smart.stop().await;
}
