// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! An organisation's approval of its own app: a professional's standalone
//! launch skips the consent page within the approved set, a request beyond
//! it, a `patient/` request and a patient's own login each show the page,
//! a person disconnects an approved app and keeps its approval, and
//! withdrawing the approval revokes what was issued on it
//! (`docs/architecture.md` §13.6 item 6; SMART App Launch 2.2.0, Obtain
//! authorization code, Response).

use super::*;

/// The ceiling of the approved app, with its organisation approval of
/// `scopes`, a TOML array.
fn approved(scopes: &str) -> String {
    format!(
        "[\"openid\", \"fhirUser\", \"user/Observation.rs\", \"user/Patient.rs\", \"patient/Observation.rs\"]\n\
         [ferrosmart.client.organisation_approval]\nscopes = {scopes}\n\
         approved_by = \"Synthetic Administrator\"\napproved_at = \"2026-11-19T09:00:00Z\""
    )
}

/// Starts FerroSMART whose app the organisation approved for `scopes`.
async fn start(scopes: &str) -> Smart {
    Smart::start_with(
        "[\"authorization_code\"]",
        &approved(scopes),
        "[\"user/Observation.rs\", \"patient/Observation.rs\"]",
    )
    .await
}

/// Starts FerroSMART whose app is the organisation's own (first party),
/// approved for `scopes`.
async fn start_first_party(scopes: &str) -> Smart {
    Smart::start_with(
        "[\"authorization_code\"]",
        &format!("{}\nfirst_party = true", approved(scopes)),
        "[\"user/Observation.rs\", \"patient/Observation.rs\"]",
    )
    .await
}

/// Runs the authorization request asking for `scope` and the login of the
/// person whose `fhirUser` is `fhir_user`, and returns where the callback
/// sends the browser.
async fn login(smart: &Smart, scope: &str, fhir_user: &str) -> Url {
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
    location(&headers)
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

#[tokio::test]
async fn a_professional_s_launch_of_an_approved_app_skips_the_page_within_four_bounds() {
    let smart =
        start("[\"openid\", \"fhirUser\", \"user/Observation.rs\", \"user/Patient.rs\"]").await;
    // NOTE: docs/architecture.md §13.6 item 6, the granted scope is the request,
    // the ceiling, the roles and the approval together: user/Encounter.rs is
    // beyond the ceiling and user/Patient.rs beyond the roles.
    let back = login(
        &smart,
        "openid fhirUser user/Observation.rs user/Patient.rs user/Encounter.rs",
        "Practitioner/synthetic-1",
    )
    .await;
    assert!(
        back.as_str().starts_with(REDIRECT),
        "no consent page: {back}"
    );
    let body = exchange(&smart, &back).await;
    assert_eq!(
        json!("openid fhirUser user/Observation.rs"),
        body["scope"],
        "the four bounds together"
    );
    // NOTE: docs/architecture.md §13.2, the skipped page writes its record with
    // the approval as its basis.
    let kept = records(&smart.store).await;
    assert!(
        events(&kept).contains(&String::from("consent-organisation-approved")),
        "{:?}",
        events(&kept)
    );
    let text = serde_json::to_string(&kept).expect("JSON");
    assert!(
        text.contains("Synthetic Administrator"),
        "the approver is recorded"
    );

    // NOTE: SMART App Launch 2.2.0, Conformance, management_endpoint: the app is
    // listed as approved by the organisation, with its Disconnect form.
    let (_cookie, page) = manage_visit(&smart).await;
    assert!(page.contains("Synthetic App"), "{page}");
    assert!(
        page.contains("Your organisation approved this app for its staff"),
        "{page}"
    );
    assert!(
        page.contains("name=\"client_id\" value=\"app\"") && page.contains("Disconnect"),
        "the person can disconnect it: {page}"
    );

    // NOTE: docs/architecture.md §13.6 item 6, the administrator clears the
    // approval; the tokens issued on it are revoked at the next start.
    let claims: Value = jsonwebtoken::dangerous::insecure_decode_claims(
        body["access_token"].as_str().expect("a token"),
    )
    .expect("claims");
    let jti = claims["jti"].as_str().expect("a jti");
    let mut cleared = smart.settings.clients.clone();
    for client in &mut cleared {
        client.registration = ferrosmart::clients::Registration::Administered(None);
    }
    let issuer = smart.settings.endpoint_url("");
    let origin = ferrosmart::approvals::Origin {
        issuer: &smart.settings.issuer,
        endpoint: &issuer,
        host: std::net::IpAddr::from([127, 0, 0, 1]),
    };
    let withdrawn = ferrosmart::approvals::withdraw_lapsed(
        &smart.store,
        &audit(&smart.settings),
        &cleared,
        origin,
    )
    .await
    .expect("withdrawn");
    assert_eq!(vec![String::from("app")], withdrawn, "the cleared approval");
    smart.store.register(&cleared).await.expect("registered");
    let record = smart
        .store
        .access_token(jti)
        .await
        .expect("read")
        .expect("recorded");
    assert!(
        !record.active,
        "the token issued on the approval is revoked"
    );
    assert!(
        events(&records(&smart.store).await)
            .contains(&String::from("organisation-approval-withdrawn")),
        "the withdrawal is recorded"
    );
    let back = login(
        &smart,
        "openid fhirUser user/Observation.rs",
        "Practitioner/synthetic-1",
    )
    .await;
    assert_eq!("/consent", back.path(), "the page again once withdrawn");
    smart.stop().await;
}

#[tokio::test]
async fn a_request_beyond_the_approval_shows_the_page() {
    let smart = start("[\"openid\", \"fhirUser\"]").await;
    let back = login(
        &smart,
        "openid fhirUser user/Observation.rs",
        "Practitioner/synthetic-1",
    )
    .await;
    assert_eq!("/consent", back.path(), "beyond the approved set");
    smart.stop().await;
}

#[tokio::test]
async fn a_request_with_a_patient_scope_shows_the_page() {
    let smart = start("[\"openid\", \"fhirUser\", \"user/Observation.rs\"]").await;
    let back = login(
        &smart,
        "openid fhirUser user/Observation.rs patient/Observation.rs",
        "Practitioner/synthetic-1",
    )
    .await;
    assert_eq!(
        "/consent",
        back.path(),
        "the person decides about patient data"
    );
    smart.stop().await;
}

#[tokio::test]
async fn a_patient_s_own_login_shows_the_page() {
    let smart = start("[\"openid\", \"fhirUser\", \"user/Observation.rs\"]").await;
    let back = login(
        &smart,
        "openid fhirUser user/Observation.rs",
        "Patient/synthetic-2",
    )
    .await;
    assert_eq!(
        "/consent",
        back.path(),
        "a patient decides about their own data"
    );
    smart.stop().await;
}

#[test]
fn an_approval_beyond_the_ceiling_or_of_a_system_scope_is_refused() {
    let section = |scopes: &[&str], first_party: bool| ClientSection {
        client_id: String::from("app"),
        kind: ClientKind::Public,
        redirect_uris: vec![String::from(REDIRECT)],
        grant_types: vec![GrantType::AuthorizationCode],
        scopes: ["openid", "user/Observation.rs", "patient/Observation.rs"]
            .into_iter()
            .map(String::from)
            .collect(),
        organisation_approval: Some(ferrosmart::clients::ApprovalSection {
            scopes: scopes.iter().map(|scope| String::from(*scope)).collect(),
            approved_by: String::from("Synthetic Administrator"),
            approved_at: String::from("2026-11-19T09:00:00Z"),
            first_party,
        }),
        ..ClientSection::default()
    };
    assert!(
        resolve(&[section(&["openid", "user/Observation.rs"], false)]).is_ok(),
        "a user/ scope within the ceiling"
    );
    assert!(
        resolve(&[section(&["openid", "patient/Observation.rs"], true)]).is_ok(),
        "a patient/ scope within the ceiling, for the organisation's own app"
    );
    for refused in [&["user/Patient.rs"][..], &["system/Observation.rs"][..]] {
        assert!(resolve(&[section(refused, true)]).is_err(), "{refused:?}");
    }
    // NOTE: OpenID Connect Core 1.0 §3.1.2.4 (owner, 2026-11-20, #727): a staff
    // approval may cover patient/ scopes, which answer a professional's EHR launch.
    assert!(
        resolve(&[section(&["openid", "patient/Observation.rs"], false)]).is_ok(),
        "a patient/ scope within the ceiling, for staff"
    );
    for refused in [
        &["user/Patient.rs"][..],
        &["system/Observation.rs"][..],
        &[][..],
    ] {
        assert!(resolve(&[section(refused, false)]).is_err(), "{refused:?}");
    }
}

#[tokio::test]
async fn a_patient_s_launch_of_a_first_party_app_skips_the_page_and_is_withdrawn_by_the_administrator()
 {
    let smart = start_first_party("[\"openid\", \"fhirUser\", \"patient/Observation.rs\"]").await;
    let back = login(
        &smart,
        "openid fhirUser patient/Observation.rs",
        "Patient/synthetic-2",
    )
    .await;
    assert!(
        back.as_str().starts_with(REDIRECT),
        "no consent page for the organisation's own app: {back}"
    );
    let body = exchange(&smart, &back).await;
    // NOTE: docs/architecture.md §13.6 item 5, a standalone launch with no patient
    // chosen offers no patient/ scope; the EHR launch case holds one with a patient.
    assert_eq!(json!("openid fhirUser"), body["scope"]);
    // NOTE: docs/architecture.md §13.2, the skipped page writes its record with
    // the first-party approval as its basis.
    let kept = records(&smart.store).await;
    assert!(
        events(&kept).contains(&String::from("consent-first-party-approved")),
        "{:?}",
        events(&kept)
    );
    assert!(
        !events(&kept).contains(&String::from("consent-organisation-approved")),
        "the basis is the first-party approval"
    );

    // NOTE: SMART App Launch 2.2.0, Conformance, management_endpoint: the app is
    // listed as the organisation's own, with its Disconnect form.
    let (_cookie, page) = manage_visit(&smart).await;
    assert!(page.contains("This is your organisation"), "{page}");
    assert!(
        page.contains("name=\"client_id\" value=\"app\"") && page.contains("Disconnect"),
        "the patient can disconnect it: {page}"
    );

    // NOTE: docs/architecture.md §13.6 item 6, the administrator clears the mark,
    // a new approval: what was issued on the first-party approval is revoked.
    let claims: Value = jsonwebtoken::dangerous::insecure_decode_claims(
        body["access_token"].as_str().expect("a token"),
    )
    .expect("claims");
    let jti = claims["jti"].as_str().expect("a jti");
    let mut cleared = smart.settings.clients.clone();
    for client in &mut cleared {
        if let ferrosmart::clients::Registration::Administered(Some(approval)) =
            &mut client.registration
        {
            approval.first_party = false;
            approval.scopes = vec![String::from("openid"), String::from("fhirUser")];
        }
    }
    let issuer = smart.settings.endpoint_url("");
    let origin = ferrosmart::approvals::Origin {
        issuer: &smart.settings.issuer,
        endpoint: &issuer,
        host: std::net::IpAddr::from([127, 0, 0, 1]),
    };
    let withdrawn = ferrosmart::approvals::withdraw_lapsed(
        &smart.store,
        &audit(&smart.settings),
        &cleared,
        origin,
    )
    .await
    .expect("withdrawn");
    assert_eq!(vec![String::from("app")], withdrawn, "the changed approval");
    smart.store.register(&cleared).await.expect("registered");
    let record = smart
        .store
        .access_token(jti)
        .await
        .expect("read")
        .expect("recorded");
    assert!(
        !record.active,
        "the token issued on the approval is revoked"
    );
    let back = login(&smart, "openid fhirUser", "Patient/synthetic-2").await;
    assert_eq!(
        "/consent",
        back.path(),
        "a patient sees the page once the app is no longer first party"
    );
    smart.stop().await;
}

#[tokio::test]
async fn a_patient_s_request_beyond_a_first_party_approval_shows_the_page() {
    let smart = start_first_party("[\"openid\"]").await;
    let back = login(&smart, "openid fhirUser", "Patient/synthetic-2").await;
    assert_eq!("/consent", back.path(), "beyond the approved set");
    smart.stop().await;
}

#[tokio::test]
async fn a_patient_s_launch_of_a_third_party_approved_app_shows_the_page() {
    let smart = start("[\"openid\", \"fhirUser\", \"user/Observation.rs\"]").await;
    let back = login(&smart, "openid fhirUser", "Patient/synthetic-2").await;
    assert_eq!(
        "/consent",
        back.path(),
        "an app without the first-party mark never skips a patient's page"
    );
    smart.stop().await;
}

#[tokio::test]
async fn a_patient_disconnects_the_organisation_s_own_app_and_its_approval_stays() {
    let smart = Smart::start_with(
        "[\"authorization_code\", \"refresh_token\"]",
        "[\"openid\", \"fhirUser\", \"offline_access\", \"patient/Observation.rs\"]\n\
         [ferrosmart.client.organisation_approval]\n\
         scopes = [\"openid\", \"fhirUser\", \"offline_access\", \"patient/Observation.rs\"]\n\
         approved_by = \"Synthetic Administrator\"\napproved_at = \"2026-11-19T09:00:00Z\"\n\
         first_party = true",
        "[\"patient/Observation.rs\"]",
    )
    .await;
    let back = login(
        &smart,
        "openid fhirUser offline_access",
        "Patient/synthetic-2",
    )
    .await;
    assert!(back.as_str().starts_with(REDIRECT), "no page: {back}");
    let body = exchange(&smart, &back).await;
    let token = body["refresh_token"].as_str().expect("a refresh token");
    // NOTE: docs/architecture.md §13.2, the code's record names its basis.
    assert_eq!(
        vec![String::from("first-party")],
        bases(&records(&smart.store).await)
    );

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
    let (_, _, page) = smart.get("/manage", Some(&cookie)).await;
    assert!(page.contains("No app keeps access to your data."), "{page}");

    // NOTE: docs/architecture.md §13.2, the disconnect commits with its record.
    let kept = records(&smart.store).await;
    let disconnect = kept
        .iter()
        .find(|record| {
            events(std::slice::from_ref(*record)).contains(&String::from("consent-withdrawn"))
        })
        .expect("the disconnect is recorded");
    let text = serde_json::to_string(disconnect).expect("JSON");
    assert!(
        text.contains("grants"),
        "the revoked grants are named: {text}"
    );

    // NOTE: docs/architecture.md §13.6 item 6, the approval is an administrator's;
    // the next sign-in follows it again.
    let approvals = smart.store.approvals().await.expect("read");
    assert_eq!(1, approvals.len(), "the approval stands");
    let back = login(
        &smart,
        "openid fhirUser offline_access",
        "Patient/synthetic-2",
    )
    .await;
    assert!(
        back.as_str().starts_with(REDIRECT),
        "the approval answers the next sign-in: {back}"
    );
    smart.stop().await;
}

// NOTE: OpenID Connect Core 1.0 §3.1.2.4 (owner, 2026-11-20, #727): a staff approval
// covers patient/ scopes only in an EHR launch; a standalone request shows the page.
#[tokio::test]
async fn a_professional_s_standalone_patient_request_under_a_staff_approval_shows_the_page() {
    let smart =
        start("[\"openid\", \"fhirUser\", \"user/Observation.rs\", \"patient/Observation.rs\"]")
            .await;
    let back = login(
        &smart,
        "openid fhirUser user/Observation.rs patient/Observation.rs",
        "Practitioner/synthetic-1",
    )
    .await;
    assert_eq!(
        "/consent",
        back.path(),
        "no EHR launch, no patient in context"
    );
    smart.stop().await;
}
