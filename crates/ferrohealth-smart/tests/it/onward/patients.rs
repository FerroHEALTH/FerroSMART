// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A patient's own token exchanged at a SMART issuer, by token exchange
//! (RFC 8693 §2.1) and by the JWT bearer grant (RFC 7523 §2.1): the issued
//! token must name a `Patient` as its `fhirUser` and keep the patient
//! context.

use ferrohealth_smart::client::onward::OnwardError;
use ferrohealth_smart::client::onward::Rejected;
use ferrohealth_smart::client::onward::SubjectToken;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::profile::onward::OnwardGrant;
use ferrohealth_smart::resource::PatientClaim;
use secrecy::SecretString;
use serde_json::Value;
use serde_json::json;

use super::caller;
use super::harness::Flavor;
use super::harness::Harness;
use super::param;
use super::received;
use super::sign;

/// The two forms of the exchange: RFC 8693 token exchange and the RFC 7523
/// JWT bearer grant.
const FORMS: [Flavor; 2] = [Flavor::Generic, Flavor::GenericJwtBearer];

/// The patient the cases' tokens name.
const PATIENT: &str = "synthetic-patient-1";

/// Starts the harness of `flavor`.
async fn start(flavor: Flavor) -> Harness {
    Harness::start(flavor).await
}

/// Returns `claims` with `claim` set to `value`.
fn with(mut claims: Value, claim: &str, value: Value) -> Value {
    if let Some(object) = claims.as_object_mut() {
        object.insert(claim.to_owned(), value);
    }
    claims
}

/// Returns the claims of a patient's token under `flavor`, naming the
/// patient in its `patient` launch context.
fn patient_claims(flavor: Flavor, now: i64) -> Value {
    let claims = with(flavor.subject_claims(now), "scope", json!("patient/*.rs"));
    let claims = with(claims, "fhirUser", json!(format!("Patient/{PATIENT}")));
    with(claims, "patient", json!(PATIENT))
}

/// Returns the claims of the patient token an exchange of `subject` issues.
fn issued_claims(flavor: Flavor, subject: &Value, now: i64) -> Value {
    let issued = with(
        flavor.issued_claims(subject, now),
        "scope",
        json!("patient/Observation.rs"),
    );
    let issued = with(issued, "fhirUser", json!(format!("Patient/{PATIENT}")));
    with(issued, "patient", json!(PATIENT))
}

/// Returns the patient's subject token and its claims.
fn patient(harness: &Harness) -> (SubjectToken, Value) {
    let claims = patient_claims(harness.flavor, harness.now());
    (harness.subject(&claims, CallerKind::Patient), claims)
}

/// Returns the refusal of an exchange whose issued token `change` alters,
/// and the requests the token endpoint received.
async fn refused(flavor: Flavor, change: impl Fn(&mut Value)) -> (OnwardError, usize) {
    let harness = start(flavor).await;
    let (subject, claims) = patient(&harness);
    let mut issued = issued_claims(flavor, &claims, harness.now());
    change(&mut issued);
    harness.issue(&issued, None).await;
    let error = harness
        .token(&subject, None)
        .await
        .expect_err("the issued token is refused");
    (error, harness.calls().await)
}

#[tokio::test]
async fn a_patients_token_is_exchanged_in_both_forms_and_keeps_the_patient() {
    for flavor in FORMS {
        let harness = start(flavor).await;
        let (subject, claims) = patient(&harness);
        let issued = issued_claims(flavor, &claims, harness.now());
        let token = harness.issue(&issued, None).await;
        let onward = harness
            .token(&subject, None)
            .await
            .expect("the patient's exchange succeeds");
        assert_eq!(
            Some(format!("Bearer {token}").as_str()),
            onward.header().to_str().ok(),
            "{flavor:?}"
        );
        let sent = received(&harness.server).await;
        let form = sent.first().expect("one request");
        assert_eq!(
            Some(flavor.grant().grant_type()),
            param(form, "grant_type"),
            "{flavor:?}"
        );
        match flavor.grant() {
            // NOTE: RFC 8693 §2.1, the patient's token is the `subject_token`.
            OnwardGrant::TokenExchange => assert!(param(form, "subject_token").is_some()),
            // NOTE: RFC 7523 §2.1, the patient's token is the `assertion`.
            OnwardGrant::JwtBearer => assert!(param(form, "assertion").is_some()),
            other => panic!("the case checks no {other:?}"),
        }
    }
}

#[tokio::test]
async fn an_issued_token_for_another_patient_is_refused() {
    for flavor in FORMS {
        let (error, _) = refused(flavor, |issued| {
            issued["patient"] = json!("synthetic-patient-2");
        })
        .await;
        assert!(
            matches!(&error, OnwardError::Rejected(Rejected::PatientContext { claim }) if claim == "patient"),
            "{flavor:?}: {error:?}"
        );
    }
}

#[tokio::test]
async fn an_issued_token_without_the_patient_is_refused() {
    for flavor in FORMS {
        let (error, _) = refused(flavor, |issued| {
            if let Some(claims) = issued.as_object_mut() {
                claims.remove("patient");
            }
        })
        .await;
        assert!(
            matches!(&error, OnwardError::Rejected(Rejected::PatientContext { claim }) if claim == "patient"),
            "{flavor:?}: {error:?}"
        );
    }
}

// NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, `fhirUser`: the
// token issued for a patient's own token names the patient as its user.
#[tokio::test]
async fn an_issued_token_that_names_no_patient_user_is_refused() {
    for flavor in FORMS {
        let (error, _) = refused(flavor, |issued| {
            issued["fhirUser"] = json!("Practitioner/p-1");
        })
        .await;
        assert!(
            matches!(&error, OnwardError::Rejected(Rejected::Patient)),
            "{flavor:?}: {error:?}"
        );
    }
}

// NOTE: no specification governs this: our own design; a patient's own token is
// exchanged for the patient in its launch context alone.
#[tokio::test]
async fn a_patient_token_without_a_patient_context_is_refused_before_sending() {
    for flavor in FORMS {
        let harness = start(flavor).await;
        let mut claims = patient_claims(flavor, harness.now());
        if let Some(object) = claims.as_object_mut() {
            object.remove("patient");
        }
        let subject = harness.subject(&claims, CallerKind::Patient);
        let error = harness
            .token(&subject, None)
            .await
            .expect_err("no patient context");
        assert!(
            matches!(error, OnwardError::NoPatientContext),
            "{flavor:?}: {error:?}"
        );
        assert_eq!(0, harness.calls().await, "{flavor:?}: nothing is sent");
    }
}

#[tokio::test]
async fn the_deployments_patient_claim_is_kept_too() {
    for flavor in FORMS {
        let harness = start(flavor).await;
        let mut claims = patient_claims(flavor, harness.now());
        claims["person"] = json!({ "patient_id": "nhs-0001" });
        let admitted = caller(&claims, CallerKind::Patient)
            .with_extension(PatientClaim::new("person.patient_id").expect("a claim path"));
        let subject =
            SubjectToken::from_caller(&admitted, SecretString::from(sign(&harness.key, &claims)))
                .expect("the caller holds a verified token");
        let mut issued = issued_claims(flavor, &claims, harness.now());
        issued["person"] = json!({ "patient_id": "nhs-0002" });
        harness.issue(&issued, None).await;
        let error = harness
            .token(&subject, None)
            .await
            .expect_err("another patient id");
        assert!(
            matches!(&error, OnwardError::Rejected(Rejected::PatientContext { claim }) if claim == "person.patient_id"),
            "{flavor:?}: {error:?}"
        );
    }
}
