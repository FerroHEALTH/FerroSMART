// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Whether a request is the natural person's own access (Regulation (EU)
//! 2025/327 Art. 5 and 9): only a token whose `fhirUser` is the `Patient` its
//! launch context names is, and it carries the [`PatientClaim`] a deployment
//! attaches to its resource server.

use std::error::Error as StdError;

use ferrohealth_smart::jws::algorithm::Algorithm;
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::resource::PatientClaim;
use ferrohealth_smart::resource::ResourceServer;

use crate::support::Issuer;
use crate::support::ec_key;
use crate::support::mint;

/// The claims of the patient's own token, `fhirUser` the `Patient` its
/// `patient` context names.
#[expect(
    clippy::indexing_slicing,
    reason = "test code: the claims are an object the issuer built"
)]
fn own(issuer: &Issuer) -> serde_json::Value {
    let mut claims = issuer.claims("patient/Observation.rs");
    claims["patient"] = serde_json::json!("p-7");
    claims["fhirUser"] = serde_json::json!("Patient/p-7");
    claims
}

#[tokio::test]
async fn a_patients_token_carries_the_attached_patient_claim() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::Es256);
    let issuer = Issuer::start(&[&key]).await;
    let server = ResourceServer::discover(issuer.settings())
        .await?
        .with_extension(PatientClaim::new("person.patient_id")?);
    let mut claims = own(&issuer);
    claims["person"] = serde_json::json!({ "patient_id": "p-7" });
    let caller = server.authenticate(&mint(&key, &claims)).await?;
    assert_eq!(&CallerKind::Patient, caller.kind());
    assert!(caller.is_the_person());
    assert_eq!(Some("p-7"), caller.person().and_then(|person| person.claim));
    Ok(())
}

#[tokio::test]
async fn a_lazy_server_carries_the_patient_claim_too() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::Es256);
    let issuer = Issuer::start(&[&key]).await;
    let server =
        ResourceServer::lazy(issuer.settings())?.with_extension(PatientClaim::new("patient_id")?);
    let mut claims = own(&issuer);
    claims["patient_id"] = serde_json::json!("p-7");
    let caller = server.authenticate(&mint(&key, &claims)).await?;
    assert_eq!(Some("p-7"), caller.person().and_then(|person| person.claim));
    Ok(())
}

// NOTE: SMART App Launch 2.2.0, Patient-specific scopes name what a `patient/`
// scope reaches, not who asks, so a professional's token is never the person's.
#[tokio::test]
async fn a_professionals_token_is_never_the_persons_own_access() -> Result<(), Box<dyn StdError>> {
    let key = ec_key("k1", Algorithm::Es256);
    let issuer = Issuer::start(&[&key]).await;
    let server = ResourceServer::discover(issuer.settings())
        .await?
        .with_extension(PatientClaim::new("patient_id")?);
    let mut claims = issuer.claims("patient/Observation.rs");
    claims["patient_id"] = serde_json::json!("p-7");
    claims["patient"] = serde_json::json!("p-7");
    claims["fhirUser"] = serde_json::json!("Practitioner/pr-1");
    let professional = server.authenticate(&mint(&key, &claims)).await?;
    assert_eq!(&CallerKind::Practitioner, professional.kind());
    assert!(!professional.is_the_person());
    assert!(professional.person().is_none());
    Ok(())
}
