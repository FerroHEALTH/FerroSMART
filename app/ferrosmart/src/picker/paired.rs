// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The patient picker at an openEHR resource server paired with the
//! platform's FHIR server (`docs/architecture.md` §13.6 item 4).
//!
//! At an openEHR resource server `launch/patient` asks for "both FHIR
//! `Patient` resource and corresponding openEHR `EHR` instance" (SMART on
//! openEHR draft, Context Selection), and the platform names its FHIR
//! server as the `org.fhir.rest` service beside `org.openehr.rest` (Service
//! Discovery). The person picks the patient at that FHIR server, and
//! FerroSMART looks the patient's EHR up at the openEHR server by the
//! identifier the configuration names, each as the person, so the launch
//! context carries `patient` and `ehrId`. The draft does not say how a
//! `Patient` names its EHR's subject: the identifier system is our own
//! design, set per base.

use std::net::IpAddr;

use axum::response::Response;
use http::HeaderMap;
use serde_json::Value;

use super::purpose::{self, Declared};
use super::{PickerError, enter, is_fhir_id, openehr, read_patient};
use crate::config::settings::Pairing;
use crate::form::Params;
use crate::launch::context::Context;
use crate::pages::{self, Fault};
use crate::server::AppState;
use crate::store::Pending;

/// The words the picker shows when the chosen patient has no EHR the
/// person may see.
const NO_EHR: &str = "picker-paired-none";

/// Reads the patient the form `form` chose at the FHIR server of `pairing`
/// again as the person, looks their EHR up at the openEHR server of
/// `pending`, and sends the browser on with both in the launch context.
pub(super) async fn choose(
    state: &AppState,
    headers: &HeaderMap,
    pending: &Pending,
    from: IpAddr,
    pairing: &Pairing,
    form: &Params,
) -> Response {
    let Some(id) = form.get("patient").filter(|id| is_fhir_id(id)) else {
        return pages::fault(state, Fault::BadRequest);
    };
    let (kept, declared) = match purpose::declared(state, pending, form).await {
        Ok(declared) => declared,
        Err(response) => return *response,
    };
    match context_of(state, &kept, from, pairing, (id, declared)).await {
        Ok(Some(context)) => match super::shortcuts::remember(state, &kept, id).await {
            Ok(()) => enter(state, &kept, &context, from).await,
            Err(error) => pages::server_error(state, &error),
        },
        Ok(None) => match super::shortcuts::fhir(state, &kept, from, &pairing.fhir_base).await {
            Ok(offered) => pages::picker(
                state,
                headers,
                &kept,
                None,
                pages::Listed::Offered(&offered, Some(NO_EHR)),
            ),
            Err(error) => pages::server_error(state, &error),
        },
        Err(response) => *response,
    }
}

/// Reads the patient `id` at the FHIR server of `pairing` again as the
/// person and looks their EHR up at the openEHR server of `pending`,
/// declaring the purpose of use `declared` when it names one, and returns
/// the context with both, or `None` when the patient has no EHR the person
/// may see.
///
/// # Errors
/// Returns the page that says why the patient or the EHR could not be read.
pub(super) async fn context_of(
    state: &AppState,
    pending: &Pending,
    from: IpAddr,
    pairing: &Pairing,
    (id, declared): (&str, Option<Declared<'_>>),
) -> Result<Option<Context>, Box<Response>> {
    let Some(namespace) = state.settings().subject_namespaces.get(&pending.audience) else {
        return Err(Box::new(pages::fault(state, Fault::Server)));
    };
    let patient = read_patient(state, pending, from, &pairing.fhir_base, id).await?;
    let subject_id = match subject_id(&patient, &pairing.subject_system) {
        Ok(Some(subject_id)) => subject_id,
        Ok(None) => return Ok(None),
        Err(error) => return Err(Box::new(pages::server_error(state, &error))),
    };
    // NOTE: SMART on openEHR draft, Context Selection, `ehrId` names the EHR of the
    // selected FHIR Patient, which is looked up as the person.
    match openehr::by_subject(state, pending, from, namespace, (subject_id, declared)).await {
        Ok(Some(found)) => Ok(Some(Context {
            patient: Some(id.to_owned()),
            ehr_id: Some(found.ehr_id),
            ..Context::default()
        })),
        Ok(None) => Ok(None),
        Err(error) => Err(Box::new(pages::server_error(state, &error))),
    }
}

/// Returns the id of the EHR of the patient `id` at the openEHR `base`
/// paired by `pairing`, read as `person`: the patient read at the FHIR
/// server, their subject id, and their EHR looked up by it; none when the
/// patient has no EHR the person may see.
///
/// # Errors
/// Returns the [`PickerError`] of a read or lookup that failed.
pub(super) async fn ehr_of(
    state: &AppState,
    person: &super::Person<'_>,
    from: IpAddr,
    (base, pairing): (&str, &Pairing),
    id: &str,
) -> Result<Option<String>, PickerError> {
    let Some(namespace) = state.settings().subject_namespaces.get(base) else {
        return Ok(None);
    };
    let url = super::patient_url(&pairing.fhir_base, Some(id)).map_err(PickerError::Url)?;
    let ask = super::fhir_ask(&url, &pairing.fhir_base, super::Action::Read);
    let patient = super::as_the(state, person, from, &ask).await?;
    if patient.get("id").and_then(Value::as_str) != Some(id) {
        return Err(PickerError::Unreadable);
    }
    let Some(subject_id) = subject_id(&patient, &pairing.subject_system)? else {
        return Ok(None);
    };
    let found =
        openehr::by_subject_as(state, person, from, (base, namespace), (subject_id, None)).await?;
    Ok(found.map(|found| found.ehr_id))
}

/// Returns the subject id of the EHR of `patient`: the value of its one
/// current identifier in `system`, or `None` when it has none.
///
/// # Errors
/// Returns [`PickerError::Ambiguous`] when two current identifiers of the
/// system carry different values, since either could name the EHR.
fn subject_id<'p>(patient: &'p Value, system: &str) -> Result<Option<&'p str>, PickerError> {
    let mut values = patient
        .get("identifier")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|identifier| identifier.get("system").and_then(Value::as_str) == Some(system))
        // NOTE: FHIR R4 Identifier.use, `old` is "no longer considered valid, but
        // may be relevant for search purposes", so it names no current subject.
        .filter(|identifier| identifier.get("use").and_then(Value::as_str) != Some("old"))
        .filter_map(|identifier| identifier.get("value").and_then(Value::as_str))
        .filter(|value| !value.trim().is_empty());
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.any(|other| other != first) {
        return Err(PickerError::Ambiguous);
    }
    Ok(Some(first))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const SYSTEM: &str = "urn:example:mrn";

    #[test]
    fn the_subject_is_the_one_current_identifier_of_the_system() {
        let patient = json!({ "identifier": [
            { "system": "urn:example:other", "value": "X-1" },
            { "system": SYSTEM, "use": "old", "value": "MRN-0" },
            { "system": SYSTEM, "value": "MRN-1" },
            { "system": SYSTEM, "use": "official", "value": "MRN-1" },
        ] });
        assert_eq!(
            Some("MRN-1"),
            subject_id(&patient, SYSTEM).expect("one subject")
        );
    }

    #[test]
    fn a_patient_without_an_identifier_of_the_system_has_no_subject() {
        for patient in [
            json!({}),
            json!({ "identifier": [{ "system": "urn:example:other", "value": "X-1" }] }),
            json!({ "identifier": [{ "system": SYSTEM, "use": "old", "value": "MRN-0" }] }),
            json!({ "identifier": [{ "system": SYSTEM, "value": " " }] }),
            json!({ "identifier": [{ "value": "MRN-1" }] }),
        ] {
            assert_eq!(
                None,
                subject_id(&patient, SYSTEM).expect("no subject"),
                "{patient}"
            );
        }
    }

    #[test]
    fn two_current_identifiers_of_the_system_name_no_one_subject() {
        let patient = json!({ "identifier": [
            { "system": SYSTEM, "value": "MRN-1" },
            { "system": SYSTEM, "value": "MRN-2" },
        ] });
        assert!(matches!(
            subject_id(&patient, SYSTEM),
            Err(PickerError::Ambiguous)
        ));
    }
}
