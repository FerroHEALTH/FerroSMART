// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The encounter step of the picker at a FHIR resource server
//! (`docs/architecture.md` §13.6 item 4).
//!
//! A standalone app that asks for `launch/encounter` "SHOULD" be given an
//! encounter (SMART App Launch 2.2.0, Scopes and Launch Context, Standalone
//! apps), and the authorization endpoint acquires it as it acquires the
//! patient (App Launch, Obtain authorization code). Once the person chose a
//! patient, FerroSMART searches that patient's `Encounter` resources as the
//! person, with a token whose one scope is [`ENCOUNTER_SCOPE`], and the
//! person picks one or goes on without. The chosen encounter is read again
//! as them, and enters the context only when its `subject` is the chosen
//! patient. The search, the step and the page are our own design.

use std::net::IpAddr;

use axum::response::Response;
use ehds_logging::record::{Action, DataSubject, PatientIdentifier};
use http::HeaderMap;
use secrecy::SecretString;
use serde_json::Value;
use url::Url;

use super::send::as_person;
use super::{
    Access, Ask, PickerError, Reach, enter, entries, fhir_request, go_on, is_fhir_id, read_patient,
};
use crate::form::Params;
use crate::launch::context::Context;
use crate::pages::{self, Fault};
use crate::server::AppState;
use crate::store::Pending;

/// The one scope the picker's token carries when it searches or reads
/// encounters (SMART App Launch 2.2.0, Scopes for requesting clinical
/// data).
pub const ENCOUNTER_SCOPE: &str = "user/Encounter.rs";

/// The value of the form's `step` that names the encounter step.
pub const STEP: &str = "encounter";

/// The most encounters one search shows.
pub const MAX_RESULTS: usize = 20;

/// An encounter the search returned, as the page shows it: the id and the
/// display fields alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundEncounter {
    /// The resource id.
    pub id: String,
    /// What kind of encounter it is: its first type's text or display,
    /// else its class's display or code.
    pub kind: String,
    /// When it started.
    pub start: Option<String>,
    /// Its status.
    pub status: Option<String>,
}

/// Returns whether `pending` takes an encounter from the picker: the
/// consent offers `launch/encounter` and the resource server is a FHIR one.
#[must_use]
pub fn wanted(state: &AppState, pending: &Pending) -> bool {
    super::reach(state, &pending.audience) == Reach::Encounter
        && pending
            .offered_scope
            .as_deref()
            .unwrap_or_default()
            .split(' ')
            .any(|scope| scope == "launch/encounter")
}

/// Answers `GET {issuer}/picker?patient=`: the encounters of `patient` the
/// person may see, to pick one from.
pub async fn list(
    state: &AppState,
    headers: &HeaderMap,
    pending: &Pending,
    from: IpAddr,
    patient: &str,
) -> Response {
    if !wanted(state, pending) || !is_fhir_id(patient) {
        return pages::fault(state, Fault::BadRequest);
    }
    let mut url = match encounter_url(&pending.audience, None) {
        Ok(url) => url,
        Err(error) => return pages::server_error(state, &error),
    };
    url.query_pairs_mut()
        .append_pair("patient", patient)
        .append_pair("_count", &MAX_RESULTS.to_string());
    match as_person(
        state,
        pending,
        from,
        &encounter_ask(&url, &pending.audience, patient, Action::Query),
    )
    .await
    {
        Ok(Value::Object(bundle)) if bundle.get("resourceType") == Some(&Value::from("Bundle")) => {
            let found = encounters(&Value::Object(bundle), patient);
            pages::encounter_picker(state, headers, (pending, patient), &found)
        }
        Ok(_) => pages::server_error(state, &PickerError::Unreadable),
        Err(error) => pages::server_error(state, &error),
    }
}

/// Answers the encounter step's `POST {issuer}/picker`.
///
/// The patient is read again, and the chosen encounter read again and
/// checked to be theirs, before both enter the launch context; when the
/// person goes on without one, the patient enters alone and
/// `launch/encounter` is no longer offered.
pub async fn choose(state: &AppState, pending: &Pending, from: IpAddr, form: &Params) -> Response {
    if !wanted(state, pending) {
        return pages::fault(state, Fault::BadRequest);
    }
    let Some(patient) = form.get("patient").filter(|id| is_fhir_id(id)) else {
        return pages::fault(state, Fault::BadRequest);
    };
    if let Err(response) = read_patient(state, pending, from, &pending.audience, patient).await {
        return *response;
    }
    let mut context = Context {
        patient: Some(patient.to_owned()),
        ..Context::default()
    };
    if form.get("without").is_some() {
        let offered: Vec<&str> = pending
            .offered_scope
            .as_deref()
            .unwrap_or_default()
            .split(' ')
            .filter(|scope| !scope.is_empty() && *scope != "launch/encounter")
            .collect();
        let offered = offered.join(" ");
        if let Err(error) = state
            .store()
            .set_launch_context_offering(&pending.id, &context, &offered)
            .await
        {
            return pages::server_error(state, &error);
        }
        return go_on(state, pending, &offered, from).await;
    }
    let Some(id) = form.get("encounter").filter(|id| is_fhir_id(id)) else {
        return pages::fault(state, Fault::BadRequest);
    };
    let url = match encounter_url(&pending.audience, Some(id)) {
        Ok(url) => url,
        Err(error) => return pages::server_error(state, &error),
    };
    // NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, `encounter` is the id
    // of an encounter of the patient in context, read again as the person.
    match as_person(
        state,
        pending,
        from,
        &encounter_ask(&url, &pending.audience, patient, Action::Read),
    )
    .await
    {
        Ok(resource)
            if resource.get("id").and_then(Value::as_str) == Some(id)
                && belongs_to(&resource, patient) => {}
        Ok(_) | Err(PickerError::Refused(_)) => return pages::fault(state, Fault::BadRequest),
        Err(error) => return pages::server_error(state, &error),
    }
    context.encounter = Some(id.to_owned());
    enter(state, pending, &context, from).await
}

/// Returns `[base]/Encounter`, or `[base]/Encounter/[id]` when `id` names one.
fn encounter_url(base: &str, id: Option<&str>) -> Result<Url, url::ParseError> {
    let base = base.trim_end_matches('/');
    match id {
        Some(id) => Url::parse(&format!("{base}/Encounter/{id}")),
        None => Url::parse(&format!("{base}/Encounter")),
    }
}

/// Whether the Encounter `resource`'s `subject` is the patient `patient`,
/// as a relative reference or an absolute one ending in it (FHIR R4
/// References, Literal references).
fn belongs_to(resource: &Value, patient: &str) -> bool {
    let wanted = format!("Patient/{patient}");
    resource
        .pointer("/subject/reference")
        .and_then(Value::as_str)
        .is_some_and(|reference| reference == wanted || reference.ends_with(&format!("/{wanted}")))
}

/// Returns the FHIR search or read of `url`, encounters of `patient` at the
/// base `audience`.
fn encounter_ask<'a>(url: &'a Url, audience: &'a str, patient: &'a str, action: Action) -> Ask<'a> {
    Ask {
        url,
        audience,
        scope: ENCOUNTER_SCOPE,
        accept: "application/fhir+json",
        describe: Box::new(move |fetched| {
            let delivered = match fetched {
                Ok(bundle @ Value::Object(_)) if action == Action::Query => {
                    Some(encounters(bundle, patient).len())
                }
                Ok(_) => Some(1),
                Err(_) => None,
            };
            Access {
                action,
                delivered,
                subject: DataSubject {
                    patient: Some(PatientIdentifier {
                        namespace: Some(audience.to_owned()),
                        value: SecretString::from(patient.to_owned()),
                    }),
                    ..DataSubject::default()
                },
                request: fhir_request(url, action, "Encounter"),
            }
        }),
        purpose: None,
    }
}

/// Returns the encounters of `patient` in the search Bundle `bundle`, the
/// latest start first, at most [`MAX_RESULTS`], with their display fields.
/// An entry of another patient is left out.
fn encounters(bundle: &Value, patient: &str) -> Vec<FoundEncounter> {
    let mut found: Vec<FoundEncounter> = entries(bundle, "Encounter")
        .filter(|resource| belongs_to(resource, patient))
        .filter_map(|resource| {
            let id = resource.get("id").and_then(Value::as_str)?;
            is_fhir_id(id).then(|| FoundEncounter {
                id: id.to_owned(),
                kind: kind_of(resource),
                start: resource
                    .pointer("/period/start")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                status: resource
                    .get("status")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            })
        })
        .collect();
    // NOTE: our own order, the start as the server wrote it, the latest first.
    found.sort_by(|one, other| other.start.cmp(&one.start));
    found.truncate(MAX_RESULTS);
    found
}

/// Returns what kind of encounter `resource` is: its first type's text or
/// first coding's display, else its class's display or code.
fn kind_of(resource: &Value) -> String {
    [
        "/type/0/text",
        "/type/0/coding/0/display",
        "/class/display",
        "/class/code",
    ]
    .iter()
    .find_map(|pointer| resource.pointer(pointer).and_then(Value::as_str))
    .unwrap_or_default()
    .to_owned()
}
