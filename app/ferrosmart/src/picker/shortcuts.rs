// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The patients the picker offers before a search (`docs/architecture.md`
//! §13.6 item 4).
//!
//! They are the person's recent choices at the base asked, and the patients
//! assigned to them where the FHIR base names a search for those, each read
//! as the person before the page shows them. No specification governs the
//! lists: our own design.

use std::net::IpAddr;

use ehds_logging::record::{Action, DataSubject};
use serde_json::Value;
use url::Url;

use super::openehr::{self, FoundEhr};
use super::send::{Person, as_person};
use super::{Access, Ask, Found, PickerError, fhir_ask, fhir_request};
use crate::authorize::consent;
use crate::config::Assigned;
use crate::server::AppState;
use crate::store::Pending;

/// The patients offered before a search at a FHIR server.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Shortcuts {
    /// The patients the person chose here lately, the latest first.
    pub recent: Vec<Found>,
    /// The patients assigned to the person.
    pub assigned: Vec<Found>,
}

/// Returns the shortcuts of `pending` at the FHIR server `base`: the
/// request's own base, or the FHIR base paired with its openEHR one.
///
/// # Errors
/// Returns the [`PickerError`] of a store read or a search that failed.
pub(super) async fn fhir(
    state: &AppState,
    pending: &Pending,
    from: IpAddr,
    base: &str,
) -> Result<Shortcuts, PickerError> {
    let recent = recent_ids(state, pending)
        .await?
        .into_iter()
        .filter(|id| super::is_fhir_id(id))
        .collect::<Vec<_>>();
    let recent = if recent.is_empty() {
        Vec::new()
    } else {
        // NOTE: FHIR R4 search §3.1.1.4.1, `_id` matches a resource by its id, and
        // a comma-separated list matches any of them (§3.1.1.4.6).
        let mut url = super::patient_url(base, None).map_err(PickerError::Url)?;
        url.query_pairs_mut()
            .append_pair("_id", &recent.join(","))
            .append_pair("_count", &recent.len().to_string());
        let read = searched(
            &as_person(
                state,
                pending,
                from,
                &fhir_ask(&url, base, Action::Query, super::PICKER_SCOPE),
            )
            .await?,
        )?;
        recent
            .iter()
            .filter_map(|id| read.iter().find(|found| &found.id == id).cloned())
            .collect()
    };
    let assigned = match (
        state.settings().assigned.get(base),
        participant(base, pending),
    ) {
        (Some(search), Some(reference)) => {
            assigned(state, pending, from, base, (*search, reference)).await?
        }
        _ => Vec::new(),
    };
    Ok(Shortcuts { recent, assigned })
}

/// Returns the EHRs of the person's recent choices at the openEHR server
/// of `pending`, each looked up again as them, when a lookup may run now:
/// the server lists no purpose of use, or the request kept one.
///
/// # Errors
/// Returns the [`PickerError`] of a store read or a lookup that failed.
pub(super) async fn openehr(
    state: &AppState,
    pending: &Pending,
    from: IpAddr,
    namespace: &str,
) -> Result<Vec<FoundEhr>, PickerError> {
    let Ok(declared) = super::purpose::kept(state, pending) else {
        return Ok(Vec::new());
    };
    let mut found = Vec::new();
    for subject_id in recent_ids(state, pending).await? {
        if let Some(ehr) =
            openehr::by_subject(state, pending, from, namespace, (&subject_id, declared)).await?
        {
            found.push(ehr);
        }
    }
    Ok(found)
}

/// Returns the recent choices of the person of `pending` at its base.
async fn recent_ids(state: &AppState, pending: &Pending) -> Result<Vec<String>, PickerError> {
    let retention = state.settings().recent_retention;
    let Some(subject) = pending.subject.as_deref().filter(|_| !retention.is_zero()) else {
        return Ok(Vec::new());
    };
    state
        .store()
        .recent_patients(subject, &pending.audience, retention)
        .await
        .map_err(PickerError::Store)
}

/// Records that the person of `pending` chose `patient` at its base, while
/// the deployment keeps a recent list.
///
/// # Errors
/// Returns [`PickerError::Store`] when the store fails.
pub(super) async fn remember(
    state: &AppState,
    pending: &Pending,
    patient: &str,
) -> Result<(), PickerError> {
    let Some(subject) = pending.subject.as_deref() else {
        return Ok(());
    };
    if state.settings().recent_retention.is_zero() {
        return Ok(());
    }
    state
        .store()
        .remember_patient(subject, &pending.audience, patient)
        .await
        .map_err(PickerError::Store)
}

/// Returns the reference the `participant` search names the person by:
/// their `fhirUser` relative to `base`, when it names a professional, a
/// `Practitioner` or `PractitionerRole`, there.
fn participant<'p>(base: &str, pending: &'p Pending) -> Option<&'p str> {
    let fhir_user = pending.fhir_user.as_deref()?;
    if consent::Person::of(Some(fhir_user)) != consent::Person::Professional {
        return None;
    }
    // NOTE: SMART App Launch 2.2.0, `fhirUser` MAY be absolute or relative to the
    // FHIR base of the request; FHIR R4 Encounter and CareTeam `participant` targets.
    let relative = match fhir_user.strip_prefix(base) {
        Some(rest) => rest.strip_prefix('/')?,
        None if fhir_user.contains("://") => return None,
        None => fhir_user,
    };
    let (_, id) = relative.split_once('/')?;
    super::is_fhir_id(id).then_some(relative)
}

/// Runs the assigned-patient search `search` for `reference` at `base` as
/// the person, and returns the patients it includes.
async fn assigned(
    state: &AppState,
    pending: &Pending,
    from: IpAddr,
    base: &str,
    (search, reference): (Assigned, &str),
) -> Result<Vec<Found>, PickerError> {
    // NOTE: FHIR R4 CareTeam and Encounter search parameters `participant` and
    // `status`, and search §3.1.1.5.4 `_include` of the `patient` reference.
    let (resource, status, include, scope) = match search {
        Assigned::CareTeam => ("CareTeam", "active", "CareTeam:patient", CARE_TEAM_SCOPE),
        Assigned::Encounter => (
            "Encounter",
            "in-progress",
            "Encounter:patient",
            ENCOUNTER_SCOPE,
        ),
    };
    let mut url = Url::parse(&format!("{}/{resource}", base.trim_end_matches('/')))
        .map_err(PickerError::Url)?;
    url.query_pairs_mut()
        .append_pair("participant", reference)
        .append_pair("status", status)
        .append_pair("_include", include)
        .append_pair("_count", &super::MAX_RESULTS.to_string());
    let asked = &url;
    let ask = Ask {
        url: asked,
        audience: base,
        scope,
        accept: "application/fhir+json",
        describe: Box::new(move |fetched| Access {
            action: Action::Query,
            delivered: match fetched {
                Ok(bundle) => Some(super::patients(bundle).len()),
                Err(_) => None,
            },
            subject: DataSubject::default(),
            request: fhir_request(asked, Action::Query, resource),
        }),
        purpose: None,
    };
    let person = Person::of(pending).ok_or(PickerError::Unreadable)?;
    searched(&super::send::as_the(state, &person, from, &ask).await?)
}

/// The scope of the token the care-team search is sent with.
const CARE_TEAM_SCOPE: &str = "user/CareTeam.rs user/Patient.rs";

/// The scope of the token the encounter search is sent with.
const ENCOUNTER_SCOPE: &str = "user/Encounter.rs user/Patient.rs";

/// Returns the patients of the search Bundle `answer`.
fn searched(answer: &Value) -> Result<Vec<Found>, PickerError> {
    if answer.get("resourceType").and_then(Value::as_str) != Some("Bundle") {
        return Err(PickerError::Unreadable);
    }
    Ok(super::patients(answer))
}
