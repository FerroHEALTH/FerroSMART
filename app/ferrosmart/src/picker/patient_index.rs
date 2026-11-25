// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The patient a wallet login names, resolved at a patient index
//! (`docs/architecture.md` §13.32).
//!
//! The PID's administrative number, in its issuing country's system, is
//! cross-referenced at the index of the request's FHIR server, a PIXm 3.1.0
//! Manager by ITI-83 or a PDQm 3.2.0 Supplier by ITI-78, to the person's
//! identifier in that server's own system, and that identifier is searched
//! there (FHIR R4 search, token parameters). Exactly one patient at each step
//! is the `fhirUser`; none or several refuse the launch. No demographic is
//! ever matched. FerroSMART asks both as its SMART Backend Services client,
//! on the person's behalf (`docs/architecture.md` §13.33). The two-step lookup
//! and its refusals are our own design: no specification says how a PID
//! becomes a SMART patient context.

use std::net::IpAddr;

use ehds_logging::record::{Action, DataSubject, Request};
use serde_json::Value;
use url::Url;

use super::send::{Person, as_backend};
use super::{Access, Ask, PickerError, entries, fhir_request, is_fhir_id};
use crate::config::{IndexTransaction, PatientIndexSection};
use crate::server::AppState;
use crate::store::Pending;
use crate::wallet::pid::PidIdentifier;

/// Why no patient is put in the launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IndexRefusal {
    /// The PID names no identifier the index can be asked for.
    #[error("the PID names no identifier the patient index knows")]
    NoIdentifier,
    /// The index or the resource server knows no patient by it.
    #[error("no patient carries the person's identifier")]
    NoMatch,
    /// More than one patient carries it.
    #[error("more than one patient carries the person's identifier")]
    Several,
    /// The index or the resource server could not be asked.
    #[error("the patient index could not be asked")]
    Failed,
}

impl IndexRefusal {
    /// Returns the outcome as an audit line names it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoIdentifier => "no-identifier",
            Self::NoMatch => "no-match",
            Self::Several => "several",
            Self::Failed => "failed",
        }
    }
}

/// Returns the patient index of the FHIR server the request to `audience`
/// reads, and that server's base; none when it names no index.
pub(crate) fn configured<'s>(
    state: &'s AppState,
    audience: &'s str,
) -> Option<(&'s PatientIndexSection, &'s str)> {
    let settings = state.settings();
    let base = match settings.pairings.get(audience) {
        Some(pairing) => pairing.fhir_base.as_str(),
        None => audience,
    };
    settings
        .patient_indexes
        .get(base)
        .map(|index| (index, base))
}

/// Resolves `identifier` to the person's `Patient` at the FHIR server
/// `base` through `index`, for the signed-in person of `pending` at
/// `audience`: the `fhirUser`, relative to `audience` or absolute at a
/// paired base.
///
/// # Errors
/// Returns [`IndexRefusal`] when no patient or several carry the
/// identifier, or a lookup fails.
pub(crate) async fn resolve(
    state: &AppState,
    pending: &Pending,
    from: IpAddr,
    (index, base): (&PatientIndexSection, &str),
    identifier: &PidIdentifier,
) -> Result<String, IndexRefusal> {
    let local = cross_referenced(state, pending, from, index, identifier).await?;
    let mut url = resource_url(base, "Patient")?;
    // NOTE: FHIR R4 search, token parameter `identifier=[system]|[code]`.
    url.query_pairs_mut()
        .append_pair("identifier", &format!("{}|{local}", index.system));
    let person = Person::of(pending).ok_or(IndexRefusal::Failed)?;
    let request = fhir_request(&url, Action::Query, "Patient");
    let ask = query(
        &url,
        base,
        |bundle| entries(bundle, "Patient").count(),
        request,
    );
    let bundle = as_backend(state, &person, from, &ask)
        .await
        .map_err(|_failed| IndexRefusal::Failed)?;
    let id = one_of(
        entries(&bundle, "Patient")
            .filter_map(|patient| patient.get("id").and_then(Value::as_str))
            .filter(|id| is_fhir_id(id))
            .map(str::to_owned),
    )?;
    let audience = pending.audience.as_str();
    Ok(if base == audience {
        format!("Patient/{id}")
    } else {
        format!("{}/Patient/{id}", base.trim_end_matches('/'))
    })
}

/// Returns the Backend Services query of `url` at `audience`, recorded as
/// `request` with what `count` finds in the answer delivered.
fn query<'a>(
    url: &'a Url,
    audience: &'a str,
    count: fn(&Value) -> usize,
    request: Request,
) -> Ask<'a> {
    Ask {
        url,
        audience,
        scope: crate::backend::SCOPE,
        accept: "application/fhir+json",
        describe: Box::new(move |fetched| Access {
            action: Action::Query,
            delivered: fetched.as_ref().ok().map(count),
            subject: DataSubject::default(),
            request: request.clone(),
        }),
        purpose: None,
    }
}

/// Returns the person's identifier value in `index.system`, as the index
/// cross-references `identifier`.
async fn cross_referenced(
    state: &AppState,
    pending: &Pending,
    from: IpAddr,
    index: &PatientIndexSection,
    identifier: &PidIdentifier,
) -> Result<String, IndexRefusal> {
    let person = Person::of(pending).ok_or(IndexRefusal::Failed)?;
    let url = index_url(index, identifier)?;
    let request = index_request(&url, index.transaction);
    let ask = query(&url, &index.base, |_| 1, request);
    let answer = match as_backend(state, &person, from, &ask).await {
        Ok(answer) => answer,
        // NOTE: PIXm 3.1.0 §2:3.83.4.2.2.2, an unknown identifier answers 404.
        Err(PickerError::Refused(status)) if status == http::StatusCode::NOT_FOUND => {
            return Err(IndexRefusal::NoMatch);
        }
        Err(PickerError::Refused(status)) if status == http::StatusCode::CONFLICT => {
            return Err(IndexRefusal::Several);
        }
        Err(_failed) => return Err(IndexRefusal::Failed),
    };
    let values = match index.transaction {
        IndexTransaction::Pixm => target_identifiers(&answer, &index.system),
        IndexTransaction::Pdqm => {
            let patients: Vec<&Value> = entries(&answer, "Patient").collect();
            match patients.as_slice() {
                [] => return Err(IndexRefusal::NoMatch),
                [patient] => identifiers_of(patient, &index.system),
                _ => return Err(IndexRefusal::Several),
            }
        }
    };
    one_of(values.into_iter())
}

/// Returns the URL that asks `index` for `identifier`: ITI-83 with the
/// resource server's system as `targetSystem` (PIXm 3.1.0 §2:3.83.4.1.2),
/// or ITI-78 by `identifier` (PDQm 3.2.0 §2:3.78.4.1.2.1).
fn index_url(index: &PatientIndexSection, identifier: &PidIdentifier) -> Result<Url, IndexRefusal> {
    let token = identifier.token();
    match index.transaction {
        IndexTransaction::Pixm => {
            let mut url = resource_url(&index.base, "Patient/$ihe-pix")?;
            url.query_pairs_mut()
                .append_pair("sourceIdentifier", &token)
                .append_pair("targetSystem", &index.system);
            Ok(url)
        }
        IndexTransaction::Pdqm => {
            let mut url = resource_url(&index.base, "Patient")?;
            url.query_pairs_mut().append_pair("identifier", &token);
            Ok(url)
        }
    }
}

/// Returns `path` under the FHIR base `base`.
fn resource_url(base: &str, path: &str) -> Result<Url, IndexRefusal> {
    Url::parse(&format!("{}/{path}", base.trim_end_matches('/')))
        .map_err(|_unparsed| IndexRefusal::Failed)
}

/// Returns the access record's request of the index query `url`.
fn index_request(url: &Url, transaction: IndexTransaction) -> Request {
    match transaction {
        IndexTransaction::Pixm => Request {
            operation: String::from("operation"),
            ..fhir_request(url, Action::Query, "Patient")
        },
        IndexTransaction::Pdqm => fhir_request(url, Action::Query, "Patient"),
    }
}

/// Returns the values of the `targetIdentifier` parameters of the ITI-83
/// answer `parameters` in `system` (PIXm 3.1.0 §2:3.83.4.2.2.1).
fn target_identifiers(parameters: &Value, system: &str) -> Vec<String> {
    parameters
        .get("parameter")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|parameter| {
            parameter.get("name").and_then(Value::as_str) == Some("targetIdentifier")
        })
        .filter_map(|parameter| parameter.get("valueIdentifier"))
        .filter_map(|identifier| value_in(identifier, system))
        .collect()
}

/// Returns the values of the identifiers of `patient` in `system`.
fn identifiers_of(patient: &Value, system: &str) -> Vec<String> {
    patient
        .get("identifier")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|identifier| value_in(identifier, system))
        .collect()
}

/// Returns the value of the FHIR `Identifier` `identifier` when it is in
/// `system`.
fn value_in(identifier: &Value, system: &str) -> Option<String> {
    if identifier.get("system").and_then(Value::as_str) != Some(system) {
        return None;
    }
    identifier
        .get("value")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
}

/// Returns the one distinct value of `values`.
fn one_of(values: impl Iterator<Item = String>) -> Result<String, IndexRefusal> {
    let mut values: Vec<String> = values.collect();
    values.sort();
    values.dedup();
    let mut values = values.into_iter();
    match (values.next(), values.next()) {
        (None, _) => Err(IndexRefusal::NoMatch),
        (Some(one), None) => Ok(one),
        (Some(_), Some(_)) => Err(IndexRefusal::Several),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const LOCAL: &str = "urn:example:hospital";

    fn identifier() -> PidIdentifier {
        PidIdentifier {
            system: String::from("http://fhir.nl/fhir/NamingSystem/bsn"),
            value: String::from("999990019"),
            kind: String::from("NI"),
            country: String::from("NL"),
        }
    }

    fn index(transaction: IndexTransaction) -> PatientIndexSection {
        PatientIndexSection {
            base: String::from("https://pix.example.org/fhir/"),
            transaction,
            system: String::from(LOCAL),
        }
    }

    #[test]
    fn pixm_asks_the_cross_reference_into_the_resource_server_system() {
        let url = index_url(&index(IndexTransaction::Pixm), &identifier()).expect("a URL");
        assert_eq!("/fhir/Patient/$ihe-pix", url.path());
        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert_eq!(
            vec![
                (
                    String::from("sourceIdentifier"),
                    String::from("http://fhir.nl/fhir/NamingSystem/bsn|999990019")
                ),
                (String::from("targetSystem"), String::from(LOCAL)),
            ],
            pairs
        );
    }

    #[test]
    fn pdqm_searches_by_the_identifier() {
        let url = index_url(&index(IndexTransaction::Pdqm), &identifier()).expect("a URL");
        assert_eq!("/fhir/Patient", url.path());
        assert_eq!(
            Some("http://fhir.nl/fhir/NamingSystem/bsn|999990019".to_owned()),
            url.query_pairs()
                .find(|(name, _)| name == "identifier")
                .map(|(_, value)| value.into_owned())
        );
    }

    #[test]
    fn the_target_identifiers_in_the_system_are_read() {
        let answer = json!({
            "resourceType": "Parameters",
            "parameter": [
                {"name": "targetIdentifier", "valueIdentifier": {"system": LOCAL, "value": "h-7"}},
                {"name": "targetIdentifier", "valueIdentifier": {"system": "urn:other", "value": "o-1"}},
                {"name": "targetId", "valueReference": {"reference": "Patient/x"}},
            ],
        });
        assert_eq!(
            vec![String::from("h-7")],
            target_identifiers(&answer, LOCAL)
        );
    }

    #[test]
    fn one_value_is_the_answer_and_none_or_several_refuse() {
        let values = |list: &[&str]| {
            list.iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            Ok(String::from("a")),
            one_of(values(&["a", "a"]).into_iter())
        );
        assert_eq!(Err(IndexRefusal::NoMatch), one_of(values(&[]).into_iter()));
        assert_eq!(
            Err(IndexRefusal::Several),
            one_of(values(&["a", "b"]).into_iter())
        );
    }

    #[test]
    fn a_patient_identifiers_in_the_system_are_read() {
        let patient = json!({"identifier": [
            {"system": LOCAL, "value": "h-7"},
            {"system": LOCAL, "value": " "},
            {"system": "urn:other", "value": "o-1"},
        ]});
        assert_eq!(vec![String::from("h-7")], identifiers_of(&patient, LOCAL));
    }
}
