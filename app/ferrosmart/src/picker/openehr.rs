// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The patient picker at an openEHR resource server (`docs/architecture.md`
//! §13.6 item 4).
//!
//! At an openEHR resource server `launch/patient` asks for the patient's
//! EHR, and "For Standalone Launch, the user should be prompted to select
//! the openEHR `EHR`" (SMART on openEHR draft, Context Selection). The
//! person names the patient by their identifier in the deployment's subject
//! namespace, and FerroSMART looks the EHR up with `GET
//! [base]/ehr?subject_id=…&subject_namespace=…` (openEHR ITS-REST 1.1.0,
//! `ehr_get_by_subject`) as that person, under the same guard as the FHIR
//! picker. The chosen EHR is looked up again as them before its `ehrId`
//! enters the launch context. The form is our own design.

use std::net::IpAddr;

use ehds_logging::record::{Action, DataSubject, EhrAt, PatientIdentifier, PatientLookup, Request};
use http::{HeaderMap, StatusCode};
use secrecy::SecretString;
use serde_json::Value;
use url::Url;

use super::purpose::{self, Declared};
use super::{Access, Ask, PickerError};
use crate::form::Params;
use crate::launch::context::Context;
use crate::pages::{self, Fault};
use crate::server::AppState;
use crate::store::Pending;

/// The one scope the picker's token carries at an openEHR server.
///
/// The `EHR` has no scope family of its own, so it is read under the
/// `composition-` family over every template (`docs/architecture.md` 3.9,
/// our own rule where the SMART on openEHR draft is silent).
pub const EHR_SCOPE: &str = "user/composition-*.r";

/// The system of the ITS-REST operation ids an access record names.
/// No specification names one: our own design, as FerroEHR records them.
pub const OPERATION_SYSTEM: &str = "urn:openehr:its-rest:operation";

/// The longest subject id or `ehr_id` the picker sends. No specification
/// bounds either: our own design.
const MAX_ID: usize = 255;

/// The EHR a lookup found, as the page shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundEhr {
    /// The subject id the person gave.
    pub subject_id: String,
    /// The EHR's `ehr_id`.
    pub ehr_id: String,
    /// When the EHR was created, as the server wrote it.
    pub time_created: Option<String>,
}

/// Answers `GET {issuer}/picker` at an openEHR resource server whose
/// subjects are named in `namespace`: the form, and the EHR the subject id
/// of `params` names when it names one.
pub(super) async fn look_up(
    state: &AppState,
    headers: &HeaderMap,
    pending: &Pending,
    from: IpAddr,
    namespace: &str,
    params: &Params,
) -> axum::response::Response {
    let Some(subject_id) = params
        .get("subject_id")
        .map(str::trim)
        .filter(|text| !text.is_empty())
    else {
        return pages::ehr_picker(state, headers, pending, None);
    };
    if subject_id.len() > MAX_ID {
        return pages::fault(state, Fault::BadRequest);
    }
    let (kept, declared) = match purpose::declared(state, pending, params).await {
        Ok(declared) => declared,
        Err(response) => return *response,
    };
    match by_subject(state, &kept, from, namespace, (subject_id, declared)).await {
        Ok(found) => pages::ehr_picker(state, headers, &kept, Some((subject_id, found.as_ref()))),
        Err(error) => pages::server_error(state, &error),
    }
}

/// Reads the choice of the form `form` at an openEHR resource server whose
/// subjects are named in `namespace`, looks it up again as the person and
/// returns the launch context it makes.
///
/// # Errors
/// Returns the page that answers a choice the person may not make, or a
/// lookup that failed.
pub(super) async fn choose(
    state: &AppState,
    pending: &Pending,
    from: IpAddr,
    namespace: &str,
    form: &Params,
) -> Result<Context, Box<axum::response::Response>> {
    let refuse = || Box::new(pages::fault(state, Fault::BadRequest));
    let subject_id = form
        .get("subject_id")
        .filter(|id| !id.is_empty() && id.len() <= MAX_ID)
        .ok_or_else(refuse)?;
    let ehr_id = form
        .get("ehr_id")
        .filter(|id| is_ehr_id(id))
        .ok_or_else(refuse)?;
    let (_, declared) = purpose::declared(state, pending, form).await?;
    // NOTE: SMART on openEHR draft, Context Selection, `ehrId` is the EHR of the
    // patient chosen, so the choice is looked up again as the person.
    match by_subject(state, pending, from, namespace, (subject_id, declared)).await {
        Ok(Some(found)) if found.ehr_id == ehr_id => Ok(Context {
            ehr_id: Some(found.ehr_id),
            ..Context::default()
        }),
        Ok(_) => Err(refuse()),
        Err(error) => Err(Box::new(pages::server_error(state, &error))),
    }
}

/// Looks up the EHR of `subject_id` in `namespace` as the person of
/// `pending`, declaring the purpose of use `declared` when it names one:
/// `None` when the server holds none they may see.
pub(super) async fn by_subject(
    state: &AppState,
    pending: &Pending,
    from: IpAddr,
    namespace: &str,
    (subject_id, declared): (&str, Option<Declared<'_>>),
) -> Result<Option<FoundEhr>, PickerError> {
    let person = super::Person::of(pending).ok_or(PickerError::Unreadable)?;
    let at = (pending.audience.as_str(), namespace);
    by_subject_as(state, &person, from, at, (subject_id, declared)).await
}

/// Looks up the EHR of `subject_id` in the namespace of `at` at the openEHR
/// base of `at` as `person`, as [`by_subject`] does.
pub(super) async fn by_subject_as(
    state: &AppState,
    person: &super::Person<'_>,
    from: IpAddr,
    (base, namespace): (&str, &str),
    (subject_id, declared): (&str, Option<Declared<'_>>),
) -> Result<Option<FoundEhr>, PickerError> {
    let mut url = ehr_url(base)?;
    url.query_pairs_mut()
        .append_pair("subject_id", subject_id)
        .append_pair("subject_namespace", namespace);
    let audience = base;
    let asked = &url;
    let ask = Ask {
        url: asked,
        audience,
        scope: EHR_SCOPE,
        accept: "application/json",
        describe: Box::new(move |fetched| access(audience, namespace, subject_id, asked, fetched)),
        purpose: declared,
    };
    match super::as_the(state, person, from, &ask).await {
        Ok(ehr) => found(subject_id, &ehr).map(Some),
        // NOTE: openEHR ITS-REST 1.1.0, ehr_get_by_subject, `404` is returned when
        // no EHR with the subject exists, which is an answer and no failure.
        Err(PickerError::Refused(StatusCode::NOT_FOUND)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Returns `[base]/ehr`.
fn ehr_url(base: &str) -> Result<Url, PickerError> {
    Url::parse(&format!("{}/ehr", base.trim_end_matches('/'))).map_err(PickerError::Url)
}

/// Returns the EHR the ITS-REST `Ehr` resource `ehr` describes.
fn found(subject_id: &str, ehr: &Value) -> Result<FoundEhr, PickerError> {
    let ehr_id = ehr
        .pointer("/ehr_id/value")
        .and_then(Value::as_str)
        .filter(|id| is_ehr_id(id))
        .ok_or(PickerError::Unreadable)?;
    Ok(FoundEhr {
        subject_id: subject_id.to_owned(),
        ehr_id: ehr_id.to_owned(),
        time_created: ehr
            .pointer("/time_created/value")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

/// Whether `id` can be an `ehr_id`: a `HIER_OBJECT_ID`, whose root is a
/// UUID, an ISO OID or an internet id, with an optional `::` extension
/// (openEHR BASE, Base Types, `UID_BASED_ID`); the characters those forms
/// use, at most [`MAX_ID`].
fn is_ehr_id(id: &str) -> bool {
    (1..=MAX_ID).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b':' | b'_'))
}

/// Returns the access the lookup of `subject_id` in `namespace` at
/// `audience` made, answered with `fetched`.
fn access(
    audience: &str,
    namespace: &str,
    subject_id: &str,
    url: &Url,
    fetched: &Result<Value, PickerError>,
) -> Access {
    let ehr_id = fetched
        .as_ref()
        .ok()
        .and_then(|ehr| ehr.pointer("/ehr_id/value"))
        .and_then(Value::as_str)
        .filter(|id| is_ehr_id(id));
    let delivered = match fetched {
        Ok(_) => Some(usize::from(ehr_id.is_some())),
        Err(PickerError::Refused(StatusCode::NOT_FOUND)) => Some(0),
        Err(_) => None,
    };
    Access {
        action: Action::Read,
        delivered,
        subject: DataSubject {
            patient: Some(PatientIdentifier {
                namespace: Some(namespace.to_owned()),
                value: SecretString::from(subject_id.to_owned()),
            }),
            ehrs: ehr_id
                .map(|ehr_id| EhrAt {
                    endpoint: audience.to_owned(),
                    ehr_id: ehr_id.to_owned(),
                    patient: PatientLookup::RequestNamed,
                })
                .into_iter()
                .collect(),
            population: None,
        },
        request: Request {
            id: None,
            operation: String::from("ehr_get_by_subject"),
            operation_system: Some(String::from(OPERATION_SYSTEM)),
            resource: None,
            query: Some(ihe_atna::balp::request_text(url)),
            stored_query: None,
            client_address: None,
            correlation: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ehr_id_is_a_hier_object_id_and_nothing_else() {
        assert!(is_ehr_id("7d44b88c-4199-4bad-97dc-d78268e01398"));
        assert!(is_ehr_id("1.2.840.114350::ext"));
        assert!(!is_ehr_id(""));
        assert!(!is_ehr_id("../ehr"));
        assert!(!is_ehr_id("a b"));
        assert!(!is_ehr_id(&"a".repeat(MAX_ID + 1)));
    }

    #[test]
    fn the_found_ehr_is_read_from_the_its_rest_resource() {
        let ehr = serde_json::json!({
            "ehr_id": {"value": "7d44b88c-4199-4bad-97dc-d78268e01398"},
            "time_created": {"value": "2015-01-20T19:30:22.765+01:00"}
        });
        let found = found("ins01", &ehr).expect("an EHR");
        assert_eq!("7d44b88c-4199-4bad-97dc-d78268e01398", found.ehr_id);
        assert_eq!(
            Some("2015-01-20T19:30:22.765+01:00"),
            found.time_created.as_deref()
        );
        assert!(matches!(
            super::found("ins01", &serde_json::json!({})),
            Err(PickerError::Unreadable)
        ));
    }
}
