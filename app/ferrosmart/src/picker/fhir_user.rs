// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The person's `fhirUser` found by an identifier when the upstream provider
//! sends none (`docs/architecture.md` §13.6 item 9).
//!
//! SMART App Launch 2.2.0 requires the `fhirUser` claim when `fhirUser` is
//! granted and leaves how the server knows it to the server. Each
//! `[[ferrosmart.resource.fhir_user_lookup]]` names a resource type, the
//! upstream claim whose text is an identifier's value and that identifier's
//! system; FerroSMART searches `[base]/[type]?identifier=[system]|[value]`
//! (FHIR R4 search, token parameters) as the signed-in person, and one match
//! across the lookups is the `fhirUser`. None or several leave it out: never
//! a guess. The lookup tables and the one-match rule are our own design.

use std::net::IpAddr;

use ehds_logging::record::{Action, DataSubject};
use serde_json::{Map, Value};
use url::Url;

use super::send::as_person;
use super::{Access, Ask, entries, fhir_request, is_fhir_id};
use crate::server::AppState;
use crate::store::Pending;

/// What the lookups found of the person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// One resource: the `fhirUser`, relative to the request's base or
    /// absolute at a paired one.
    Found(String),
    /// No resource carries the person's identifier, or the provider sent no
    /// value for any lookup.
    NoMatch,
    /// More than one resource carries it.
    Several,
    /// A search failed or was refused.
    Failed,
}

impl Resolved {
    /// Returns the outcome as an audit line names it.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Found(_) => "found",
            Self::NoMatch => "no-match",
            Self::Several => "several",
            Self::Failed => "failed",
        }
    }
}

/// Looks the person of `pending` up at the FHIR server the request to
/// `audience` reads, by the lookups configured there and the upstream ID
/// Token's `claims`; `None` when no lookup is configured there.
pub(crate) async fn resolve(
    state: &AppState,
    pending: &Pending,
    from: IpAddr,
    audience: &str,
    claims: &Map<String, Value>,
) -> Option<Resolved> {
    let settings = state.settings();
    let base = match settings.pairings.get(audience) {
        Some(pairing) => pairing.fhir_base.as_str(),
        None => audience,
    };
    let lookups = settings.fhir_user_lookups.get(base)?;
    let mut found: Vec<String> = Vec::new();
    for lookup in lookups {
        let Some(value) = ferrohealth_smart::roles::claim_text(claims, &lookup.claim) else {
            continue;
        };
        let kind = lookup.resource_type.as_str();
        let Ok(mut url) = Url::parse(&format!("{}/{kind}", base.trim_end_matches('/'))) else {
            return Some(Resolved::Failed);
        };
        // NOTE: FHIR R4 search, token parameter `identifier=[system]|[code]`.
        url.query_pairs_mut()
            .append_pair("identifier", &format!("{}|{value}", lookup.system));
        let asked = &url;
        let ask = Ask {
            url: asked,
            audience: base,
            scope: lookup.resource_type.scope(),
            accept: "application/fhir+json",
            describe: Box::new(move |fetched| Access {
                action: Action::Query,
                delivered: fetched
                    .as_ref()
                    .ok()
                    .map(|bundle| entries(bundle, kind).count()),
                subject: DataSubject::default(),
                request: fhir_request(asked, Action::Query, kind),
            }),
            purpose: None,
        };
        match as_person(state, pending, from, &ask).await {
            Ok(bundle) => found.extend(
                entries(&bundle, kind)
                    .filter_map(|resource| resource.get("id").and_then(Value::as_str))
                    .filter(|id| is_fhir_id(id))
                    .map(|id| format!("{kind}/{id}")),
            ),
            Err(_) => return Some(Resolved::Failed),
        }
    }
    found.sort();
    found.dedup();
    Some(match found.as_slice() {
        [] => Resolved::NoMatch,
        [one] if base == audience => Resolved::Found(one.clone()),
        [one] => Resolved::Found(format!("{}/{one}", base.trim_end_matches('/'))),
        _ => Resolved::Several,
    })
}
