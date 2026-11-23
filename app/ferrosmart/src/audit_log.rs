// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! `GET {issuer}/audit`: FerroSMART's own audit records, read by subject and
//! time.
//!
//! Regulation (EU) 2025/327 Art 9 gives a person access to the information
//! on who accessed their data, so the records FerroSMART keeps of logins and
//! tokens are readable by an operator's client without a database client.
//! The caller presents a bearer access token FerroSMART issued for its own
//! issuer with [`AUDIT_SCOPE`]; the answer is a FHIR R4 `searchset` Bundle of
//! `AuditEvent` resources, newest first. No specification governs the
//! endpoint's parameters: our own design.

use std::sync::Arc;

use axum::extract::{RawQuery, State};
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};
use serde_json::{Value, json};

use crate::admin::openapi::Operation;
use crate::introspect::{Refused, bearer, presented};
use crate::server::AppState;
use crate::store::audit::AuditQuery;

/// The route of the audit records under the issuer.
pub const AUDIT_ROUTE: &str = "/audit";

/// The scope a caller's token carries to read the records: the SMART v2
/// scope to read and search `AuditEvent` resources (SMART App Launch 2.2.0,
/// Scopes for requesting clinical data).
pub const AUDIT_SCOPE: &str = "system/AuditEvent.rs";

/// The records one answer holds unless `_count` names fewer.
pub const DEFAULT_COUNT: i64 = 100;

/// The most records one answer holds.
pub const MAX_COUNT: i64 = 1000;

/// Returns the operation of the audit records.
#[must_use]
pub fn table() -> Vec<Operation> {
    vec![Operation::get(AUDIT_ROUTE, audit_log)]
}

/// `GET {issuer}/audit?subject=&since=&until=&_count=`.
pub async fn audit_log(
    State(state): State<Arc<AppState>>,
    headers: http::HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let token = match presented(&headers) {
        Ok(Some(token)) => token,
        Ok(None) => return challenge(StatusCode::UNAUTHORIZED, None),
        Err(refused) => return refused.into_response(),
    };
    match bearer(&state, token, AUDIT_SCOPE).await {
        Ok(_client) => {}
        // NOTE: RFC 6750 §3.1, insufficient_scope answers 403.
        Err(Refused::Bearer("insufficient_scope")) => {
            return challenge(StatusCode::FORBIDDEN, Some("insufficient_scope"));
        }
        Err(refused) => return refused.into_response(),
    }
    let Ok(asked) = read_query(query.as_deref().unwrap_or_default()) else {
        return (
            StatusCode::BAD_REQUEST,
            "the query is not one this endpoint reads",
        )
            .into_response();
    };
    match state.store().audit_records(&asked).await {
        Ok(records) => {
            let entry: Vec<Value> = records
                .into_iter()
                .map(|resource| json!({ "resource": resource }))
                .collect();
            let bundle = json!({ "resourceType": "Bundle", "type": "searchset", "entry": entry });
            let mut response = axum::Json(bundle).into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/fhir+json"),
            );
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(error) => {
            tracing::error!(error = %ferrohealth_server::run::chain(&error), "the audit records cannot be read");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Returns the answer naming the bearer scheme with `error`, if any (RFC
/// 6750 §3).
fn challenge(status: StatusCode, error: Option<&str>) -> Response {
    let value = error.map_or_else(
        || String::from("Bearer"),
        |error| format!("Bearer error=\"{error}\", scope=\"{AUDIT_SCOPE}\""),
    );
    let mut response = status.into_response();
    if let Ok(value) = HeaderValue::from_str(&value) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

/// Why a query could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unreadable;

/// Reads `query`: `subject`, `since` and `until` as RFC 3339 instants, and
/// `_count` from 1 to [`MAX_COUNT`], each at most once.
///
/// # Errors
///
/// Returns [`Unreadable`] for a parameter named twice, an unknown one, an
/// instant that is no RFC 3339 instant or a count outside its range.
pub fn read_query(query: &str) -> Result<AuditQuery, Unreadable> {
    let params =
        crate::form::Params::parse(query.as_bytes(), &[]).map_err(|_repeated| Unreadable)?;
    let instant = |name: &str| {
        params
            .get(name)
            .map(|text| {
                text.parse::<jiff::Timestamp>()
                    .map(|instant| instant.to_string())
                    .map_err(|_not_an_instant| Unreadable)
            })
            .transpose()
    };
    let limit = params
        .get("_count")
        .map(|text| text.parse::<i64>().map_err(|_not_a_number| Unreadable))
        .transpose()?
        .unwrap_or(DEFAULT_COUNT);
    if !(1..=MAX_COUNT).contains(&limit) {
        return Err(Unreadable);
    }
    if params
        .names()
        .any(|name| !matches!(name, "subject" | "since" | "until" | "_count"))
    {
        return Err(Unreadable);
    }
    Ok(AuditQuery {
        subject: params.get("subject").map(str::to_owned),
        since: instant("since")?,
        until: instant("until")?,
        limit,
    })
}
