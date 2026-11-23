// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! `GET {issuer}/audit`: FerroSMART's own audit records, read by subject,
//! client, event, outcome and time, a page at a time.
//!
//! Regulation (EU) 2025/327 Art 9 gives a person access to the information
//! on who accessed their data, so the records FerroSMART keeps of logins and
//! tokens are readable by an operator's client without a database client.
//! The caller presents a bearer access token FerroSMART issued for its own
//! issuer with [`AUDIT_SCOPE`]; the answer is a FHIR R4 `searchset` Bundle of
//! `AuditEvent` resources, newest first, whose `next` link reads the next
//! page (FHIR R4 Bundle.link). No specification governs the endpoint's
//! parameters: our own design.

use std::sync::Arc;

use axum::extract::{RawQuery, State};
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};
use serde_json::{Value, json};

use crate::admin::openapi::Operation;
use crate::introspect::{Refused, bearer, presented};
use crate::server::AppState;
use crate::store::audit::{AuditCursor, AuditQuery};

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

/// `GET {issuer}/audit?subject=&client=&event=&outcome=&since=&until=&_count=&cursor=`.
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
    match state.store().audit_page(&asked).await {
        Ok(page) => {
            let entry: Vec<Value> = page
                .records
                .into_iter()
                .map(|resource| json!({ "resource": resource }))
                .collect();
            let audit = state.settings().endpoint(AUDIT_ROUTE);
            let mut link =
                vec![json!({ "relation": "self", "url": page_url(&audit, &asked, asked.after) })];
            if let Some(next) = page.next {
                link.push(
                    json!({ "relation": "next", "url": page_url(&audit, &asked, Some(next)) }),
                );
            }
            let bundle = json!({
                "resourceType": "Bundle",
                "type": "searchset",
                "link": link,
                "entry": entry,
            });
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

/// Returns the URL of the page of `asked` that starts after `cursor`, at
/// the audit endpoint `audit`.
fn page_url(audit: &str, asked: &AuditQuery, cursor: Option<AuditCursor>) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in [
        ("subject", &asked.subject),
        ("client", &asked.client),
        ("event", &asked.event),
        ("outcome", &asked.outcome),
        ("since", &asked.since),
        ("until", &asked.until),
    ] {
        if let Some(value) = value {
            query.append_pair(name, value);
        }
    }
    query.append_pair("_count", &asked.limit.to_string());
    if let Some(cursor) = cursor {
        query.append_pair("cursor", &cursor.to_string());
    }
    format!("{audit}?{}", query.finish())
}

/// The `AuditEvent.outcome` codes (FHIR R4, the `AuditEventOutcome` value set).
const OUTCOMES: [&str; 4] = ["0", "4", "8", "12"];

/// Why a query could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unreadable;

/// Reads `query`, each parameter at most once.
///
/// `subject`, `client` and `event` are taken as given, `outcome` as an
/// `AuditEvent.outcome` code, `since` and `until` as RFC 3339 instants,
/// `_count` from 1 to [`MAX_COUNT`], and `cursor` as a next link names it.
///
/// # Errors
///
/// Returns [`Unreadable`] for a parameter named twice, an unknown one, an
/// instant that is no RFC 3339 instant, an outcome that is no
/// outcome code, a count outside its range or a cursor no link names.
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
    if params.names().any(|name| {
        !matches!(
            name,
            "subject" | "client" | "event" | "outcome" | "since" | "until" | "_count" | "cursor"
        )
    }) {
        return Err(Unreadable);
    }
    let text = |name: &str| params.get(name).map(str::to_owned);
    let outcome = text("outcome");
    if outcome
        .as_deref()
        .is_some_and(|code| !OUTCOMES.contains(&code))
    {
        return Err(Unreadable);
    }
    let after = params
        .get("cursor")
        .map(|cursor| cursor.parse::<AuditCursor>().map_err(|_unread| Unreadable))
        .transpose()?;
    Ok(AuditQuery {
        subject: text("subject"),
        client: text("client"),
        event: text("event"),
        outcome,
        since: instant("since")?,
        until: instant("until")?,
        after,
        limit,
    })
}
