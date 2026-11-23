// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A person's grants, consents and sessions through the admin API, so an
//! administrator ends a person's access as the person can on the
//! management page (`docs/architecture.md` §13.8).
//!
//! Withdrawing is as easy as giving (GDPR Art 7(3)): each change commits
//! with its record naming the admin client and the person. No
//! specification governs the routes: our own design.

use std::net::IpAddr;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, RawQuery, State};
use axum::response::{IntoResponse, Response};
use ferrohealth_smart::resource::Access;
use http::StatusCode;
use serde_json::{Value, json};

use super::document::instant;
use super::{AdminError, no_store};
use crate::audit::{self, Connected, Happening};
use crate::server::AppState;
use crate::store::Transaction;

/// A person's FerroSMART subject, looked up by provider and upstream `sub`.
pub const SUBJECTS_ROUTE: &str = "/admin/subjects";
/// A person's live grants and remembered consents.
pub const GRANTS_ROUTE: &str = "/admin/subjects/{sub}/grants";
/// One grant of a person.
pub const GRANT_ROUTE: &str = "/admin/subjects/{sub}/grants/{grant_id}";
/// A person's consent for one client.
pub const CONSENT_ROUTE: &str = "/admin/subjects/{sub}/consents/{client_id}";
/// A person's upstream sessions.
pub const SESSIONS_ROUTE: &str = "/admin/subjects/{sub}/sessions";

/// `GET /admin/subjects?upstream=&sub=`: the pairwise subject of the person
/// `sub` at the provider `upstream` (`docs/architecture.md` §13.6 item 9).
pub(super) async fn lookup(
    State(state): State<Arc<AppState>>,
    RawQuery(query): RawQuery,
) -> Result<Response, AdminError> {
    let params = crate::form::Params::parse(query.unwrap_or_default().as_bytes(), &[])
        .map_err(|_repeated| AdminError::Query("a parameter is named twice"))?;
    if params
        .names()
        .any(|name| !matches!(name, "upstream" | "sub"))
    {
        return Err(AdminError::Query(
            "the query names a parameter this route does not read",
        ));
    }
    let (Some(name), Some(sub)) = (params.get("upstream"), params.get("sub")) else {
        return Err(AdminError::Query("the query names `upstream` and `sub`"));
    };
    if sub.is_empty() {
        return Err(AdminError::Query("`sub` is empty"));
    }
    let upstream = state
        .settings()
        .upstreams
        .iter()
        .find(|upstream| upstream.name == name)
        .ok_or_else(|| AdminError::NoProvider(name.to_owned()))?;
    let subject = crate::upstream::pairwise(upstream.issuer(), sub);
    Ok(no_store(
        Json(json!({ "upstream": name, "subject": subject })).into_response(),
    ))
}

/// `GET /admin/subjects/{sub}/grants`: the person's live grants, newest
/// first, and the consents they remembered.
pub(super) async fn grants(
    State(state): State<Arc<AppState>>,
    Path(subject): Path<String>,
) -> Result<Response, AdminError> {
    let store = state.store();
    let grants: Vec<Value> = store
        .live_grants(&subject)
        .await?
        .into_iter()
        .map(|grant| {
            let mut entry = json!({
                "grant_id": grant.id,
                "client_id": grant.client_id,
                "aud": grant.audience,
                "scope": grant.scope,
                "issued_at": instant(grant.issued_at),
            });
            if let Some(members) = entry.as_object_mut() {
                for (name, value) in [("basis", grant.basis), ("access", grant.access)] {
                    if let Some(value) = value {
                        members.insert(String::from(name), Value::from(value));
                    }
                }
                if let Some(used) = grant.last_used_at {
                    members.insert(String::from("last_used_at"), Value::from(instant(used)));
                }
            }
            entry
        })
        .collect();
    let consents: Vec<Value> = store
        .remembered_consents(&subject)
        .await?
        .into_iter()
        .map(|consent| {
            json!({
                "client_id": consent.client_id,
                "aud": consent.audience,
                "scope": consent.scope,
                "granted_at": instant(consent.granted_at),
            })
        })
        .collect();
    Ok(no_store(
        Json(json!({ "subject": subject, "grants": grants, "consents": consents })).into_response(),
    ))
}

/// `DELETE /admin/subjects/{sub}/grants/{grant_id}`: revokes the person's
/// grant with every token under it.
pub(super) async fn revoke(
    State(state): State<Arc<AppState>>,
    Connected(from): Connected,
    access: Access,
    Path((subject, grant_id)): Path<(String, String)>,
) -> Result<Response, AdminError> {
    let mut tx = state.store().begin().await?;
    let client = tx
        .revoke_subject_grant(&subject, &grant_id)
        .await?
        .ok_or(AdminError::NoGrant)?;
    let change = SubjectChange::new(&state, &access, from, &subject);
    change
        .commit(
            tx,
            audit::Event::GrantRevoked,
            vec![("client", client), ("grant", grant_id)],
        )
        .await?;
    Ok(no_store(StatusCode::NO_CONTENT.into_response()))
}

/// `DELETE /admin/subjects/{sub}/consents/{client_id}`: disconnects the
/// client from the person as the management page does, forgetting their
/// remembered consent and revoking the client's grants about them.
pub(super) async fn withdraw(
    State(state): State<Arc<AppState>>,
    Connected(from): Connected,
    access: Access,
    Path((subject, client_id)): Path<(String, String)>,
) -> Result<Response, AdminError> {
    let mut tx = state.store().begin().await?;
    let ended = tx.revoke_consent(&subject, &client_id).await?;
    let change = SubjectChange::new(&state, &access, from, &subject);
    change
        .commit(
            tx,
            audit::Event::ConsentWithdrawn,
            vec![
                ("client", client_id),
                ("remembered", ended.remembered.to_string()),
                ("grants", ended.grants.to_string()),
            ],
        )
        .await?;
    Ok(no_store(
        Json(json!({ "remembered": ended.remembered, "grants": ended.grants })).into_response(),
    ))
}

/// `DELETE /admin/subjects/{sub}/sessions`: ends every upstream session of
/// the person with its `online_access` grants.
pub(super) async fn end_sessions(
    State(state): State<Arc<AppState>>,
    Connected(from): Connected,
    access: Access,
    Path(subject): Path<String>,
) -> Result<Response, AdminError> {
    let mut tx = state.store().begin().await?;
    let ended = tx.end_sessions(&subject).await?;
    let change = SubjectChange::new(&state, &access, from, &subject);
    change
        .commit(
            tx,
            audit::Event::SessionEnded,
            vec![
                ("sessions", ended.sessions.to_string()),
                ("grants", ended.grants.to_string()),
            ],
        )
        .await?;
    Ok(no_store(
        Json(json!({ "sessions": ended.sessions, "grants": ended.grants })).into_response(),
    ))
}

/// A change an administrator makes to a person's access.
struct SubjectChange<'a> {
    /// The state.
    state: &'a AppState,
    /// The admin client.
    by: Option<&'a str>,
    /// The address the request came from.
    from: IpAddr,
    /// The person.
    subject: &'a str,
}

impl<'a> SubjectChange<'a> {
    /// Returns the change `access` makes from `from` to `subject`.
    fn new(state: &'a AppState, access: &'a Access, from: IpAddr, subject: &'a str) -> Self {
        Self {
            state,
            by: access.caller().and_then(|caller| caller.client_id()),
            from,
            subject,
        }
    }

    /// Commits `tx` with the record of `event`, holding `details`.
    async fn commit(
        &self,
        tx: Transaction,
        event: audit::Event,
        details: Vec<(&'static str, String)>,
    ) -> Result<(), AdminError> {
        let endpoint = self.state.settings().endpoint_url(SUBJECTS_ROUTE);
        self.state
            .audit()
            .commit_happening(
                tx,
                &Happening {
                    event,
                    issuer: self.state.settings().issuer.as_str(),
                    client_id: self.by,
                    subject: Some(self.subject),
                    from: self.from,
                    endpoint: &endpoint,
                    details,
                },
            )
            .await
            .map_err(AdminError::Record)?;
        tracing::info!(
            target: "ferrosmart::audit",
            event = event.code(),
            "a person's access was changed by an administrator"
        );
        Ok(())
    }
}
