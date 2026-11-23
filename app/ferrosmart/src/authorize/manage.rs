// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The management page of the apps a person allowed, the
//! `management_endpoint` (SMART App Launch 2.2.0, Conformance, Metadata).

use std::net::IpAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::response::Response;
use http::HeaderMap;

use crate::audit::{self, Connected};
use crate::form::Params;
use crate::pages::{self, Fault};
use crate::server::AppState;
use crate::store::grant::Access;
use crate::store::{Asking, Pending, Purpose};

use super::{
    COOKIE, MANAGE_ROUTE, REQUEST_SECONDS, Stop, constant_eq, cookie, fail, now, random, see_other,
    set_cookie,
};

/// `GET {issuer}/manage`: the person's remembered consents and the apps
/// holding live access to their data, once they logged in at the provider
/// for it; the visit begins that login.
pub async fn manage_get(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(id) = cookie(&headers, COOKIE) {
        match state.store().pending(&id).await {
            Ok(Some(pending))
                if pending.purpose == Purpose::Manage && pending.subject.is_some() =>
            {
                return manage_page(&state, &headers, &pending).await;
            }
            Ok(_) => {}
            Err(error) => return pages::server_error(&state, &error),
        }
    }
    let every: Vec<_> = state.providers().iter().collect();
    let begun = (|| {
        let start = super::choose::start(&state, &every, &Asking::default())?;
        Ok::<_, Stop>((start, random().map_err(fail)?, random().map_err(fail)?))
    })();
    let (start, id, form_token) = match begun {
        Ok(begun) => begun,
        Err(Stop::Deny(_)) => return pages::fault(&state, Fault::BadRequest),
        Err(Stop::Fail(_)) => return pages::fault(&state, Fault::Server),
    };
    let [upstream_state, upstream_nonce, upstream_verifier] = start.sign_in;
    let pending = Pending {
        id: id.clone(),
        client_id: None,
        redirect_uri: String::new(),
        scope: String::new(),
        state: String::new(),
        nonce: None,
        code_challenge: String::new(),
        audience: String::new(),
        upstream_state,
        upstream_nonce,
        upstream_verifier,
        upstream_provider: start.provider,
        form_token,
        subject: None,
        fhir_user: None,
        display_name: None,
        offered_scope: None,
        auth_time: None,
        expires_at: now().saturating_add(REQUEST_SECONDS),
        purpose: Purpose::Manage,
        launch_context: None,
        upstream_session: None,
        roles: Vec::new(),
        asking: Asking::default(),
        person_claims: crate::store::PersonClaims::default(),
        purpose_of_use: None,
        acr: None,
    };
    if let Err(error) = state.store().begin_authorization(&pending).await {
        return pages::server_error(&state, &error);
    }
    let mut response = start.departure.respond(&state, &id);
    set_cookie(&state, &mut response, COOKIE, &id, REQUEST_SECONDS);
    response
}

/// `POST {issuer}/manage`: disconnects the app the form names from the
/// person, forgetting their remembered consent and revoking the app's
/// grants and tokens about them.
pub async fn manage_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Connected(from): Connected,
    body: Bytes,
) -> Response {
    let Ok(form) = Params::parse(&body, &[]) else {
        return pages::fault(&state, Fault::BadRequest);
    };
    let pending = match cookie(&headers, COOKIE) {
        Some(id) => match state.store().pending(&id).await {
            Ok(Some(pending)) if pending.purpose == Purpose::Manage => pending,
            Ok(_) => return pages::fault(&state, Fault::Lapsed),
            Err(error) => return pages::server_error(&state, &error),
        },
        None => return pages::fault(&state, Fault::Lapsed),
    };
    let sent = form.get("form_token").unwrap_or_default();
    let (Some(subject), Some(client_id)) = (&pending.subject, form.get("client_id")) else {
        return pages::fault(&state, Fault::BadRequest);
    };
    if !constant_eq(sent.as_bytes(), pending.form_token.as_bytes()) {
        return pages::fault(&state, Fault::BadRequest);
    }
    match disconnect(&state, subject, client_id, from).await {
        Ok(()) => see_other(&state.settings().endpoint(MANAGE_ROUTE)),
        Err(error) => pages::server_error(&state, &error),
    }
}

/// Disconnects `client_id` from `subject` with its record in one
/// transaction, leaving any organisation approval of the client in place.
async fn disconnect(
    state: &AppState,
    subject: &str,
    client_id: &str,
    from: IpAddr,
) -> Result<(), audit::RecordFailure> {
    let mut tx = state
        .store()
        .begin()
        .await
        .map_err(audit::RecordFailure::Store)?;
    let ended = tx
        .revoke_consent(subject, client_id)
        .await
        .map_err(audit::RecordFailure::Store)?;
    let endpoint = state.settings().endpoint_url(MANAGE_ROUTE);
    state
        .audit()
        .commit_happening(
            tx,
            &audit::Happening {
                event: audit::Event::ConsentWithdrawn,
                issuer: &state.settings().issuer,
                client_id: Some(client_id),
                subject: Some(subject),
                from,
                endpoint: &endpoint,
                details: vec![
                    ("remembered", ended.remembered.to_string()),
                    ("grants", ended.grants.to_string()),
                ],
            },
        )
        .await
}

/// Draws the management page of `pending`'s person.
async fn manage_page(state: &AppState, headers: &HeaderMap, pending: &Pending) -> Response {
    let Some(subject) = &pending.subject else {
        return pages::fault(state, Fault::Lapsed);
    };
    let consents = match state.store().consents(subject).await {
        Ok(consents) => consents,
        Err(error) => return pages::server_error(state, &error),
    };
    // NOTE: SMART App Launch 2.2.0, Best Practices, remind users which apps have
    // offline access: every app with live access is listed, remembered or not.
    let connected = match state.store().connected_apps(subject).await {
        Ok(connected) => connected,
        Err(error) => return pages::server_error(state, &error),
    };
    let mut apps: std::collections::BTreeMap<String, (String, Option<Access>, bool)> = consents
        .into_iter()
        .map(|(client_id, scope)| (client_id, (scope, None, false)))
        .collect();
    for app in connected {
        apps.entry(app.client_id)
            .and_modify(|(_, access, organisation)| {
                *access = app.access;
                *organisation = app.organisation;
            })
            .or_insert((app.scope, app.access, app.organisation));
    }
    let mut named = Vec::with_capacity(apps.len());
    for (client_id, (scope, access, organisation)) in apps {
        let (name, first_party) = match state.store().client(&client_id).await {
            Ok(Some(client)) => {
                let first_party = client
                    .approval()
                    .is_some_and(|approval| approval.first_party);
                (client.name, first_party)
            }
            Ok(None) => (client_id.clone(), false),
            Err(error) => return pages::server_error(state, &error),
        };
        named.push(pages::Remembered {
            client_id,
            name,
            scope,
            access,
            organisation,
            first_party: organisation && first_party,
        });
    }
    pages::manage(state, headers, pending, &named)
}
