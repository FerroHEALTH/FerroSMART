// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The consent page, the scopes it offers and the code its approval issues
//! (`docs/architecture.md` §13.6 items 5 and 6).

use std::net::IpAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::response::Response;
use http::HeaderMap;

use crate::audit::{self, Connected};
use crate::clients::{Client, GrantType};
use crate::form::Params;
use crate::launch::context::Context;
use crate::pages::{self, Fault};
use crate::server::AppState;
use crate::store::{Code, Pending};

use super::{
    Back, CODE_SECONDS, CONSENT_ROUTE, COOKIE, Denial, constant_eq, found, logged_in, now, random,
    registered, see_other, set_cookie, sha256,
};

/// What the person's `fhirUser` says of them at the request's resource
/// server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FhirUser {
    /// The provider carries no `fhirUser`.
    Absent,
    /// A `fhirUser` that is not the person's own `Patient` at this server.
    Present,
    /// The person is the `Patient` their `fhirUser` names at this server.
    ThePatient,
}

/// Returns the scopes the consent page offers the person.
///
/// Of the requested scopes it offers `openid` and `fhirUser` when the client may ask for them (and the
/// provider carries the person's `fhirUser`, without which "it cannot
/// support the `fhirUser` scope", SMART App Launch 2.2.0, Scopes for
/// requesting identity data), and each `user/` scope the client may ask
/// for and one of the person's roles grants (13.6 item 5). An EHR launch's
/// `context` adds `launch`, the `launch/patient` and `launch/encounter`
/// hints its context answers, and the `patient/` scopes the ceiling and a
/// role allow once the launch put a patient in context (SMART App Launch
/// 2.2.0, Scopes and Launch Context, Apps that launch from the EHR). Scopes
/// that need a standalone patient or a refresh token join with the steps
/// that bring them (#518). A standalone launch whose `picker` can search
/// the resource server offers `launch/patient` and the `patient/` scopes,
/// since the patient picker puts the patient in context (#516), and at a
/// FHIR server also `launch/encounter`, which the picker answers with one
/// of the patient's encounters (#604). The picker chooses an encounter only
/// with a patient, so `launch/encounter` alone is not offered. An extension
/// scope (`__`-prefixed) is offered when the ceiling and a role list it
/// (#647). A person whose `fhirUser` is their own `Patient` at the server
/// is offered the `patient/` scopes the ceiling allows without a role,
/// since those reach their own record alone (#673). Matching a scope as
/// written is our own design.
#[must_use]
pub fn offer(
    requested: &str,
    client: &Client,
    held: &[String],
    roles: &std::collections::BTreeMap<String, Vec<String>>,
    fhir_user: FhirUser,
    context: Option<&Context>,
    picker: crate::picker::Reach,
) -> Vec<String> {
    // NOTE: SMART App Launch 2.2.0, Obtain authorization code, a standalone
    // launch's `launch/patient` is answered by the patient selection widget.
    let chosen_by_picker = picker != crate::picker::Reach::Nothing
        && context.is_none()
        && requested.split(' ').any(|scope| scope == "launch/patient")
        && client
            .scopes
            .iter()
            .any(|allowed| allowed == "launch/patient");
    let patient = chosen_by_picker || context.is_some_and(|context| context.patient.is_some());
    // NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, Standalone apps,
    // `launch/encounter` SHOULD be provided, by the picker at a FHIR server.
    let encounter = context.is_some_and(|context| context.encounter.is_some())
        || (chosen_by_picker && picker == crate::picker::Reach::Encounter);
    let ceiling = |scope: &str| crate::scopes::admits(&client.scopes, scope);
    let granted_by_role = |scope: &str| {
        held.iter()
            .filter_map(|role| roles.get(role))
            .any(|scopes| crate::scopes::admits(scopes, scope))
    };
    let mut offered: Vec<String> = Vec::new();
    for scope in requested.split(' ').filter(|scope| !scope.is_empty()) {
        let admitted = match scope {
            // NOTE: OpenID Connect Core 1.0 §5.4, profile and email ask for the
            // standard claims the upstream ID Token carries.
            "openid" | "profile" | "email" => ceiling(scope),
            "fhirUser" => ceiling(scope) && fhir_user != FhirUser::Absent,
            user if user.starts_with("user/") => ceiling(user) && granted_by_role(user),
            "launch" => ceiling(scope) && context.is_some(),
            "launch/patient" => ceiling(scope) && patient,
            "launch/encounter" => ceiling(scope) && encounter,
            single if single.starts_with("patient/") => {
                // NOTE: docs/architecture.md §13.6 item 4 (owner, 2026-11-19, #673): a
                // patient's own patient/ scopes need no role, as they reach that record alone.
                patient
                    && ceiling(single)
                    && (granted_by_role(single) || fhir_user == FhirUser::ThePatient)
            }
            // NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, Extensibility, an
            // extension scope is the server's own; a role grants it, never the request alone.
            extension if crate::scopes::is_extension(extension) => {
                ceiling(extension) && granted_by_role(extension)
            }
            // NOTE: SMART App Launch 2.2.0, Refresh access token, the server decides
            // which clients get a refresh token: those whose ceiling and grants name it.
            "offline_access" | "online_access" => {
                ceiling(scope) && client.grant_types.contains(&GrantType::RefreshToken)
            }
            _ => false,
        };
        if admitted && !offered.iter().any(|kept| kept == scope) {
            offered.push(scope.to_owned());
        }
    }
    // NOTE: OpenID Connect Core 1.0 §3.1.2.1, `fhirUser` arrives in an ID Token,
    // which only `openid` asks for.
    if !offered.iter().any(|scope| scope == "openid") {
        offered.retain(|scope| !matches!(scope.as_str(), "fhirUser" | "profile" | "email"));
    }
    offered
}

/// `GET {issuer}/consent`: the consent page of the browser's request.
pub async fn consent_get(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let pending = match logged_in(&state, &headers).await {
        Ok(pending) => pending,
        Err(response) => return *response,
    };
    if crate::picker::waits(&state, &pending) {
        return see_other(&state.settings().endpoint(crate::picker::PICKER_ROUTE));
    }
    let client = match registered(&state, &pending).await {
        Ok(client) => client,
        Err(response) => return *response,
    };
    // NOTE: RFC 8252 §8.6, a request shown the page though a remembered consent
    // covers it starts from that decision, the remember box ticked.
    let remembered = match &pending.subject {
        Some(subject) => match state
            .store()
            .remembered(subject, &client.client_id, &pending.audience)
            .await
        {
            Ok(remembered) => remembered.is_some(),
            Err(error) => return pages::server_error(&state, &error),
        },
        None => false,
    };
    pages::consent(&state, &headers, &client, &pending, remembered)
}

/// `POST {issuer}/consent`: the person's decision.
pub async fn consent_post(
    State(state): State<Arc<AppState>>,
    Connected(from): Connected,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(form) = Params::parse(&body, &["scope"]) else {
        return pages::fault(&state, Fault::BadRequest);
    };
    let pending = match logged_in(&state, &headers).await {
        Ok(pending) => pending,
        Err(response) => return *response,
    };
    // NOTE: RFC 6749 §10.12, the decision carries the token its page drew.
    let sent = form.get("form_token").unwrap_or_default();
    if !constant_eq(sent.as_bytes(), pending.form_token.as_bytes()) {
        return pages::fault(&state, Fault::BadRequest);
    }
    let client = match registered(&state, &pending).await {
        Ok(client) => client,
        Err(response) => return *response,
    };
    let pending = match found(&state, state.store().finish(&pending.id).await) {
        Ok(pending) => pending,
        Err(response) => return *response,
    };
    let back = Back::of(&state, &pending);
    let mut response = if form.get("decision") == Some("approve") {
        // NOTE: RFC 7591 §5, an app that registered itself is shown the page every
        // time, so no consent to it is remembered.
        let remember = form.get("remember") == Some("yes") && !client.registered_itself();
        let basis = Basis::Person { remember };
        approve(&state, &pending, &form.all("scope"), basis, &back, from).await
    } else {
        tracing::info!(
            target: "ferrosmart::audit",
            event = "authorization.declined",
            client_id = ?pending.client_id,
            "the person declined"
        );
        back.deny(Denial {
            error: "access_denied",
            description: "the person declined",
        })
    };
    set_cookie(&state, &mut response, COOKIE, "", 0);
    response
}

/// What a code is issued on (`docs/architecture.md` §13.6 item 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    /// The person approved on the consent page, and chose whether to
    /// remember it.
    Person {
        /// Whether to remember the consent.
        remember: bool,
    },
    /// A consent the person remembered covers the request.
    Remembered,
    /// An administrator registered the client, the organisation's
    /// consent for its professionals, and the person saw no page.
    Administrative,
    /// The client is the controller's own or acts for it, and the person
    /// saw no page.
    FirstParty,
}

impl Basis {
    /// The basis as the code, the grant and the `code-issued` record name
    /// it: `page`, `remembered`, `administrative` or `first-party`.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Person { .. } => "page",
            Self::Remembered => "remembered",
            Self::Administrative => "administrative",
            Self::FirstParty => "first-party",
        }
    }
}

/// Who the person is, by the resource type their `fhirUser` names (SMART
/// App Launch 2.2.0, Scopes and Launch Context, `fhirUser`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Person {
    /// A `Practitioner` or `PractitionerRole`.
    Professional,
    /// A `Patient`, a `RelatedPerson` or a `Person`: the person whose data
    /// it is, or one who speaks for them (Regulation (EU) 2025/327 Art 4(2)).
    Represented,
    /// No `fhirUser`, or one of another type.
    Unstated,
}

impl Person {
    /// Returns the person `fhir_user` names, a reference whose last two path
    /// segments are the resource type and id.
    #[must_use]
    pub fn of(fhir_user: Option<&str>) -> Self {
        match fhir_user.and_then(|reference| reference.rsplit('/').nth(1)) {
            Some("Practitioner" | "PractitionerRole") => Self::Professional,
            Some("Patient" | "RelatedPerson" | "Person") => Self::Represented,
            _ => Self::Unstated,
        }
    }
}

/// Returns the basis on which `person` gets a code for `client` with no
/// consent page, or `None` when they see it.
///
/// An administrator's registration is the organisation's consent for its
/// professionals: RFC 6749 §4.1.1 lets the server establish approval "via
/// other means", OpenID Connect Core 1.0 §3.1.2.4 names "previous
/// administrative consent", and SMART App Launch 2.2.0 (Best Practices,
/// Considerations for Scope Consent) asks the user's consent where the
/// client and the resource server are not from the same organization. A
/// patient or their representative decides which other party's app reads
/// their data (Regulation (EU) 2025/327 Art 3, 4(2), 7(1)), so they skip the
/// page only for a first-party app. An app that registered itself asserts
/// its own metadata (RFC 7591 §5) and always shows the page. Every offered
/// scope lies within the registration's ceiling.
#[must_use]
pub fn without_page(client: &Client, person: Person, offered: &[&str]) -> Option<Basis> {
    if client.registered_itself()
        || !offered
            .iter()
            .all(|scope| crate::scopes::admits(&client.scopes, scope))
    {
        return None;
    }
    match person {
        Person::Professional => Some(Basis::Administrative),
        Person::Represented if client.first_party() => Some(Basis::FirstParty),
        Person::Represented | Person::Unstated => None,
    }
}

/// Issues the code for the offered fixed scopes and the resource scopes the
/// person kept, and sends the browser back to the app with it.
pub(super) async fn approve(
    state: &AppState,
    pending: &Pending,
    selected: &[&str],
    basis: Basis,
    back: &Back,
    from: IpAddr,
) -> Response {
    let offered = pending.offered_scope.as_deref().unwrap_or_default();
    let mut granted: Vec<&str> = offered
        .split(' ')
        .filter(|scope| crate::scopes::is_fixed(scope) || selected.contains(scope))
        .collect();
    if !granted.contains(&"openid") {
        granted.retain(|scope| !matches!(*scope, "fhirUser" | "profile" | "email"));
    }
    // NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, an EHR launch's context
    // comes under `launch`, a standalone one's under `launch/patient` from the picker.
    let launch_context = pending.launch_context.as_ref().filter(|_| {
        granted.contains(&"launch")
            || (!pending.scope.split(' ').any(|scope| scope == "launch")
                && granted.contains(&"launch/patient"))
    });
    if launch_context.is_none() {
        granted.retain(|scope| !scope.starts_with("patient/") && !scope.starts_with("launch/"));
    }
    if granted.is_empty() {
        return back.deny(Denial {
            error: "access_denied",
            description: "the person granted no scope",
        });
    }
    let (Some(subject), Some(auth_time), Some(client_id)) =
        (&pending.subject, pending.auth_time, &pending.client_id)
    else {
        return pages::fault(state, Fault::Lapsed);
    };
    let issued = random().map(|code| (sha256(&code), code));
    let Ok((hash, code)) = issued else {
        return back.deny(Denial {
            error: "server_error",
            description: "no code could be drawn",
        });
    };
    let grant = Code {
        client_id: client_id.clone(),
        redirect_uri: pending.redirect_uri.clone(),
        code_challenge: pending.code_challenge.clone(),
        audience: pending.audience.clone(),
        subject: subject.clone(),
        fhir_user: pending.fhir_user.clone(),
        scope: granted.join(" "),
        nonce: pending.nonce.clone(),
        auth_time,
        expires_at: now().saturating_add(CODE_SECONDS),
        launch_context: launch_context.cloned(),
        upstream_session: pending.upstream_session.clone(),
        basis: Some(String::from(basis.code())),
        roles: pending.roles.clone(),
        person_claims: pending.person_claims.granted(&granted.join(" ")),
        acr: pending.acr,
    };
    if let Err(error) = issue_code(state, &hash, &grant, basis, from).await {
        tracing::error!(error = %ferrohealth_server::run::chain(&error), "the code could not be stored");
        return back.deny(Denial {
            error: "server_error",
            description: "the code could not be stored",
        });
    }
    back.grant(&code)
}

/// Stores the code `grant` under `hash`, with the person's consent when
/// they chose to remember it and the record of the registration it rests
/// on when it skipped the page, in one transaction.
async fn issue_code(
    state: &AppState,
    hash: &str,
    grant: &Code,
    basis: Basis,
    from: IpAddr,
) -> Result<(), audit::RecordFailure> {
    let endpoint = state.settings().endpoint_url(CONSENT_ROUTE);
    let happening = |event, details| audit::Happening {
        event,
        issuer: &state.settings().issuer,
        client_id: Some(&grant.client_id),
        subject: Some(&grant.subject),
        from,
        endpoint: &endpoint,
        details,
    };
    let lane = state.audit();
    let mut tx = state
        .store()
        .begin()
        .await
        .map_err(audit::RecordFailure::Store)?;
    tx.issue_code(hash, grant)
        .await
        .map_err(audit::RecordFailure::Store)?;
    let skipped = match basis {
        Basis::Administrative => Some(audit::Event::ConsentAdministrative),
        Basis::FirstParty => Some(audit::Event::ConsentFirstParty),
        Basis::Person { .. } | Basis::Remembered => None,
    };
    if let Some(event) = skipped {
        let approved = audit::happened(&happening(event, vec![("scope", grant.scope.clone())]));
        tx.record(&lane.row(
            &approved,
            event.code(),
            Some(&grant.subject),
            Some(&grant.client_id),
        )?)
        .await
        .map_err(audit::RecordFailure::Store)?;
    }
    if matches!(basis, Basis::Person { remember: true }) {
        tx.remember(
            &grant.subject,
            &grant.client_id,
            &grant.audience,
            &grant.scope,
        )
        .await
        .map_err(audit::RecordFailure::Store)?;
        let remembered = audit::happened(&happening(
            audit::Event::ConsentRemembered,
            vec![("scope", grant.scope.clone())],
        ));
        tx.record(&lane.row(
            &remembered,
            audit::Event::ConsentRemembered.code(),
            Some(&grant.subject),
            Some(&grant.client_id),
        )?)
        .await
        .map_err(audit::RecordFailure::Store)?;
    }
    // NOTE: no specification governs audit content: our own design, the record of a
    // code names the basis it was issued on.
    lane.commit_happening(
        tx,
        &happening(
            audit::Event::CodeIssued,
            vec![
                ("scope", grant.scope.clone()),
                ("basis", String::from(basis.code())),
            ],
        ),
    )
    .await
}
