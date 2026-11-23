// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The authorization endpoint: the request checked and the browser sent to
//! the upstream provider (SMART App Launch 2.2.0, Obtain authorization
//! code).

use std::net::IpAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::response::Response;

use crate::audit::Connected;
use crate::clients::{Client, GrantType};
use crate::form::Params;
use crate::launch::Unresolved;
use crate::pages::{self, Fault};
use crate::server::AppState;
use crate::store::{Pending, Purpose};

use super::{Back, COOKIE, Denial, REQUEST_SECONDS, Stop, fail, now, random, set_cookie};

/// `GET {issuer}/authorize`, the request in the query.
pub async fn authorize_get(
    State(state): State<Arc<AppState>>,
    Connected(from): Connected,
    RawQuery(query): RawQuery,
) -> Response {
    authorize(&state, query.unwrap_or_default().as_bytes(), from).await
}

/// `POST {issuer}/authorize`, the request as a form.
///
/// "Authorization Servers SHALL support the use of the HTTP GET and POST methods at the
/// Authorization Endpoint", SMART App Launch 2.2.0, Obtain authorization
/// code).
pub async fn authorize_post(
    State(state): State<Arc<AppState>>,
    Connected(from): Connected,
    body: Bytes,
) -> Response {
    authorize(&state, &body, from).await
}

/// Checks the authorization request `encoded` and sends the browser to the
/// upstream provider.
async fn authorize(state: &AppState, encoded: &[u8], from: IpAddr) -> Response {
    let Ok(params) = Params::parse(encoded, &[]) else {
        return pages::fault(state, Fault::BadRequest);
    };
    // NOTE: RFC 6749 §4.1.2.1, an unknown client or a redirect URI that is not
    // registered is told to the person, never redirected to.
    let client = match params.get("client_id") {
        Some(client_id) => match state.store().client(client_id).await {
            Ok(Some(client)) if client.grant_types.contains(&GrantType::AuthorizationCode) => {
                client
            }
            Ok(_) => return pages::fault(state, Fault::UnknownClient),
            Err(error) => return pages::server_error(state, &error),
        },
        None => return pages::fault(state, Fault::UnknownClient),
    };
    // NOTE: RFC 9700 §2.1, the redirect URI matches a registered one exactly.
    let Some(redirect_uri) = params.get("redirect_uri").filter(|uri| {
        client
            .redirect_uris
            .iter()
            .any(|registered| registered == uri)
    }) else {
        return pages::fault(state, Fault::UnknownRedirect);
    };
    let back = Back {
        redirect_uri: redirect_uri.to_owned(),
        state: params.get("state").map(str::to_owned),
        issuer: state.settings().issuer.clone(),
    };
    let (denial, fault) = match begin(state, &client, &params, redirect_uri, from).await {
        Ok(response) => return response,
        Err(Stop::Deny(denial)) => (denial, Fault::Refused),
        Err(Stop::Fail(error)) => {
            tracing::error!(error = %ferrohealth_server::run::chain(&*error), "the authorization request failed");
            let denial = Denial {
                error: "server_error",
                description: "the authorization server failed",
            };
            (denial, Fault::Server)
        }
    };
    // NOTE: RFC 9700 §4.11.2, the server authenticates the person before it redirects;
    // no administrator vouched for the redirect URI of an app that registered itself.
    if client.registered_itself() {
        return pages::fault(state, fault);
    }
    back.deny(denial)
}

/// Returns the resource server the request names for `client`.
fn audience<'a>(state: &'a AppState, client: &Client, params: &Params) -> Result<&'a str, Stop> {
    // NOTE: SMART App Launch 2.2.0, `aud` is required of the app and `resource` MAY
    // be its synonym; with one base configured a missing one defaults to it (#670).
    let resources = &state.settings().resources;
    let audience = match (
        params.get("aud").or_else(|| params.get("resource")),
        resources.as_slice(),
    ) {
        (Some(aud), _) => resources.iter().find(|base| base.as_str() == aud),
        (None, [only]) => Some(only),
        (None, _) => None,
    }
    .ok_or(Stop::Deny(Denial::request(
        "the aud is not a server this issuer serves",
    )))?;
    // NOTE: RFC 8707 §2, a base the client's `resources` does not list is
    // invalid_target, so a token's aud says the client was admitted there.
    if !client.reaches(audience) {
        return Err(Stop::Deny(Denial {
            error: "invalid_target",
            description: "the client may not name this resource server",
        }));
    }
    Ok(audience)
}

/// Checks the rest of the request and begins the upstream login.
async fn begin(
    state: &AppState,
    client: &Client,
    params: &Params,
    redirect_uri: &str,
    from: IpAddr,
) -> Result<Response, Stop> {
    if params.get("response_type") != Some("code") {
        return Err(Stop::Deny(Denial {
            error: "unsupported_response_type",
            description: "the response_type is not code",
        }));
    }
    // NOTE: SMART App Launch 2.2.0, Obtain authorization code, `state` is required.
    let client_state = params
        .get("state")
        .ok_or(Stop::Deny(Denial::request("the request carries no state")))?;
    // NOTE: SMART App Launch 2.2.0, Considerations for PKCE Support: S256, never plain.
    let challenge = params
        .get("code_challenge")
        .filter(|_| params.get("code_challenge_method") == Some("S256"))
        .ok_or(Stop::Deny(Denial::request(
            "the request carries no S256 code_challenge",
        )))?;
    let audience = audience(state, client, params)?;
    let scope = params.get("scope").ok_or(Stop::Deny(Denial {
        error: "invalid_scope",
        description: "the request names no scope",
    }))?;
    let mut asking = super::oidc::read(params).map_err(Stop::Deny)?;
    asking.acr = asking.acr.max(client.assurance_minimum);
    let launch_context = match params.get("launch") {
        Some(launch) => {
            match crate::launch::redeem(state, &client.client_id, launch, audience, scope, from)
                .await
            {
                Ok(context) => Some(context),
                Err(Unresolved::NoLaunchScope) => {
                    return Err(Stop::Deny(Denial {
                        error: "invalid_scope",
                        description: "a launch needs the launch scope",
                    }));
                }
                Err(Unresolved::Refused(rule)) => return Err(Stop::Deny(Denial::request(rule))),
                Err(Unresolved::Store(error)) => return Err(fail(error)),
                Err(Unresolved::Record(error)) => return Err(fail(error)),
            }
        }
        None => None,
    };
    // NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, Standalone apps: the
    // server may infer launch/patient; an EHR launch's context comes from launch.
    let scope = if launch_context.is_none() {
        crate::scopes::with_inferred_patient(scope)
    } else {
        scope.to_owned()
    };
    let allowed = state.providers().allowed(&client.upstreams);
    let start = super::choose::start(state, &allowed, &asking)?;
    let [upstream_state, upstream_nonce, upstream_verifier] = start.sign_in;
    let id = random().map_err(fail)?;
    let pending = Pending {
        id: id.clone(),
        client_id: Some(client.client_id.clone()),
        redirect_uri: redirect_uri.to_owned(),
        scope,
        state: client_state.to_owned(),
        nonce: params.get("nonce").map(str::to_owned),
        code_challenge: challenge.to_owned(),
        audience: audience.to_owned(),
        upstream_state,
        upstream_nonce,
        upstream_verifier,
        upstream_provider: start.provider,
        form_token: random().map_err(fail)?,
        subject: None,
        fhir_user: None,
        display_name: None,
        offered_scope: None,
        auth_time: None,
        expires_at: now().saturating_add(REQUEST_SECONDS),
        purpose: Purpose::Authorize,
        launch_context,
        upstream_session: None,
        roles: Vec::new(),
        asking,
        person_claims: crate::store::PersonClaims::default(),
        purpose_of_use: None,
        acr: None,
    };
    state
        .store()
        .begin_authorization(&pending)
        .await
        .map_err(fail)?;
    let mut response = start.departure.respond(state, &id);
    set_cookie(state, &mut response, COOKIE, &id, REQUEST_SECONDS);
    Ok(response)
}
