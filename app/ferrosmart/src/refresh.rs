// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The refresh token grant (RFC 6749 §6; SMART App Launch 2.2.0, Refresh
//! access token).
//!
//! Every refresh rotates the token: the one presented is used up and a new
//! one issued under the same grant, with the grant's whole scope (OAuth 2.1
//! draft §4.3.3). A token presented again after its rotation revokes the
//! grant with every token under it, which is the replay detection RFC 9700
//! §4.14.2 requires for public clients and FerroSMART applies to every
//! client, except that the same client presenting it again within
//! [`crate::store::grant::REPEAT_WINDOW`], while its successor is unused,
//! gets the same successor back: a retried or racing request is not a
//! replay. A refresh token lapses after its idle time, `refresh_idle` for
//! `offline_access` and `online_access`'s shorter `online_idle`, and an
//! `online_access` one with the person's upstream login
//! (`docs/architecture.md` §13.6 item 7). A refresh that names a
//! `resource` gets a token for that resource server alone, its own
//! audience or the FHIR base paired with it, with the scopes its kind
//! takes (RFC 8707 §2.2, `docs/architecture.md` §13.6 item 11).

use serde_json::{Map, Value};

use crate::audit::{Event, Happening};
use crate::authorize::{random, sha256};
use crate::clients::{Client, GrantType};
use crate::form::Params;
use crate::server::AppState;
use crate::store::Code;
use crate::store::Transaction;
use crate::store::grant::{Access, GrantRecord, IdleUntil, NewGrant, Rotation, Successor};
use crate::token::grants::identify;
use crate::token::mint::{Authentication, Grant, mint};
use crate::token::{Issued, Refusal, server_error};

/// The `invalid_grant` refusal: "The provided authorization grant ... or
/// refresh token is invalid, expired, revoked, ... or was issued to another
/// client" (RFC 6749 §5.2).
const fn invalid(description: &'static str) -> Refusal {
    Refusal {
        error: "invalid_grant",
        description,
    }
}

/// Answers a refresh token request.
pub(crate) async fn refresh(
    state: &AppState,
    headers: &http::HeaderMap,
    form: &Params,
    from: std::net::IpAddr,
) -> Result<Issued, Refusal> {
    let client = identify(state, headers, form).await?;
    if !client.grant_types.contains(&GrantType::RefreshToken) {
        return Err(Refusal {
            error: "unauthorized_client",
            description: "the client may not use this grant",
        });
    }
    let presented = form
        .get("refresh_token")
        .ok_or(Refusal::request("the request carries no refresh_token"))?;
    let hash = sha256(presented);
    let (scope, target) = requested(state, &client, form, &hash).await?;
    let (grant, successor) = redeem(state, &client, presented, &hash, from).await?;
    let context = grant.context.as_object().cloned().unwrap_or_default();
    let fhir_user = grant
        .fhir_user
        .as_deref()
        .filter(|_| holds(&scope, "fhirUser"));
    let mut issued = mint(
        state,
        &client,
        Grant {
            subject: &grant.subject,
            audience: target.as_deref().unwrap_or(&grant.audience),
            scope: &scope,
            fhir_user,
            code_hash: None,
            token_type: "bearer",
            longest: None,
            identity: None,
            under: Some(&grant.id),
            context: &context,
            roles: &grant.roles,
            login: Some(Authentication::of(&grant)),
        },
    )?;
    // NOTE: SMART App Launch 2.2.0, Refresh access token, Response: the launch
    // context MAY be included, and is, as the original response carried it.
    issued.response.refresh_token = Some(successor);
    Ok(issued)
}

/// Redeems the refresh token `presented`, whose SHA-256 is `hash`, for
/// `client` in one transaction committed with its record, and returns the
/// grant it is under with the successor to answer.
async fn redeem(
    state: &AppState,
    client: &Client,
    presented: &str,
    hash: &str,
    from: std::net::IpAddr,
) -> Result<(Box<GrantRecord>, String), Refusal> {
    let salt = random().map_err(|error| server_error("no refresh token could be drawn", &error))?;
    let successor = derived(presented, &salt);
    let settings = state.settings();
    let now = jiff::Timestamp::now().as_second();
    let idle = IdleUntil {
        offline: now.saturating_add_unsigned(settings.refresh_idle.as_secs()),
        online: now.saturating_add_unsigned(settings.online_idle.as_secs()),
    };
    let mut tx = state
        .store()
        .begin()
        .await
        .map_err(|error| server_error("the refresh token cannot be redeemed", &error))?;
    let rotation = tx
        .rotate(
            hash,
            &client.client_id,
            Successor {
                hash: &sha256(&successor),
                salt: &salt,
            },
            idle,
        )
        .await
        .map_err(|error| server_error("the refresh token cannot be redeemed", &error))?;
    let endpoint = settings.endpoint_url(crate::discovery::TOKEN_ROUTE);
    let happening = |event, subject, grant_id: &str| Happening {
        event,
        issuer: &settings.issuer,
        client_id: Some(&client.client_id),
        subject,
        from,
        endpoint: &endpoint,
        details: vec![("grant", grant_id.to_owned())],
    };
    match rotation {
        Rotation::Rotated(grant) => {
            commit(
                state,
                tx,
                &happening(
                    Event::RefreshRotated,
                    Some(grant.subject.as_str()),
                    &grant.id,
                ),
            )
            .await?;
            Ok((grant, successor))
        }
        // NOTE: our own design (docs/architecture.md §13.6 item 11): a retry or a
        // race within the window gets the successor the first answer carried.
        Rotation::Repeated { grant, salt } => {
            commit(
                state,
                tx,
                &happening(
                    Event::RefreshRepeated,
                    Some(grant.subject.as_str()),
                    &grant.id,
                ),
            )
            .await?;
            Ok((grant, derived(presented, &salt)))
        }
        Rotation::Reused { grant_id } => {
            commit(state, tx, &happening(Event::RefreshReused, None, &grant_id)).await?;
            Err(invalid("the refresh token was used before"))
        }
        // NOTE: an invalid or foreign token changes nothing, so the transaction
        // is dropped and its request is recorded as the ITI-71 refusal alone.
        Rotation::OtherClient | Rotation::Invalid => Err(invalid("the refresh token is not valid")),
    }
}

/// Returns the scope and the audience a refresh request asks for: the
/// grant's scope narrowed by its `scope`, and the resource its `resource`
/// names with the scope its kind takes. An unknown token asks for nothing,
/// and the rotation refuses it.
async fn requested(
    state: &AppState,
    client: &Client,
    form: &Params,
    hash: &str,
) -> Result<(String, Option<String>), Refusal> {
    // NOTE: SMART App Launch 2.2.0, Refresh access token, Request: a scope names no
    // permission the grant lacks; it is checked before the token is used up.
    let granted = state
        .store()
        .refresh_token(hash)
        .await
        .map_err(|error| server_error("the refresh token cannot be read", &error))?
        .filter(|record| record.grant.client_id == client.client_id)
        .map(|record| (record.grant.scope, record.grant.audience));
    let mut scope = match (&granted, form.get("scope")) {
        (Some((granted, _)), Some(requested)) => narrowed(granted, requested)?,
        (Some((granted, _)), None) => granted.clone(),
        (None, _) => String::new(),
    };
    // NOTE: RFC 8707 §2.2, a refresh request's `resource` names the token's target,
    // which the grant's policy limits; it is checked before the token is used up.
    let target = match (&granted, form.get("resource")) {
        (Some((_, audience)), Some(named)) => {
            let target = reachable(state, audience, named)?;
            scope = for_kind(&scope, state.settings().openehr_resources.contains(&target))?;
            Some(target)
        }
        _ => None,
    };
    // NOTE: RFC 8707 §2, the token's aud must be a base the client's `resources`
    // lists now, so a base taken off its list is refused from the next refresh.
    if let Some((_, audience)) = &granted
        && !client.reaches(target.as_deref().unwrap_or(audience))
    {
        return Err(Refusal {
            error: "invalid_target",
            description: "the client may not name this resource server",
        });
    }
    Ok((scope, target))
}

/// What redeeming a code opens: the grant every token of the launch is
/// issued under, the launch context the responses carry, and the first
/// refresh token when the grant has one.
#[derive(Debug)]
pub(crate) struct Opened {
    /// The grant's id.
    pub(crate) grant_id: String,
    /// The launch context parameters.
    pub(crate) context: Map<String, Value>,
    /// The first refresh token.
    pub(crate) refresh_token: Option<String>,
}

/// Records the grant the code `code` opens for `client`, with its first
/// refresh token when the person granted `offline_access` or
/// `online_access` and the client registered the `refresh_token` grant.
///
/// `offline_access` wins over `online_access` when both are granted; an
/// `online_access` grant needs the upstream session the person logged in
/// under, and gets no refresh token without one (`docs/architecture.md`
/// §13.6 item 7).
pub(crate) async fn open(
    state: &AppState,
    client: &Client,
    code: &Code,
) -> Result<Opened, Refusal> {
    let settings = state.settings();
    let mut context = Map::new();
    if !settings.branding.smart_style_url.is_empty() {
        context.insert(
            String::from("smart_style_url"),
            Value::String(settings.branding.smart_style_url.clone()),
        );
    }
    // NOTE: SMART App Launch 2.2.0, Launch context arrives with your access_token:
    // an EHR launch's context joins the response (docs/architecture.md §13.6 item 3).
    if let Some(launch) = &code.launch_context {
        match serde_json::to_value(launch) {
            Ok(Value::Object(members)) => context.extend(members),
            Ok(_) => {
                return Err(Refusal {
                    error: "server_error",
                    description: "the launch context is no JSON object",
                });
            }
            Err(error) => {
                return Err(server_error(
                    "the launch context could not be written",
                    &error,
                ));
            }
        }
    }
    let refreshes = client.grant_types.contains(&GrantType::RefreshToken);
    let access = if !refreshes {
        None
    } else if holds(&code.scope, "offline_access") {
        Some(Access::Offline)
    } else if holds(&code.scope, "online_access") && code.upstream_session.is_some() {
        Some(Access::Online)
    } else {
        None
    };
    let grant_id = random().map_err(|error| server_error("no grant id could be drawn", &error))?;
    let context_value = Value::Object(context.clone());
    state
        .store()
        .create_grant(&NewGrant {
            id: &grant_id,
            client_id: &client.client_id,
            subject: &code.subject,
            fhir_user: code
                .fhir_user
                .as_deref()
                .filter(|_| holds(&code.scope, "fhirUser")),
            audience: &code.audience,
            scope: &code.scope,
            context: &context_value,
            auth_time: Some(code.auth_time),
            access,
            upstream_session: code
                .upstream_session
                .as_deref()
                .filter(|_| access == Some(Access::Online)),
            approved_at: code.approved_at,
            roles: &code.roles,
            acr: code.acr,
        })
        .await
        .map_err(|error| server_error("the grant could not be recorded", &error))?;
    let refresh_token = match access {
        Some(access) => {
            let value = random()
                .map_err(|error| server_error("no refresh token could be drawn", &error))?;
            let idle = match access {
                Access::Offline => settings.refresh_idle,
                Access::Online => settings.online_idle,
            };
            let expires = jiff::Timestamp::now()
                .as_second()
                .saturating_add_unsigned(idle.as_secs());
            state
                .store()
                .issue_refresh(&sha256(&value), &grant_id, expires)
                .await
                .map_err(|error| server_error("the refresh token could not be recorded", &error))?;
            Some(value)
        }
        None => None,
    };
    tracing::info!(
        target: "ferrosmart::audit",
        event = "grant.opened",
        client_id = %client.client_id,
        grant = %grant_id,
        access = access.map_or("none", Access::as_str),
        "a grant was opened"
    );
    Ok(Opened {
        grant_id,
        context,
        refresh_token,
    })
}

/// Returns the successor of the refresh token `presented` drawn with
/// `salt`: the SHA-256 of both, so only a holder of the presented token can
/// derive it again, and the store, which keeps the salt beside the presented
/// token's hash, cannot.
fn derived(presented: &str, salt: &str) -> String {
    sha256(&format!("{presented}.{salt}"))
}

/// Returns whether the space-separated `scope` holds `wanted`.
fn holds(scope: &str, wanted: &str) -> bool {
    scope.split(' ').any(|held| held == wanted)
}

/// Returns the scopes of `requested` the grant's `granted` scope holds, in
/// the grant's order, refusing a request that names any other ("no new
/// permissions can be obtained at refresh time", SMART App Launch 2.2.0,
/// Refresh access token, Request; "MUST NOT include any scope not
/// originally granted", OAuth 2.1 draft §4.3.1).
fn narrowed(granted: &str, requested: &str) -> Result<String, Refusal> {
    let requested: Vec<&str> = requested.split(' ').filter(|s| !s.is_empty()).collect();
    let held: Vec<&str> = granted.split(' ').filter(|s| !s.is_empty()).collect();
    if requested.is_empty() || requested.iter().any(|scope| !held.contains(scope)) {
        return Err(Refusal {
            error: "invalid_scope",
            description: "the scope names a permission the grant does not hold",
        });
    }
    Ok(held
        .into_iter()
        .filter(|scope| requested.contains(scope))
        .collect::<Vec<_>>()
        .join(" "))
}

/// Returns the resource server `named` when the grant for `audience` may
/// reach it: the grant's own audience, or the FHIR base paired with it
/// (`docs/architecture.md` §13.6 item 11). Any other is `invalid_target`
/// (RFC 8707 §2).
fn reachable(state: &AppState, audience: &str, named: &str) -> Result<String, Refusal> {
    let paired = state
        .settings()
        .pairings
        .get(audience)
        .is_some_and(|pairing| pairing.fhir_base == named);
    if named == audience || paired {
        Ok(named.to_owned())
    } else {
        Err(Refusal {
            error: "invalid_target",
            description: "the grant does not reach the resource",
        })
    }
}

/// Returns the scopes of `scope` a resource server of one kind takes: every
/// scope but the clinical scopes of the other kind's grammar. A clinical
/// scope of the `template-`, `composition-` or `aql-` family is openEHR's
/// (SMART on openEHR draft, Resource Scopes); any other is FHIR's (SMART
/// App Launch 2.2.0, Scopes for requesting FHIR Resources). A scope
/// left empty is `invalid_scope` (RFC 6749 §5.2).
fn for_kind(scope: &str, openehr: bool) -> Result<String, Refusal> {
    let taken: Vec<&str> = scope
        .split(' ')
        .filter(|held| !held.is_empty())
        .filter(|held| clinical_kind(held).is_none_or(|kind| kind == openehr))
        .collect();
    if taken.is_empty() {
        return Err(Refusal {
            error: "invalid_scope",
            description: "the grant holds no scope the resource takes",
        });
    }
    Ok(taken.join(" "))
}

/// Returns whether the clinical scope `scope` is openEHR's, or `None` for a
/// scope that names no resource.
fn clinical_kind(scope: &str) -> Option<bool> {
    let (context, rest) = scope.split_once('/')?;
    if !matches!(context, "patient" | "user" | "system") {
        return None;
    }
    let (resource, _) = rest.rsplit_once('.')?;
    Some(
        ["template-", "composition-", "aql-"]
            .iter()
            .any(|family| resource.starts_with(family)),
    )
}

/// Commits `tx` with the record of `happening`, or refuses the request as
/// the server's failure.
async fn commit(
    state: &AppState,
    tx: Transaction,
    happening: &Happening<'_>,
) -> Result<(), Refusal> {
    state
        .audit()
        .commit_happening(tx, happening)
        .await
        .map_err(|error| server_error("the refresh could not be recorded", &error))
}
