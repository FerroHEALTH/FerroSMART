// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The upstream provider's redirect back: the login completed, the person's
//! scopes offered, and on to the consent page or the app.

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{RawQuery, State};
use axum::response::Response;
use ferrohealth_secret::secret::Secret;
use ferrohealth_smart::oidc::{Callback, PendingSignIn};
use http::HeaderMap;
use url::Url;

use ferrohealth_smart::assurance::AssuranceLevel;

use crate::assurance::Assurance;
use crate::audit::Connected;
use crate::audit::exchanges::{Person, login};
use crate::clients::Client;
use crate::form::Params;
use crate::pages::{self, Fault};
use crate::picker::patient_index::IndexRefusal;
use crate::server::AppState;
use crate::store::{Asking, Login, Pending, Purpose};
use crate::upstream::{Identity, LoginProvider};

use super::consent::{FhirUser, approve, offer, without_page};
use super::{
    Back, CONSENT_ROUTE, COOKIE, Denial, MANAGE_ROUTE, cookie, deny_unsigned, forget, found, now,
    random, registered, see_other, set_cookie,
};

/// `GET {issuer}/callback`, where the upstream provider sends the browser
/// back.
pub async fn callback(
    State(state): State<Arc<AppState>>,
    Connected(from): Connected,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let query = query.unwrap_or_default();
    let Ok(answer) = read_callback(&query) else {
        return pages::fault(&state, Fault::BadRequest);
    };
    let Some(upstream_state) = answer.state.as_deref() else {
        return pages::fault(&state, Fault::Lapsed);
    };
    let pending = match found(
        &state,
        state.store().pending_by_upstream(upstream_state).await,
    ) {
        Ok(pending) => pending,
        Err(response) => return *response,
    };
    // NOTE: RFC 9700 §4.7, the login completes in the browser that began it.
    if cookie(&headers, COOKIE).as_deref() != Some(pending.id.as_str()) {
        return pages::fault(&state, Fault::OtherBrowser);
    }
    // NOTE: the login completes at the provider the request went to, with its
    // settings alone; a callback another provider's login answers fails its check.
    let Some(provider) = pending
        .upstream_provider
        .as_deref()
        .and_then(|name| state.providers().named(name))
    else {
        return pages::fault(&state, Fault::Lapsed);
    };
    let Some(party) = provider.oidc() else {
        return pages::fault(&state, Fault::BadRequest);
    };
    let upstream = provider.upstream();
    let sign_in = PendingSignIn::from_parts(
        pending.upstream_state.clone(),
        pending.upstream_nonce.clone(),
        Secret::new(pending.upstream_verifier.clone()),
    );
    let signed_in = match party.exchange(&sign_in, &answer).await {
        Ok(signed_in) => signed_in,
        Err(error) => {
            forget(&state, &pending).await;
            tracing::warn!(error = %ferrohealth_server::run::chain(&error), "the upstream login failed");
            let reason = if answer.error.is_some() {
                "the person declined at the provider"
            } else {
                "the login could not be completed"
            };
            if let Err(response) = record_login(&state, upstream, Err(reason)).await {
                return *response;
            }
            if pending.purpose == Purpose::Manage {
                return pages::fault(&state, Fault::Lapsed);
            }
            // NOTE: RFC 6749 §4.1.2.1, a person who declined at the provider is
            // access_denied; any other failure is the server's.
            let denial = if answer.error.is_some() {
                Denial {
                    error: "access_denied",
                    description: "the login was declined",
                }
            } else {
                Denial {
                    error: "server_error",
                    description: "the login could not be completed",
                }
            };
            return deny_unsigned(&state, &pending, denial).await;
        }
    };
    let identity = Identity::from_id_token(&signed_in.claims);
    complete(&state, &pending, provider, &identity, from).await
}

/// Goes on once the person logged in at `provider` as `identity`: the
/// login judged against the request's `max_age`, and on to [`proceed`].
pub(super) async fn complete(
    state: &AppState,
    pending: &Pending,
    provider: &LoginProvider,
    identity: &Identity,
    from: IpAddr,
) -> Response {
    let upstream = provider.upstream();
    let back = Back::of(state, pending);
    let auth_time = match freshness(&pending.asking, identity.auth_time, now()) {
        Fresh::At(auth_time) => auth_time,
        Fresh::Again => return again(state, pending, provider).await,
        Fresh::Stale => {
            forget(state, pending).await;
            if let Err(response) =
                record_login(state, upstream, Err("the login is older than max_age")).await
            {
                return *response;
            }
            // NOTE: OpenID Connect Core 1.0 §3.1.2.6: the person could not be
            // authenticated within max_age, so the request needs a login.
            let denial = Denial {
                error: "login_required",
                description: "the login is older than max_age",
            };
            return deny_unsigned(state, pending, denial).await;
        }
    };
    let acr = upstream.assurance.level_of(identity.acr.as_deref());
    if let Some(short) = short_of(&pending.asking, &upstream.assurance, acr) {
        forget(state, pending).await;
        if let Err(response) = record_login(state, upstream, Err(short.description)).await {
            return *response;
        }
        if pending.purpose == Purpose::Manage {
            return pages::fault(state, Fault::Assurance);
        }
        return deny_unsigned(state, pending, short).await;
    }
    let signed_in = SignedIn {
        upstream,
        wallet: provider.wallet(),
        identity,
        auth_time,
        acr,
    };
    proceed(state, pending, &back, &signed_in, from).await
}

/// Returns the refusal of a login at the eIDAS level `reached`, none when it
/// reaches both the provider's minimum, the deployment's floor included,
/// and the level the request asks.
fn short_of(
    asking: &Asking,
    assurance: &Assurance,
    reached: Option<AssuranceLevel>,
) -> Option<Denial> {
    let below = |needed: AssuranceLevel| reached.is_none_or(|level| level < needed);
    // NOTE: RFC 6749 §4.1.2.1, the server's own minimum unmet is a denial of access.
    if assurance.minimum().is_some_and(below) {
        return Some(Denial {
            error: "access_denied",
            description: "the login does not reach the level of assurance required",
        });
    }
    // NOTE: RFC 9470 §5, an acr value the request asks for and the login does not
    // meet fails the request with unmet_authentication_requirements.
    asking.acr.is_some_and(below).then_some(Denial {
        error: "unmet_authentication_requirements",
        description: "the login does not reach the level of assurance asked for",
    })
}

/// A person's login at a provider, as the steps after it read it.
#[derive(Debug, Clone, Copy)]
struct SignedIn<'a> {
    /// The provider's settings.
    upstream: &'a crate::upstream::Upstream,
    /// The provider as an EUDI Wallet verifier, when it is one.
    wallet: Option<&'a crate::upstream::wallet::WalletLogin>,
    /// What the provider's login states.
    identity: &'a Identity,
    /// When the person authenticated, in seconds since the epoch.
    auth_time: i64,
    /// The eIDAS level the login reached, when the provider's value maps
    /// to one.
    acr: Option<AssuranceLevel>,
}

/// When the person last authenticated, as the request's `max_age` judges
/// the upstream login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fresh {
    /// They authenticated at this time, in seconds since the epoch.
    At(i64),
    /// The upstream login is older than `max_age`, or does not say when it
    /// authenticated: it is begun again with `prompt=login`.
    Again,
    /// The upstream login begun again is still older than `max_age`.
    Stale,
}

/// Judges the upstream login's `auth_time`, `upstream`, against what
/// `asking` asked, at `now`. Without `max_age` the time is the upstream
/// login's, or the callback's when its ID Token names none.
fn freshness(asking: &Asking, upstream: Option<i64>, now: i64) -> Fresh {
    let Some(max_age) = asking.max_age else {
        return Fresh::At(upstream.map_or(now, |at| at.min(now)));
    };
    // NOTE: OpenID Connect Core 1.0 §3.1.2.1: past max_age the OP MUST attempt to
    // actively re-authenticate, so the upstream login is begun again with prompt=login.
    match upstream {
        Some(at) if now.saturating_sub(at) <= max_age => Fresh::At(at.min(now)),
        _ if !asking.reauthenticated => Fresh::Again,
        Some(_) => Fresh::Stale,
        // NOTE: the upstream login was told prompt=login, so it authenticated just now.
        None => Fresh::At(now),
    }
}

/// Begins the upstream login of `pending` at `provider` again with
/// `prompt=login` (a SAML request's `ForceAuthn`), as its authentication
/// was older than the request's `max_age`.
async fn again(state: &AppState, pending: &Pending, provider: &LoginProvider) -> Response {
    let mut asking = pending.asking.clone();
    asking.prompt.login = true;
    let Ok((departure, [upstream_state, nonce, verifier])) =
        super::choose::sign_in_at(provider, &asking)
    else {
        return pages::fault(state, Fault::Server);
    };
    if let Err(error) = state
        .store()
        .reauthenticate(&pending.id, &upstream_state, &nonce, &verifier)
        .await
    {
        return pages::server_error(state, &error);
    }
    departure.respond(state, &pending.id)
}

/// The person's `fhirUser`: the provider's claim, or for an authorization
/// the patient index's answer to a wallet login, or else the identifier
/// lookup when the provider sends none.
///
/// # Errors
/// Returns [`IndexRefusal`] when a wallet login's patient index finds no
/// patient or several, or cannot be asked.
async fn fhir_user_of(
    state: &AppState,
    pending: &Pending,
    signed_in: &SignedIn<'_>,
    subject: &str,
    from: IpAddr,
) -> Result<Option<String>, IndexRefusal> {
    let claimed = signed_in
        .upstream
        .fhir_user_claim
        .as_deref()
        .and_then(|claim| ferrohealth_smart::roles::claim_text(&signed_in.identity.claims, claim))
        .map(str::to_owned);
    match claimed {
        Some(claimed) => Ok(Some(claimed)),
        None if pending.purpose == Purpose::Authorize => {
            let index = crate::picker::patient_index::configured(state, &pending.audience);
            if let (Some(wallet), Some(index)) = (signed_in.wallet, index) {
                let claims = &signed_in.identity.claims;
                return indexed(state, pending, subject, (wallet, claims), index, from)
                    .await
                    .map(Some);
            }
            Ok(looked_up(state, pending, subject, &signed_in.identity.claims, from).await)
        }
        None => Ok(None),
    }
}

/// Returns the `fhirUser` the patient index `index` resolves the PID
/// `claims` the wallet verified to, for the person `subject`, and writes
/// the outcome as an audit line, never a value (`docs/architecture.md`
/// §13.32).
async fn indexed(
    state: &AppState,
    pending: &Pending,
    subject: &str,
    (wallet, claims): (
        &crate::upstream::wallet::WalletLogin,
        &serde_json::Map<String, serde_json::Value>,
    ),
    index: (&crate::config::PatientIndexSection, &str),
    from: IpAddr,
) -> Result<String, IndexRefusal> {
    let asking = Pending {
        subject: Some(subject.to_owned()),
        ..pending.clone()
    };
    let resolved = match wallet.upstream().identifier(claims) {
        Ok(identifier) => {
            crate::picker::patient_index::resolve(state, &asking, from, index, &identifier).await
        }
        Err(_undisclosed) => Err(IndexRefusal::NoIdentifier),
    };
    tracing::info!(
        target: "ferrosmart::audit",
        event = "patient_index.lookup",
        client_id = ?pending.client_id,
        outcome = resolved.as_ref().map_or_else(|refusal| refusal.as_str(), |_| "found"),
        "the person's patient was resolved at the patient index"
    );
    resolved
}

/// Goes on once the person logged in as `claims` for `pending`: to the
/// management page, to the consent page, or straight back to the app with
/// a code when a remembered consent covers what is offered.
async fn proceed(
    state: &AppState,
    pending: &Pending,
    back: &Back,
    signed_in: &SignedIn<'_>,
    from: IpAddr,
) -> Response {
    let SignedIn {
        upstream,
        identity,
        auth_time,
        acr,
        ..
    } = *signed_in;
    let held = ferrohealth_smart::roles::from_claims(&identity.claims, &upstream.role_claims);
    let subject = crate::upstream::pairwise(&identity.issuer, &identity.subject);
    let fhir_user = match fhir_user_of(state, pending, signed_in, &subject, from).await {
        Ok(fhir_user) => fhir_user,
        Err(refusal) => return unresolved(state, pending, upstream, refusal).await,
    };
    let upstream_session = match pending.purpose {
        Purpose::Authorize => match begin_session(state, identity).await {
            Ok(session) => Some(session),
            Err(response) => return *response,
        },
        Purpose::Manage => None,
    };
    let mut login = Login {
        subject,
        fhir_user,
        display_name: identity.display_name.clone(),
        offered_scope: String::new(),
        auth_time,
        upstream_session,
        roles: mapped(&held, &state.settings().roles),
        person_claims: crate::store::PersonClaims::from_identity(identity),
        acr,
    };
    let person = Person {
        issuer: &state.settings().issuer,
        subject: &login.subject,
        name: login.display_name.as_deref(),
        client_id: pending.client_id.as_deref(),
    };
    if let Err(response) = record_login(state, upstream, Ok(person)).await {
        return *response;
    }
    if pending.purpose == Purpose::Manage {
        if let Err(error) = state.store().logged_in(&pending.id, &login).await {
            return pages::server_error(state, &error);
        }
        return see_other(&state.settings().endpoint(MANAGE_ROUTE));
    }
    let client = match registered(state, pending).await {
        Ok(client) => client,
        Err(response) => return *response,
    };
    let own = crate::picker::own_patient(state, &pending.audience, login.fhir_user.as_deref())
        .map(str::to_owned);
    let fhir_user = match (&login.fhir_user, &own) {
        (None, _) => FhirUser::Absent,
        (Some(_), None) => FhirUser::Present,
        (Some(_), Some(_)) => FhirUser::ThePatient,
    };
    let offered = offer(
        &pending.scope,
        &client,
        &held,
        &state.settings().roles,
        fhir_user,
        pending.launch_context.as_ref(),
        crate::picker::reach(state, &pending.audience),
    );
    if offered.is_empty() {
        forget(state, pending).await;
        return no_scope(state, &client, &pending.scope, back);
    }
    login.offered_scope = offered.join(" ");
    if let Err(error) = state.store().logged_in(&pending.id, &login).await {
        return pages::server_error(state, &error);
    }
    let offered: Vec<&str> = offered.iter().map(String::as_str).collect();
    // NOTE: SMART App Launch 2.2.0, Obtain authorization code, the patient is
    // chosen within the authorization flow, before the consent.
    if pending.launch_context.is_none() && offered.contains(&"launch/patient") {
        // NOTE: docs/architecture.md §13.6 item 4 (owner, 2026-11-19, #673): a patient's
        // own record is the context, read again as them, with no picker.
        if let Some(id) = &own {
            return match state.store().pending(&pending.id).await {
                Ok(Some(signed_in)) => crate::picker::own_record(state, &signed_in, from, id).await,
                Ok(None) => pages::fault(state, Fault::Lapsed),
                Err(error) => pages::server_error(state, &error),
            };
        }
        return see_other(&state.settings().endpoint(crate::picker::PICKER_ROUTE));
    }
    let asked = Asked {
        pending,
        subject: &login.subject,
        fhir_user: login.fhir_user.as_deref(),
        client: &client,
        offered: &offered,
    };
    onward(state, &asked, back, from).await
}

/// Refuses the launch of `pending`, whose wallet login's patient the index
/// did not resolve, and records the login as failed: a patient is never
/// taken from the wallet's values alone (`docs/architecture.md` §13.32).
async fn unresolved(
    state: &AppState,
    pending: &Pending,
    upstream: &crate::upstream::Upstream,
    refusal: IndexRefusal,
) -> Response {
    forget(state, pending).await;
    let description = match refusal {
        IndexRefusal::NoIdentifier => "the PID names no identifier the patient index knows",
        IndexRefusal::NoMatch => "the patient index knows no patient by the PID's identifier",
        IndexRefusal::Several => "the patient index knows several patients by the PID's identifier",
        IndexRefusal::Failed => "the patient index could not be asked",
    };
    if let Err(response) = record_login(state, upstream, Err(description)).await {
        return *response;
    }
    // NOTE: RFC 6749 §4.1.2.1, a person the server cannot place is access_denied;
    // an index it cannot ask is the server's error.
    let error = if refusal == IndexRefusal::Failed {
        "server_error"
    } else {
        "access_denied"
    };
    deny_unsigned(state, pending, Denial { error, description }).await
}

/// Returns the `fhirUser` the lookups configured for the request's server
/// find for the person `subject` with the upstream `claims`, and writes the
/// outcome as an audit line, never a value (`docs/architecture.md` §13.6
/// item 9).
async fn looked_up(
    state: &AppState,
    pending: &Pending,
    subject: &str,
    claims: &serde_json::Map<String, serde_json::Value>,
    from: IpAddr,
) -> Option<String> {
    let asking = Pending {
        subject: Some(subject.to_owned()),
        ..pending.clone()
    };
    let resolved =
        crate::picker::fhir_user::resolve(state, &asking, from, &pending.audience, claims).await?;
    tracing::info!(
        target: "ferrosmart::audit",
        event = "fhir_user.lookup",
        client_id = ?pending.client_id,
        outcome = resolved.as_str(),
        "the person's fhirUser was looked up"
    );
    match resolved {
        crate::picker::fhir_user::Resolved::Found(fhir_user) => Some(fhir_user),
        _ => None,
    }
}

/// Answers a request of which no scope can be granted to the person: a page
/// naming the roles that would grant one, whose way on sends the browser
/// back with `access_denied` (RFC 6749 §4.1.2.1; the page first is our own
/// design, `docs/architecture.md` §13.6 item 5).
fn no_scope(state: &AppState, client: &Client, requested: &str, back: &Back) -> Response {
    let roles = granting_roles(client, requested, &state.settings().roles);
    tracing::info!(
        target: "ferrosmart::audit",
        event = "authorization.refused",
        client_id = %client.client_id,
        reason = "no requested scope can be granted to this person",
        "no scope could be granted"
    );
    let Some(url) = back.denial_url(Denial {
        error: "access_denied",
        description: "no requested scope can be granted to this person",
    }) else {
        return pages::fault(state, Fault::UnknownRedirect);
    };
    pages::no_scope(state, client, &roles, url.as_str())
}

/// Returns the configured roles, in name order, that grant at least one
/// scope of `requested` the client's ceiling admits.
fn granting_roles<'a>(
    client: &Client,
    requested: &str,
    roles: &'a std::collections::BTreeMap<String, Vec<String>>,
) -> Vec<&'a str> {
    let wanted: Vec<&str> = requested
        .split(' ')
        .filter(|scope| !scope.is_empty() && crate::scopes::admits(&client.scopes, scope))
        .collect();
    roles
        .iter()
        .filter(|(_, scopes)| {
            wanted
                .iter()
                .any(|scope| crate::scopes::admits(scopes, scope))
        })
        .map(|(name, _)| name.as_str())
        .collect()
}

/// What a person, logged in with the launch context complete, was asked
/// to authorize.
pub(crate) struct Asked<'a> {
    /// The pending authorization: its id, the scope the app requested,
    /// its redirect URI and whether it asked for the consent page with
    /// `prompt=consent` (OpenID Connect Core 1.0 §3.1.2.1).
    pub(crate) pending: &'a Pending,
    /// The person's pairwise subject.
    pub(crate) subject: &'a str,
    /// The person's `fhirUser`, when the provider carries one.
    pub(crate) fhir_user: Option<&'a str>,
    /// The client.
    pub(crate) client: &'a Client,
    /// The scopes policy offers (`docs/architecture.md` §13.6 item 5).
    pub(crate) offered: &'a [&'a str],
}

/// Goes on once the person logged in and the context is complete: straight
/// back to the app with a code when [`without_page`] answers for the person,
/// or on the consent page a remembered consent covers `offered`, and the
/// client's identity is assured; to the consent page otherwise.
pub(crate) async fn onward(
    state: &AppState,
    asked: &Asked<'_>,
    back: &Back,
    from: IpAddr,
) -> Response {
    // NOTE: OpenID Connect Core 1.0 §3.1.2.1: prompt=consent asks the person for
    // consent, so neither the registration nor a remembered consent answers.
    if asked.pending.asking.prompt.consent {
        return see_other(&state.settings().endpoint(CONSENT_ROUTE));
    }
    // NOTE: RFC 8252 §8.6, no request is processed automatically unless the client's
    // identity is assured: a confidential client, or a public one's claimed https redirect;
    // RFC 7591 §5, an app that registered itself asserts its own, so it never is.
    if asked.client.registered_itself() || !asked.client.assured_by(&asked.pending.redirect_uri) {
        return see_other(&state.settings().endpoint(CONSENT_ROUTE));
    }
    let skipped = without_page(
        asked.client,
        super::consent::Person::of(asked.fhir_user),
        asked.offered,
    );
    let basis = if let Some(basis) = skipped {
        basis
    } else {
        // NOTE: docs/architecture.md §13.6 item 6, a consent the person chose to
        // remember answers again, for this client at this resource server, while it covers every scope offered.
        let remembered = match state
            .store()
            .remembered(
                asked.subject,
                &asked.client.client_id,
                &asked.pending.audience,
            )
            .await
        {
            Ok(remembered) => remembered,
            Err(error) => return pages::server_error(state, &error),
        };
        let covered = remembered.is_some_and(|scope| {
            asked
                .offered
                .iter()
                .all(|wanted| scope.split(' ').any(|given| given == *wanted))
        });
        if !covered {
            return see_other(&state.settings().endpoint(CONSENT_ROUTE));
        }
        super::consent::Basis::Remembered
    };
    let pending = match found(state, state.store().finish(&asked.pending.id).await) {
        Ok(pending) => pending,
        Err(response) => return *response,
    };
    let mut response = approve(state, &pending, asked.offered, basis, back, from).await;
    set_cookie(state, &mut response, COOKIE, "", 0);
    response
}

/// Returns the roles of `held` that a `[[ferrosmart.role]]` of `roles`
/// names, sorted and once each: the roles FerroSMART maps, which the access
/// token carries (RFC 9068 §2.2.3.1; `docs/architecture.md` §13.6 item 5).
/// A role no table names is the provider's alone and stays there.
fn mapped(held: &[String], roles: &std::collections::BTreeMap<String, Vec<String>>) -> Vec<String> {
    held.iter()
        .filter(|role| roles.contains_key(role.as_str()))
        .cloned()
        .collect::<std::collections::BTreeSet<String>>()
        .into_iter()
        .collect()
}

/// Records the upstream login `identity` describes as a session, with the
/// provider's `sid` when it names one, and returns its id: the session an
/// `online_access` grant lives in (`docs/architecture.md` §13.6 item 7),
/// which the provider's back-channel logout ends.
async fn begin_session(state: &AppState, identity: &Identity) -> Result<String, Box<Response>> {
    let session = random().map_err(|error| Box::new(pages::server_error(state, &error)))?;
    state
        .store()
        .begin_session(
            &session,
            &identity.issuer,
            &identity.subject,
            identity.session.as_deref(),
        )
        .await
        .map_err(|error| Box::new(pages::server_error(state, &error)))?;
    Ok(session)
}

/// Reads the provider's answer from the callback's query (RFC 6749 §4.1.2,
/// §4.1.2.1).
fn read_callback(query: &str) -> Result<Callback, crate::form::Repeated> {
    let params = Params::parse(query.as_bytes(), &[])?;
    let mut answer = Callback::default();
    answer.code = params.get("code").map(Secret::new);
    answer.state = params.get("state").map(str::to_owned);
    answer.error = params.get("error").map(str::to_owned);
    answer.error_description = params.get("error_description").map(str::to_owned);
    answer.error_uri = params.get("error_uri").map(str::to_owned);
    Ok(answer)
}

/// Records the login `answer` at the upstream provider, or returns the page
/// of a login that could not be recorded: a login whose record is not
/// stored does not go on (no specification governs this: our own design).
pub(super) async fn record_login(
    state: &AppState,
    upstream: &crate::upstream::Upstream,
    answer: Result<Person<'_>, &str>,
) -> Result<(), Box<Response>> {
    let provider = Url::parse(upstream.issuer())
        .map_err(|error| Box::new(pages::server_error(state, &error)))?;
    let (subject, client_id) = answer.ok().map_or((None, None), |person| {
        (Some(person.subject), person.client_id)
    });
    let recorded = state
        .audit()
        .row(&login(&provider, answer), "login", subject, client_id)
        .map_err(|error| Box::new(pages::server_error(state, &error)))?;
    state
        .audit()
        .record(state.store(), &recorded)
        .await
        .map_err(|error| Box::new(pages::server_error(state, &error)))
}
