// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Which upstream provider a person logs in at, and the start of that
//! login.
//!
//! A client names the providers its people may log in at (every provider
//! when it names none). With one, the browser goes straight to it; with
//! several, `GET {issuer}/login` draws the chooser and its post sends the
//! browser on. The pending request records the provider, so the callback
//! completes the login with that provider's settings alone. Nothing in
//! SMART App Launch 2.2.0 limits a server to one provider; the chooser is
//! our own design (#678).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::response::Response;
use http::HeaderMap;
use url::Url;

use crate::form::Params;
use crate::pages::{self, Fault};
use crate::server::AppState;
use crate::store::{Asking, Pending, Purpose};
use crate::upstream::LoginProvider;

use super::{COOKIE, REQUEST_SECONDS, Stop, constant_eq, cookie, fail, random, see_other};

/// The chooser's route under the issuer.
pub const LOGIN_ROUTE: &str = "/login";

/// The cookie that binds a SAML login to the browser that began it.
///
/// It is sent with the identity provider's cross-site post to the
/// assertion consumer service, which `SameSite=Lax` would withhold (RFC
/// 6265bis §5.6.7.1). No specification governs the cookie: our own design.
pub const SAML_COOKIE: &str = "ferrosmart_saml_login";

/// Where the browser goes to log in.
#[derive(Debug, Clone)]
pub(crate) enum Departure {
    /// Redirected: to an OpenID Provider, to the chooser, or to a SAML
    /// provider by HTTP-Redirect when `saml` says so.
    Redirect {
        /// The location.
        to: Url,
        /// Whether a SAML login begins there.
        saml: bool,
    },
    /// Posting a SAML `AuthnRequest` to the provider (HTTP-POST).
    Post {
        /// The single sign-on location.
        action: Url,
        /// The `SAMLRequest` value.
        saml_request: String,
        /// The `RelayState` value.
        relay_state: String,
    },
}

impl Departure {
    /// Returns the response that sends the browser of the request
    /// `pending_id` on, binding a SAML login to it with [`SAML_COOKIE`].
    pub(crate) fn respond(&self, state: &AppState, pending_id: &str) -> Response {
        let (mut response, saml) = match self {
            Self::Redirect { to, saml } => (see_other(to.as_str()), *saml),
            Self::Post {
                action,
                saml_request,
                relay_state,
            } => (
                pages::saml::post(
                    state,
                    action,
                    &[("SAMLRequest", saml_request), ("RelayState", relay_state)],
                ),
                true,
            ),
        };
        if saml {
            saml_cookie(state, &mut response, pending_id, REQUEST_SECONDS);
        }
        response
    }
}

/// Sets [`SAML_COOKIE`] to `value` for `max_age` seconds on the assertion
/// consumer service's path: `HttpOnly`, `Secure` and `SameSite=None`.
pub(crate) fn saml_cookie(state: &AppState, response: &mut Response, value: &str, max_age: i64) {
    let path = state
        .settings()
        .endpoint_url(crate::upstream::saml::ACS_ROUTE);
    let cookie = format!(
        "{SAML_COOKIE}={value}; Path={}; Max-Age={max_age}; HttpOnly; Secure; SameSite=None",
        path.path()
    );
    if let Ok(value) = http::HeaderValue::from_str(&cookie) {
        response
            .headers_mut()
            .append(http::header::SET_COOKIE, value);
    }
}

/// Where a new request's browser goes first, and what the request records
/// of it.
#[derive(Debug)]
pub(super) struct Start {
    /// The provider's login, or the chooser.
    pub(super) departure: Departure,
    /// The provider chosen, when only one was allowed.
    pub(super) provider: Option<String>,
    /// The upstream `state`, `nonce` and PKCE verifier, or a SAML login's
    /// `RelayState`, request `ID` and an unused random value; drawn at
    /// random until a provider is chosen, so no callback can match them.
    pub(super) sign_in: [String; 3],
}

/// Returns how a new request whose client allows `allowed` starts: at the
/// one provider, or at the chooser.
pub(super) fn start(
    state: &AppState,
    allowed: &[&LoginProvider],
    asking: &Asking,
) -> Result<Start, Stop> {
    match allowed {
        [] => Err(Stop::Deny(super::Denial::request("no login is configured"))),
        [only] => {
            let (departure, sign_in) = sign_in_at(only, asking)?;
            Ok(Start {
                departure,
                provider: Some(only.name().to_owned()),
                sign_in,
            })
        }
        _ => Ok(Start {
            departure: Departure::Redirect {
                to: state.settings().endpoint_url(LOGIN_ROUTE),
                saml: false,
            },
            provider: None,
            sign_in: [
                random().map_err(fail)?,
                random().map_err(fail)?,
                random().map_err(fail)?,
            ],
        }),
    }
}

/// Returns the login request at `provider`, carrying what `asking` passes
/// on, with its `state`, `nonce` and PKCE verifier, or for a SAML provider
/// its `RelayState`, its request `ID` and an unused random value, or for
/// the wallet its `state`, `nonce` and ephemeral key.
pub(super) fn sign_in_at(
    provider: &LoginProvider,
    asking: &Asking,
) -> Result<(Departure, [String; 3]), Stop> {
    if let Some(login) = provider.wallet() {
        // NOTE: OpenID4VP 1.0 §5.2, a fresh nonce and state per request; HAIP 1.0 §5, a
        // fresh encryption key, which the request keeps in the verifier's slot.
        let begun = login.begin().map_err(fail)?;
        return Ok((
            Departure::Redirect {
                to: begun.invocation,
                saml: false,
            },
            [begun.state, begun.nonce, begun.key],
        ));
    }
    if let Some(login) = provider.saml() {
        // NOTE: saml-bindings-2.0-os §3.4.3, the RelayState is at most 80 bytes; 256
        // random bits in base64url are 43, and they find the pending request again.
        let relay_state = random().map_err(fail)?;
        // NOTE: OpenID Connect Core 1.0 §3.1.2.1, prompt=login asks for a fresh
        // authentication, which a SAML request asks by ForceAuthn (saml-core §3.4.1).
        let begun = login
            .begin(relay_state, asking.prompt.login)
            .map_err(fail)?;
        let departure = match begun.leg {
            crate::upstream::saml::Leg::Redirect(to) => Departure::Redirect { to, saml: true },
            crate::upstream::saml::Leg::Post {
                action,
                saml_request,
            } => Departure::Post {
                action,
                saml_request,
                relay_state: begun.relay_state.clone(),
            },
        };
        return Ok((
            departure,
            [begun.relay_state, begun.request_id, random().map_err(fail)?],
        ));
    }
    let party = provider
        .oidc()
        .ok_or(Stop::Deny(super::Denial::request("no login is configured")))?;
    let upstream = party.authorization_request().map_err(fail)?;
    let location =
        super::oidc::upstream(upstream.url.clone(), asking, &provider.upstream().assurance);
    Ok((
        Departure::Redirect {
            to: location,
            saml: false,
        },
        [
            upstream.pending.state().to_owned(),
            upstream.pending.nonce().to_owned(),
            upstream.pending.verifier().expose().to_owned(),
        ],
    ))
}

/// Returns the providers the person of `pending` may choose from: those its
/// client allows, or every provider for the management page.
async fn allowed<'a>(
    state: &'a AppState,
    pending: &Pending,
) -> Result<Vec<&'a LoginProvider>, Box<Response>> {
    if pending.purpose == Purpose::Manage {
        return Ok(state.providers().iter().collect());
    }
    let client = super::registered(state, pending).await?;
    Ok(state.providers().allowed(&client.upstreams))
}

/// Returns the browser's request that waits for a provider, or the page
/// that says why there is none.
async fn choosing(state: &AppState, headers: &HeaderMap) -> Result<Pending, Box<Response>> {
    let Some(id) = cookie(headers, COOKIE) else {
        return Err(Box::new(pages::fault(state, Fault::Lapsed)));
    };
    let pending = super::found(state, state.store().pending(&id).await)?;
    if pending.upstream_provider.is_some() {
        return Err(Box::new(pages::fault(state, Fault::Lapsed)));
    }
    Ok(pending)
}

/// `GET {issuer}/login`: the chooser.
pub async fn choose_get(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let pending = match choosing(&state, &headers).await {
        Ok(pending) => pending,
        Err(page) => return *page,
    };
    match allowed(&state, &pending).await {
        Ok(providers) => pages::chooser(&state, &headers, &pending, &providers),
        Err(page) => *page,
    }
}

/// `POST {issuer}/login`: the person's choice, which sends the browser on to
/// that provider.
pub async fn choose_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (pending, provider) = match chosen(&state, &headers, &body).await {
        Ok(chosen) => chosen,
        Err(page) => return *page,
    };
    let Ok((departure, [upstream_state, nonce, verifier])) = sign_in_at(provider, &pending.asking)
    else {
        return pages::fault(&state, Fault::Server);
    };
    match state
        .store()
        .choose_upstream(
            &pending.id,
            provider.name(),
            [&upstream_state, &nonce, &verifier],
        )
        .await
    {
        Ok(true) => departure.respond(&state, &pending.id),
        Ok(false) => pages::fault(&state, Fault::Lapsed),
        Err(error) => pages::server_error(&state, &error),
    }
}

/// Reads the chooser's form against the request the cookie names: the
/// request and the provider chosen among those it allows, or the page that
/// refuses the form.
async fn chosen<'a>(
    state: &'a AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(Pending, &'a LoginProvider), Box<Response>> {
    let refuse = |fault| Box::new(pages::fault(state, fault));
    let form = Params::parse(body, &[]).map_err(|_repeated| refuse(Fault::BadRequest))?;
    let pending = choosing(state, headers).await?;
    let sent = form.get("form_token").unwrap_or_default();
    if !constant_eq(sent.as_bytes(), pending.form_token.as_bytes()) {
        return Err(refuse(Fault::BadRequest));
    }
    let provider = allowed(state, &pending)
        .await?
        .into_iter()
        .find(|provider| form.get("provider") == Some(provider.name()))
        .ok_or_else(|| refuse(Fault::BadRequest))?;
    Ok((pending, provider))
}
