// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The signed launch JWT.
//!
//! It is the launch an EHR states in a JWS (RFC 7515) signed with a key of its registered JWK Set and hands the app as the
//! `launch` value, so the EHR and FerroSMART share no database
//! (`docs/architecture.md` §13.6 item 3). SMART defines no such token: its
//! claims are our own design, checked the way SMART App Launch 2.2.0,
//! Client Authentication: Asymmetric, Signature Verification, checks a
//! client assertion.

use jsonwebtoken::{Algorithm, Validation};
use serde_json::{Map, Value};

use crate::clients::{Client, ClientKeys, ClientKind};
use crate::launch::Unresolved::{self, Refused};
use crate::launch::context::Context;
use crate::launch::{LAUNCH_SCOPE, MAX_LAUNCH_SECONDS};
use crate::server::AppState;
use crate::token::LEEWAY_SECONDS;
use crate::token::assertion::key_of;

/// The `typ` of a launch JWT (RFC 7515 §4.1.9; RFC 8725 §3.11, explicit
/// typing). Our own media type.
pub const LAUNCH_JWT_TYPE: &str = "launch+jwt";

/// The claims a launch JWT carries beside its context: the RFC 7519 §4.1
/// claims, `client_id` (RFC 8693 §4.3) naming the app, and `resource` (RFC
/// 8707 §2) naming the resource server.
const REGISTERED: [&str; 8] = [
    "iss",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "client_id",
    "resource",
];

/// A launch JWT whose signature and claims hold.
#[derive(Debug, Clone)]
pub struct SignedLaunch {
    /// The EHR client that signed it, its `iss`.
    pub ehr_client_id: String,
    /// The app it launches.
    pub client_id: String,
    /// The resource server it is for.
    pub audience: String,
    /// Its `jti`.
    pub jti: String,
    /// Its `exp`, in seconds since the epoch.
    pub expires_at: i64,
    /// The context.
    pub context: Context,
}

/// Reads the launch JWT `jwt`, without recording its `jti`.
///
/// It is read as `RS384` or `ES384`, `typ` [`LAUNCH_JWT_TYPE`],
/// signed by a key its `iss` registered, an EHR client that may launch, with
/// `aud` FerroSMART's issuer as its sole value, an `exp` at most
/// [`MAX_LAUNCH_SECONDS`] ahead, a `jti`, the app and the resource server,
/// and a context that holds.
///
/// # Errors
/// Returns [`Unresolved::Refused`] naming the rule broken, and
/// [`Unresolved::Store`] when the registry cannot be read.
pub async fn read(state: &AppState, jwt: &str) -> Result<SignedLaunch, Unresolved> {
    let header =
        jsonwebtoken::decode_header(jwt).map_err(|_unread| Refused("the launch is no JWT"))?;
    let algorithm = header.alg;
    // NOTE: SMART App Launch 2.2.0, Client Authentication: Asymmetric, the two
    // algorithms FerroSMART validates for a client's key.
    if !matches!(algorithm, Algorithm::RS384 | Algorithm::ES384) {
        return Err(Refused("the launch JWT's algorithm is not admitted"));
    }
    if header.typ.as_deref() != Some(LAUNCH_JWT_TYPE) {
        return Err(Refused("the launch JWT's typ is not launch+jwt"));
    }
    let kid = header
        .kid
        .as_deref()
        .ok_or(Refused("the launch JWT names no kid"))?;
    // NOTE: RFC 7519 §4.1.1, the issuer names the EHR; the claims are read
    // unverified only to find whose key verifies them.
    let unverified: Value = jsonwebtoken::dangerous::insecure_decode_claims(jwt)
        .map_err(|_unread| Refused("the launch JWT's claims are no JSON"))?;
    let issuer = unverified
        .get("iss")
        .and_then(Value::as_str)
        .ok_or(Refused("the launch JWT names no iss"))?;
    let ehr = super::launching_ehr(state, issuer)
        .await?
        .ok_or(Refused("the launch JWT's iss is no EHR that may launch"))?;
    if let Some(jku) = header.jku.as_deref()
        && !matches!(&ehr.keys, Some(ClientKeys::Uri(url)) if url.as_str() == jku)
    {
        return Err(Refused(
            "the launch JWT's jku is not the registered JWK Set URL",
        ));
    }
    let key = key_of(state, &ehr, kid, algorithm)
        .await
        .map_err(|refusal| Refused(refusal.description))?;
    let mut validation = Validation::new(algorithm);
    validation.leeway = LEEWAY_SECONDS;
    validation.validate_aud = false;
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    let claims: Map<String, Value> = jsonwebtoken::decode(jwt, &key, &validation)
        .map_err(|_refused| Refused("the launch JWT does not verify"))?
        .claims;
    claims_of(state, &ehr, claims)
}

/// Returns the launch `claims` state, signed by `ehr`.
fn claims_of(
    state: &AppState,
    ehr: &Client,
    mut claims: Map<String, Value>,
) -> Result<SignedLaunch, Unresolved> {
    let settings = state.settings();
    // NOTE: RFC 7519 §4.1.3, the token is for FerroSMART; one string, as RFC
    // 10070 §4 has for a client's JWT, so it is for no other server.
    if claims.get("aud").and_then(Value::as_str) != Some(settings.issuer.as_str()) {
        return Err(Refused("the launch JWT's aud is not this issuer"));
    }
    let now = jiff::Timestamp::now().as_second();
    let latest = now.saturating_add_unsigned(MAX_LAUNCH_SECONDS + LEEWAY_SECONDS);
    let expires_at = claims
        .get("exp")
        .and_then(Value::as_i64)
        .filter(|exp| *exp <= latest)
        .ok_or(Refused("the launch JWT lives longer than five minutes"))?;
    let text = |claims: &Map<String, Value>, name: &str| {
        claims
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    let jti = text(&claims, "jti").ok_or(Refused("the launch JWT names no jti"))?;
    let client_id =
        text(&claims, "client_id").ok_or(Refused("the launch JWT names no client_id"))?;
    let audience = text(&claims, "resource")
        .filter(|base| settings.resources.contains(base))
        .ok_or(Refused(
            "the launch JWT's resource is not served by this issuer",
        ))?;
    for name in REGISTERED {
        claims.remove(name);
    }
    let context: Context = serde_json::from_value(Value::Object(claims)).map_err(|_unread| {
        Refused("the launch JWT carries a claim that is no context parameter")
    })?;
    context
        .check(settings.openehr_resources.contains(&audience))
        .map_err(Refused)?;
    Ok(SignedLaunch {
        ehr_client_id: ehr.client_id.clone(),
        client_id,
        audience,
        jti,
        expires_at,
        context,
    })
}

/// Returns whether `client` may register or sign a launch: a confidential
/// asymmetric client whose ceiling lists [`LAUNCH_SCOPE`].
#[must_use]
pub fn may_launch(client: &Client) -> bool {
    client.kind() == ClientKind::ConfidentialAsymmetric
        && client.scopes.iter().any(|scope| scope == LAUNCH_SCOPE)
}
