// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The client assertion of `private_key_jwt` (RFC 7523 §2.2, §3), checked as
//! SMART App Launch 2.2.0, Client Authentication: Asymmetric, Signature
//! Verification, has it.

use ferrohealth_smart::jws::algorithm::Algorithm;
use ferrohealth_smart::jws::compact::Unverified;
use ferrohealth_smart::jws::jwk::Jwk;
use serde_json::{Map, Value};

use crate::clients::{Client, ClientKeys, ClientKind};
use crate::discovery::TOKEN_ROUTE;
use crate::form::Params;
use crate::server::AppState;

use super::{
    ASSERTION_TYPES, JWT_BEARER, LEEWAY_SECONDS, MAX_ASSERTION_SECONDS, Refusal, server_error,
};

/// The algorithms a client assertion and a signed launch may be signed
/// with.
///
/// RS384 and ES384, of which "The FHIR authorization server SHALL be
/// capable of validating signatures with at least one" (SMART App Launch
/// 2.2.0, Client Authentication: Asymmetric, Registering a client), PS256,
/// ES256 and `EdDSA`, the ones FAPI 2.0 Security Profile §5.4.1 admits (RFC
/// 7518 §3.4, §3.5; RFC 8037 §3.1), and the three ML-DSA parameter sets
/// (RFC 9964 §5).
pub(crate) const ALGORITHMS: [Algorithm; 8] = [
    Algorithm::Rs384,
    Algorithm::Es384,
    Algorithm::Ps256,
    Algorithm::Es256,
    Algorithm::EdDsa,
    Algorithm::MlDsa44,
    Algorithm::MlDsa65,
    Algorithm::MlDsa87,
];

/// Authenticates the client of `form` by its JWT assertion.
pub(crate) async fn authenticate(state: &AppState, form: &Params) -> Result<Client, Refusal> {
    if form.get("client_assertion_type") != Some(JWT_BEARER) {
        return Err(Refusal::client(
            "the client_assertion_type is not jwt-bearer",
        ));
    }
    let assertion = form
        .get("client_assertion")
        .ok_or(Refusal::client("the request carries no client_assertion"))?;
    let jws = ferrohealth_smart::jws::compact::decode(assertion).map_err(|error| match error {
        ferrohealth_smart::jws::JwsError::Algorithm => {
            Refusal::client("the client_assertion's algorithm is not admitted")
        }
        _ => Refusal::client("the client_assertion is no JWT"),
    })?;
    let header = jws.header();
    let algorithm = header.alg;
    if !ALGORITHMS.contains(&algorithm) {
        return Err(Refusal::client(
            "the client_assertion's algorithm is not admitted",
        ));
    }
    // NOTE: RFC 10070 §3.2, "it is NOT RECOMMENDED for servers to reject JWTs that do
    // not have explicit types"; a typ that is present names a client assertion.
    if header
        .typ
        .as_deref()
        .is_some_and(|typ| !ASSERTION_TYPES.contains(&typ))
    {
        return Err(Refusal::client(
            "the client_assertion's typ is not admitted",
        ));
    }
    let kid = header
        .kid
        .as_deref()
        .ok_or(Refusal::client("the client_assertion names no kid"))?;
    // NOTE: RFC 7523 §3 item 1, the issuer names the client; the claims are read
    // unverified only to find whose key verifies them.
    let unverified = unverified_claims(assertion)
        .ok_or(Refusal::client("the client_assertion's claims are no JSON"))?;
    let issuer = unverified
        .get("iss")
        .and_then(Value::as_str)
        .ok_or(Refusal::client("the client_assertion names no iss"))?;
    let client = state
        .store()
        .client(issuer)
        .await
        .map_err(|error| server_error("the client registry cannot be read", &error))?
        .ok_or(Refusal::client("the client is not registered"))?;
    // NOTE: SMART App Launch 2.2.0, Signature Verification, the client_id provided
    // is known and matches the JWT's iss.
    if form
        .get("client_id")
        .is_some_and(|client_id| client_id != issuer)
    {
        return Err(Refusal::client(
            "the client_id is not the client_assertion's iss",
        ));
    }
    if client.kind() != ClientKind::ConfidentialAsymmetric {
        return Err(Refusal::client("the client authenticates with no key"));
    }
    if let Some(jku) = jku(&jws) {
        let listed = matches!(&client.keys, Some(ClientKeys::Uri(url)) if url.as_str() == jku);
        if !listed {
            return Err(Refusal::client("the jku is not the registered JWK Set URL"));
        }
    }
    let key = key_of(state, &client, kid, algorithm).await?;
    let claims = verified(state, &jws, &key)?;
    if claims.get("sub").and_then(Value::as_str) != Some(client.client_id.as_str()) {
        return Err(Refusal::client("the client_assertion's sub is not its iss"));
    }
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|jti| !jti.is_empty())
        .ok_or(Refusal::client("the client_assertion names no jti"))?;
    let expires = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(Refusal::client("the client_assertion names no exp"))?;
    let fresh = state
        .store()
        .first_use(&client.client_id, jti, expires)
        .await
        .map_err(|error| server_error("the assertion record cannot be written", &error))?;
    if !fresh {
        return Err(Refusal::client("the client_assertion was used before"));
    }
    Ok(client)
}

/// Returns the payload of the compact JWS `jwt` as a JSON object, read
/// without checking its signature.
pub(crate) fn unverified_claims(jwt: &str) -> Option<Map<String, Value>> {
    let payload = jwt.split('.').nth(1)?;
    let bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Returns the `jku` the header of `jws` names, when it names one.
pub(crate) fn jku<'a>(jws: &'a Unverified<'_>) -> Option<&'a str> {
    jws.header_members().get("jku").and_then(Value::as_str)
}

/// Returns the one key of `client`'s set whose `kid` is `kid` and which may
/// verify `algorithm`, its type, curve or parameter set and its `alg`,
/// `use` and `key_ops` admitting it (SMART App Launch 2.2.0, Client
/// Authentication: Asymmetric, Signature Verification, step 3; RFC 7517
/// §4.4; RFC 9964 §5), reading the set again once when the cached set holds
/// none.
pub(crate) async fn key_of(
    state: &AppState,
    client: &Client,
    kid: &str,
    algorithm: Algorithm,
) -> Result<Jwk, Refusal> {
    for refresh in [false, true] {
        let set = state
            .client_keys()
            .get(client, refresh)
            .await
            .map_err(|_unread| Refusal::client("the client's JWK Set cannot be read"))?;
        // NOTE: RFC 7517 §5, a member that is no supported key is ignored.
        let candidates: Vec<Jwk> = set
            .get("keys")
            .and_then(Value::as_array)
            .map(|keys| {
                keys.iter()
                    .filter_map(|key| Jwk::try_from(key).ok())
                    .filter(|key| key.kid() == Some(kid) && key.verifies(algorithm))
                    .collect()
            })
            .unwrap_or_default();
        match candidates.as_slice() {
            [key] => return Ok(key.clone()),
            [] => {}
            _ => return Err(Refusal::client("more than one key matches the kid")),
        }
    }
    Err(Refusal::client("no key of the client matches the kid"))
}

/// Returns the claims of `jws` once its signature, `exp`, `iss` and `aud`
/// hold (RFC 7523 §3; `docs/architecture.md` §13.6 item 1).
fn verified(state: &AppState, jws: &Unverified<'_>, key: &Jwk) -> Result<Value, Refusal> {
    let claims = jws
        .verify_claims(key)
        .map_err(|_refused| Refusal::client("the client_assertion does not verify"))?;
    // NOTE: RFC 7523 §3 items 1 to 4 and 7: `iss`, `sub`, `aud`, `exp` and `jti`;
    // `exp` is checked below on its own, so an expired assertion is told apart.
    if ["exp", "iss", "sub", "aud", "jti"]
        .iter()
        .any(|name| !claims.contains_key(*name))
    {
        return Err(Refusal::client("the client_assertion does not verify"));
    }
    let claims = Value::Object(claims);
    let now = jiff::Timestamp::now().as_second();
    if claims
        .get("exp")
        .and_then(Value::as_i64)
        .is_none_or(|exp| exp.saturating_add_unsigned(LEEWAY_SECONDS) < now)
    {
        return Err(Refusal::client("the client_assertion has expired"));
    }
    // NOTE: RFC 10070 §4, a sole audience value; SMART App Launch 2.2.0 names the
    // token URL, the issuer identifier is admitted beside it (13.6 item 1), and RFC
    // 9126 §2 has the PAR endpoint URL admitted too.
    let settings = state.settings();
    let token_url = settings.endpoint(TOKEN_ROUTE);
    let par_url = settings.endpoint(crate::authorize::par::PAR_ROUTE);
    let admitted = claims
        .get("aud")
        .and_then(Value::as_str)
        .is_some_and(|aud| aud == token_url || aud == par_url || aud == settings.issuer);
    if !admitted {
        return Err(Refusal::client(
            "the client_assertion's aud is not this server",
        ));
    }
    let latest = now.saturating_add_unsigned(MAX_ASSERTION_SECONDS + LEEWAY_SECONDS);
    if claims
        .get("exp")
        .and_then(Value::as_i64)
        .is_none_or(|exp| exp > latest)
    {
        return Err(Refusal::client(
            "the client_assertion lives longer than five minutes",
        ));
    }
    Ok(claims)
}
