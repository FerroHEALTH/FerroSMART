// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The client assertion of `private_key_jwt` (RFC 7523 §2.2, §3), checked as
//! SMART App Launch 2.2.0, Client Authentication: Asymmetric, Signature
//! Verification, has it.

use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::Jwk};
use serde_json::Value;

use crate::clients::{Client, ClientKeys, ClientKind};
use crate::discovery::TOKEN_ROUTE;
use crate::form::Params;
use crate::server::AppState;

use super::{
    ASSERTION_TYPES, JWT_BEARER, LEEWAY_SECONDS, MAX_ASSERTION_SECONDS, Refusal, server_error,
};

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
    let header = jsonwebtoken::decode_header(assertion)
        .map_err(|_unread| Refusal::client("the client_assertion is no JWT"))?;
    let algorithm = header.alg;
    // NOTE: SMART App Launch 2.2.0, Client Authentication: Asymmetric, the server
    // validates RS384 or ES384, the two the metadata advertises.
    if !matches!(algorithm, Algorithm::RS384 | Algorithm::ES384) {
        return Err(Refusal::client(
            "the client_assertion's algorithm is not admitted",
        ));
    }
    if !header
        .typ
        .as_deref()
        .is_some_and(|typ| ASSERTION_TYPES.contains(&typ))
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
    let unverified: Value = jsonwebtoken::dangerous::insecure_decode_claims(assertion)
        .map_err(|_unread| Refusal::client("the client_assertion's claims are no JSON"))?;
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
    if let Some(jku) = header.jku.as_deref() {
        let listed = matches!(&client.keys, Some(ClientKeys::Uri(url)) if url.as_str() == jku);
        if !listed {
            return Err(Refusal::client("the jku is not the registered JWK Set URL"));
        }
    }
    let key = key_of(state, &client, kid, algorithm).await?;
    let claims = verified(state, assertion, &key, algorithm)?;
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

/// Returns the one key of `client`'s set whose `kid` is `kid` and whose
/// `kty` fits `algorithm` (SMART App Launch 2.2.0, Client Authentication:
/// Asymmetric, Signature Verification, step 3), reading the set again once
/// when the cached set holds none.
pub(crate) async fn key_of(
    state: &AppState,
    client: &Client,
    kid: &str,
    algorithm: Algorithm,
) -> Result<DecodingKey, Refusal> {
    let kty = if matches!(algorithm, Algorithm::RS384) {
        "RSA"
    } else {
        "EC"
    };
    for refresh in [false, true] {
        let set = state
            .client_keys()
            .get(client, refresh)
            .await
            .map_err(|_unread| Refusal::client("the client's JWK Set cannot be read"))?;
        let candidates: Vec<&Value> = set
            .get("keys")
            .and_then(Value::as_array)
            .map(|keys| {
                keys.iter()
                    .filter(|key| {
                        key.get("kid").and_then(Value::as_str) == Some(kid)
                            && key.get("kty").and_then(Value::as_str) == Some(kty)
                    })
                    .collect()
            })
            .unwrap_or_default();
        match candidates.as_slice() {
            [key] => {
                let jwk: Jwk = serde_json::from_value((*key).clone())
                    .map_err(|_unread| Refusal::client("the client's key is no JWK"))?;
                return DecodingKey::from_jwk(&jwk)
                    .map_err(|_unread| Refusal::client("the client's key cannot verify"));
            }
            [] => {}
            _ => return Err(Refusal::client("more than one key matches the kid")),
        }
    }
    Err(Refusal::client("no key of the client matches the kid"))
}

/// Returns the claims of `assertion` once its signature, `exp`, `iss` and
/// `aud` hold (RFC 7523 §3; `docs/architecture.md` §13.6 item 1).
fn verified(
    state: &AppState,
    assertion: &str,
    key: &DecodingKey,
    algorithm: Algorithm,
) -> Result<Value, Refusal> {
    let mut validation = Validation::new(algorithm);
    validation.leeway = LEEWAY_SECONDS;
    validation.validate_aud = false;
    // NOTE: RFC 7523 §3 item 4, `exp` is checked below on its own, so an expired
    // assertion whose signature holds is told apart from one that does not verify.
    validation.validate_exp = false;
    validation.set_required_spec_claims(&["exp", "iss", "sub", "aud", "jti"]);
    let claims: Value = jsonwebtoken::decode(assertion, key, &validation)
        .map_err(|_refused| Refusal::client("the client_assertion does not verify"))?
        .claims;
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
