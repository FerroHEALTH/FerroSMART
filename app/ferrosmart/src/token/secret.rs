// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The client secret of a confidential symmetric client.
//!
//! SMART App Launch 2.2.0, Client Authentication: Symmetric: the secret is
//! sent by HTTP Basic (`client_secret_basic`) or in the form
//! (`client_secret_post`), RFC 6749 §2.3.1, and verified against the
//! Argon2id hash the registry holds.

use base64::Engine as _;
use ferrohealth_smart::basic::PasswordStore;
use http::{HeaderMap, header};

use crate::clients::{AuthMethod, Client};
use crate::form::Params;
use crate::server::AppState;

use super::{Refusal, server_error};

/// The name the one-entry store verifies a secret under: a client id may
/// carry a colon, which an RFC 7617 user-id may not.
const VERIFIED_AS: &str = "client";

/// A client id and secret a request presents.
pub(crate) struct Presented {
    /// The `client_id`.
    client_id: String,
    /// The secret.
    secret: secrecy::SecretString,
    /// How it was sent.
    method: AuthMethod,
}

/// Returns the client secret `headers` or `form` present, if any.
///
/// RFC 6749 §2.3.1: by HTTP Basic, the client id and secret each
/// form-urlencoded before the RFC 7617 encoding, or as the `client_id` and
/// `client_secret` form parameters. "The client MUST NOT use more than one
/// authentication method in each request" (RFC 6749 §2.3), so a request with
/// both, or with either beside a client assertion, is refused.
///
/// # Errors
/// Returns `invalid_request` for two methods at once, and `invalid_client`
/// for a Basic credential that cannot be read.
pub(crate) fn presented(headers: &HeaderMap, form: &Params) -> Result<Option<Presented>, Refusal> {
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Basic"));
    let posted = form.get("client_secret");
    let asserted = form.get("client_assertion").is_some();
    if usize::from(basic.is_some()) + usize::from(posted.is_some()) + usize::from(asserted) > 1 {
        return Err(Refusal::request(
            "the request uses more than one client authentication method",
        ));
    }
    if let Some((_, encoded)) = basic {
        let unreadable = || Refusal::client("the Basic credential cannot be read");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .map_err(|_unread| unreadable())?;
        let decoded = String::from_utf8(decoded).map_err(|_unread| unreadable())?;
        let (id, secret) = decoded.split_once(':').ok_or_else(unreadable)?;
        let id = decode(id).ok_or_else(unreadable)?;
        let secret = decode(secret).ok_or_else(unreadable)?;
        if form.get("client_id").is_some_and(|named| named != id) {
            return Err(Refusal::client(
                "the client_id is not the Basic credential's",
            ));
        }
        return Ok(Some(Presented {
            client_id: id,
            secret: secrecy::SecretString::from(secret),
            method: AuthMethod::ClientSecretBasic,
        }));
    }
    let Some(secret) = posted else {
        return Ok(None);
    };
    let client_id = form
        .get("client_id")
        .ok_or(Refusal::client("the client_secret names no client_id"))?;
    Ok(Some(Presented {
        client_id: client_id.to_owned(),
        secret: secrecy::SecretString::from(secret.to_owned()),
        method: AuthMethod::ClientSecretPost,
    }))
}

/// Returns `value` form-urlencoding decoded (RFC 6749 Appendix B), or
/// `None` when it decodes to no UTF-8.
fn decode(value: &str) -> Option<String> {
    let bytes: Vec<u8> = url::form_urlencoded::parse(format!("v={value}").as_bytes())
        .next()
        .map(|(_, decoded)| decoded.into_owned().into_bytes())?;
    String::from_utf8(bytes).ok()
}

/// Authenticates the confidential symmetric client of `presented`, by the
/// method it registered (RFC 7591 §2 `token_endpoint_auth_method`).
///
/// An unknown client, a client of another method and a wrong secret all
/// answer one `invalid_client`, and the key derivation runs for each, so the
/// answer tells no client from another (`ferrohealth_smart::basic`, after
/// the OWASP Password Storage Cheat Sheet: our own design).
///
/// # Errors
/// Returns `invalid_client` when the secret does not hold.
pub(crate) async fn authenticate(
    state: &AppState,
    presented: Presented,
) -> Result<Client, Refusal> {
    let client = state
        .store()
        .client(&presented.client_id)
        .await
        .map_err(|error| server_error("the client registry cannot be read", &error))?;
    let symmetric = client.filter(|client| client.auth_method == presented.method);
    let mut store = PasswordStore::new();
    if let Some(hash) = symmetric
        .as_ref()
        .and_then(|client| client.secret_hash.as_ref())
    {
        store = store
            .with_user(
                VERIFIED_AS,
                secrecy::SecretString::from(hash.phc().to_owned()),
            )
            .map_err(|_unusable| Refusal::client("the client's secret cannot be verified"))?;
    }
    let verified = tokio::task::spawn_blocking(move || {
        use secrecy::ExposeSecret as _;
        store
            .verify_password(VERIFIED_AS, presented.secret.expose_secret())
            .is_ok()
    })
    .await
    .map_err(|error| server_error("the secret could not be verified", &error))?;
    match symmetric {
        Some(client) if verified => Ok(client),
        _ => Err(Refusal::client("the client secret does not hold")),
    }
}
