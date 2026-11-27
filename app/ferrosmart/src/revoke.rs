// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The revocation endpoint (RFC 7009 §2).
//!
//! A confidential client authenticates by its `private_key_jwt` assertion,
//! a public client names itself by `client_id` (RFC 7009 §2.1, RFC 6749
//! §2.3); the token must have been issued to it. Revoking a refresh token
//! revokes its whole grant, every refresh and access token issued under it
//! ("the authorization server SHOULD also invalidate all access tokens
//! based on the same authorization grant", RFC 7009 §2.1); revoking an
//! access token revokes that token alone. An unknown, expired or already
//! revoked token answers `200` (RFC 7009 §2.2).

use std::net::IpAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, StatusCode};

use crate::audit::{Connected, Event, Happening};
use crate::discovery::REVOKE_ROUTE;
use crate::introspect::{Found, find};
use crate::server::AppState;
use crate::token::grants::identify;
use crate::token::{Refusal, no_store, read_form, server_error};

/// `POST {issuer}/revoke`.
pub async fn revoke(
    State(state): State<Arc<AppState>>,
    Connected(from): Connected,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match revoked(&state, &headers, &body, from).await {
        Ok(()) => no_store(StatusCode::OK.into_response()),
        Err(refusal) => {
            tracing::info!(
                target: "ferrosmart::audit",
                event = "revocation.refused",
                error = refusal.error,
                "a revocation request was refused"
            );
            refusal.answer(&headers)
        }
    }
}

/// Revokes the token the request names, once its client is known and the
/// token is its own.
async fn revoked(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
    from: IpAddr,
) -> Result<(), Refusal> {
    let form = read_form(headers, body)?;
    let client = identify(
        state,
        headers,
        &form,
        crate::token::assertion::Endpoint::Token,
    )
    .await?;
    let token = form
        .get("token")
        .ok_or(Refusal::request("the request carries no token"))?;
    // NOTE: RFC 7009 §2.1, a server MAY ignore token_type_hint; the value itself
    // tells an access token from a refresh token.
    let not_its_own = Refusal {
        error: "unauthorized_client",
        description: "the token was not issued to this client",
    };
    let mut tx = state
        .store()
        .begin()
        .await
        .map_err(|error| server_error("the token cannot be revoked", &error))?;
    let (event, subject, details) = match find(state, token).await? {
        Some(Found::Access { jti, record, .. }) => {
            if record.client_id != client.client_id {
                return Err(not_its_own);
            }
            let revoked = tx
                .revoke_access_token(&jti)
                .await
                .map_err(|error| server_error("the token cannot be revoked", &error))?;
            (
                Event::TokenRevoked,
                record.subject,
                vec![("jti", jti), ("revoked", revoked.to_string())],
            )
        }
        Some(Found::Refresh { record }) => {
            if record.grant.client_id != client.client_id {
                return Err(not_its_own);
            }
            let revoked = tx
                .revoke_grant(&record.grant.id)
                .await
                .map_err(|error| server_error("the grant cannot be revoked", &error))?;
            (
                Event::GrantRevoked,
                record.grant.subject,
                vec![("grant", record.grant.id), ("revoked", revoked.to_string())],
            )
        }
        // NOTE: RFC 7009 §2.2, an unknown token answers 200 and changes nothing,
        // so the transaction is dropped unwritten.
        None => return Ok(()),
    };
    let endpoint = state.settings().endpoint_url(REVOKE_ROUTE);
    let happening = Happening {
        event,
        issuer: &state.settings().issuer,
        client_id: Some(&client.client_id),
        subject: Some(&subject),
        from,
        endpoint: &endpoint,
        details,
    };
    state
        .audit()
        .commit_happening(tx, &happening)
        .await
        .map_err(|error| server_error("the revocation could not be recorded", &error))?;
    Ok(())
}
