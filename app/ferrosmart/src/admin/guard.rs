// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `ferrohealth-smart` guard in front of the admin API.
//!
//! Every admin route requires [`ADMIN_SCOPE`] verbatim
//! (`Requirement::Scope`), and the layer writes its audit line for each
//! request. The bearer token is an access token FerroSMART issued for its
//! own issuer, and the verifier confirms it against the store on every
//! request: the token's record active, its audience the issuer, and its
//! client registered and enabled. A token revoked, or a client disabled, is
//! refused on the next request at every replica, with no cache between.
//! No specification governs the admin API's guard: our own design.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::Json;
use axum::extract::MatchedPath;
use axum::response::{IntoResponse, Response};
use ferrohealth_smart::guard::{AuthLayer, Classify, Gate, Render, Requirement, Target};
use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::refusal::{Denied, Reason};
use ferrohealth_smart::resource::{Caller, Rejection, Verifier};
use http::request::Parts;
use http::{Extensions, HeaderValue, Method, Uri, header};
use serde_json::json;

use crate::server::AppState;

/// The scope an access token carries to reach the admin API. FerroSMART
/// grants it, like its other `system/` scopes, only to a Backend Services
/// client whose ceiling lists it, so no person ever holds it.
pub const ADMIN_SCOPE: &str = "system/admin";

/// The interaction the guard's audit line records for every admin route.
const ADMIN: &str = "admin";

/// The realm the challenges name.
const REALM: &str = "ferrosmart-admin";

/// The verifier of the admin API's bearer tokens: FerroSMART's own access
/// tokens, each confirmed against the store.
pub struct OwnTokens {
    /// The state whose keys and store confirm a token.
    state: Arc<AppState>,
}

impl std::fmt::Debug for OwnTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnTokens").finish_non_exhaustive()
    }
}

impl OwnTokens {
    /// Returns the caller `token` authenticates, or why it does not.
    async fn caller(&self, token: &str) -> Result<Caller, Rejection> {
        let refused = |reason| Rejection::Invalid { reason };
        let jti = crate::introspect::own_access_token(&self.state, token)
            .ok_or(refused(Reason::Signature))?;
        let store = self.state.store();
        let record = store
            .access_token(&jti)
            .await
            .map_err(|error| Rejection::upstream("token store", error))?
            .filter(|record| record.active)
            .ok_or(refused(Reason::Inactive))?;
        let issuer = &self.state.settings().issuer;
        if record.audience != *issuer {
            return Err(refused(Reason::Audience));
        }
        // NOTE: our own design, the exact-reads rule: a disabled client's token
        // is refused at once, whatever its record says.
        store
            .client(&record.client_id)
            .await
            .map_err(|error| Rejection::upstream("client registry", error))?
            .ok_or(refused(Reason::Inactive))?;
        Ok(Caller::new(
            record.subject,
            Some(record.client_id),
            &record.scope,
            None,
            CallerKind::System,
        )
        .with_issuer(issuer.clone()))
    }
}

impl Verifier for OwnTokens {
    fn verify<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Caller, Rejection>> + Send + 'a>> {
        Box::pin(self.caller(token))
    }
}

/// How the guard reads an admin request: every route the admin router
/// matched requires [`ADMIN_SCOPE`].
#[derive(Debug, Clone, Copy)]
pub struct Classifier;

impl Classify for Classifier {
    fn classify(&self, _method: &Method, _uri: &Uri, extensions: &Extensions) -> Option<Target> {
        let template = extensions.get::<MatchedPath>()?.as_str();
        Some(Target::new(ADMIN, Requirement::Scope(ADMIN_SCOPE.to_owned())).route(template))
    }
}

/// The answer of a refusal: its status, the challenge with its reason code
/// (RFC 6750 §3), and the RFC 6750 §3.1 error code in a JSON body.
#[derive(Debug, Clone, Copy)]
pub struct Body;

impl Render for Body {
    fn render(&self, denied: &Denied, _parts: &Parts) -> Response {
        let refusal = denied.refusal();
        let error = match refusal.status() {
            http::StatusCode::FORBIDDEN => "insufficient_scope",
            http::StatusCode::BAD_REQUEST => "invalid_request",
            http::StatusCode::SERVICE_UNAVAILABLE => "temporarily_unavailable",
            _ => "invalid_token",
        };
        let mut response = (refusal.status(), Json(json!({ "error": error }))).into_response();
        // NOTE: RFC 9110 §5.5, the challenge is built of visible ASCII; one that is
        // not a header value is left off, the status still refusing the request.
        if let Some(value) = denied
            .challenge(Some(REALM))
            .and_then(|challenge| HeaderValue::from_str(&challenge).ok())
        {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

/// Returns the guard of the admin routes over `state`.
#[must_use]
pub fn layer(state: Arc<AppState>) -> AuthLayer<Classifier> {
    let gate = Gate::open()
        .with_bearer(Arc::new(OwnTokens { state }))
        .with_realm(REALM);
    AuthLayer::new(gate, Classifier).with_render(Body)
}
