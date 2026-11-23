// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The OpenAPI 3.1 document of the administration API, and the operation
//! table every admin route is built from, so the document and the router
//! name the same operations (`docs/architecture.md` §13.8).
//!
//! The standard endpoints (`/authorize`, `/token`, `/introspect`, `/revoke`
//! and the discovery documents) are described by their RFCs and are not in
//! the document.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::handler::Handler;
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodFilter, MethodRouter, on};
use http::{HeaderValue, Method, header};
use serde_json::Value;

use crate::config::settings::Settings;
use crate::server::AppState;

/// The route of the document.
pub const OPENAPI_ROUTE: &str = "/admin/openapi.json";

/// The document as committed.
const DOCUMENT: &str = include_str!("../../openapi.json");

/// One operation of the API: its method, its route template and its
/// handler.
pub struct Operation {
    /// The method.
    method: Method,
    /// The route template, in axum's `{name}` form, which OpenAPI path
    /// templating shares.
    path: &'static str,
    /// The handler, routed on the method alone.
    route: MethodRouter<Arc<AppState>>,
}

impl std::fmt::Debug for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Operation")
            .field("method", &self.method)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Operation {
    /// Returns the operation `method` at `path`, answered by `handler`.
    fn new<H, T>(method: Method, filter: MethodFilter, path: &'static str, handler: H) -> Self
    where
        H: Handler<T, Arc<AppState>>,
        T: 'static,
    {
        Self {
            method,
            path,
            route: on(filter, handler),
        }
    }

    /// Returns `GET path`.
    pub fn get<H, T>(path: &'static str, handler: H) -> Self
    where
        H: Handler<T, Arc<AppState>>,
        T: 'static,
    {
        Self::new(Method::GET, MethodFilter::GET, path, handler)
    }

    /// Returns `POST path`.
    pub fn post<H, T>(path: &'static str, handler: H) -> Self
    where
        H: Handler<T, Arc<AppState>>,
        T: 'static,
    {
        Self::new(Method::POST, MethodFilter::POST, path, handler)
    }

    /// Returns `PUT path`.
    pub fn put<H, T>(path: &'static str, handler: H) -> Self
    where
        H: Handler<T, Arc<AppState>>,
        T: 'static,
    {
        Self::new(Method::PUT, MethodFilter::PUT, path, handler)
    }

    /// Returns `DELETE path`.
    pub fn delete<H, T>(path: &'static str, handler: H) -> Self
    where
        H: Handler<T, Arc<AppState>>,
        T: 'static,
    {
        Self::new(Method::DELETE, MethodFilter::DELETE, path, handler)
    }
}

/// Returns the router of `operations`.
pub fn routes(operations: Vec<Operation>) -> Router<Arc<AppState>> {
    operations
        .into_iter()
        .fold(Router::new(), |router, operation| {
            router.route(operation.path, operation.route)
        })
}

/// Returns every operation the document describes, as method and route
/// template: the admin API, client registration, the audit records and the
/// document itself.
#[must_use]
pub fn operations() -> Vec<(Method, &'static str)> {
    super::table()
        .into_iter()
        .chain(super::register::table())
        .chain(crate::audit_log::table())
        .chain(table())
        .map(|operation| (operation.method, operation.path))
        .collect()
}

/// Returns the document's own operation, which answers without a token.
pub fn table() -> Vec<Operation> {
    vec![Operation::get(OPENAPI_ROUTE, openapi)]
}

/// The issuer the committed document names (RFC 2606 §2), which
/// [`document`] replaces with the deployment's.
pub const PLACEHOLDER: &str = "https://issuer.invalid";

/// The `info.version` the committed document names, which [`document`]
/// replaces with the server's version.
const VERSION: &str = "\"version\": \"0.0.0\"";

/// Returns the document for the deployment `settings` describe: its server
/// the issuer, its token URL the issuer's token endpoint, and its version
/// the server's.
#[must_use]
pub fn document(settings: &Settings) -> Bytes {
    let issuer = Value::from(settings.issuer.trim_end_matches('/')).to_string();
    let issuer = issuer.trim_matches('"');
    let version = format!("\"version\": \"{}\"", env!("CARGO_PKG_VERSION"));
    Bytes::from(
        DOCUMENT
            .replacen(VERSION, &version, 1)
            .replace(PLACEHOLDER, issuer),
    )
}

/// `GET {issuer}/admin/openapi.json`.
async fn openapi(axum::extract::State(state): axum::extract::State<Arc<AppState>>) -> Response {
    let mut response = state.openapi().clone().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}
