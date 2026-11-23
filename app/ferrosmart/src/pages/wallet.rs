// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The page that offers the EUDI Wallet (`docs/architecture.md` §13.32).
//!
//! Its link invokes the wallet by redirect, so the page works with no
//! script. Its module, served from FerroSMART's own origin, asks the
//! browser through the W3C Digital Credentials API instead where the
//! browser has it, and posts the wallet's answer back by the page's own
//! form (OpenID4VP 1.0 Appendix A; HAIP 1.0 §5.2).

use axum::response::{IntoResponse, Response};
use ferrohealth_ui::html::Html;
use ferrohealth_ui::view::button::{Variant, label};
use ferrohealth_ui::view::surface::page_card;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use url::Url;

use super::{CATALOG, Sources, brand_lockup, negotiated, respond};
use crate::server::AppState;
use crate::store::Pending;
use crate::upstream::wallet::{DIGITAL_CREDENTIALS_ROUTE, MODULE_ROUTE};

/// The page's module.
const MODULE: &str = include_str!("../../scripts/wallet.js");

/// Returns the page of `pending` whose link is `invocation` and whose
/// module asks the browser with the signed `request`.
#[must_use]
pub fn page(
    state: &AppState,
    headers: &HeaderMap,
    pending: &Pending,
    invocation: &Url,
    request: &str,
) -> Response {
    let locale = negotiated(headers, pending);
    let words = |id: &str| locale.lookup(&*CATALOG, id);
    let offer = Html::raw(format!(
        "<div class=\"fui-stack\" data-ferrosmart-wallet data-request=\"{request}\">\
         <div class=\"fui-cluster\"><a class=\"{primary}\" href=\"{invocation}\">{open}</a></div>\
         <form method=\"post\" action=\"{action}\" hidden>\
         <input type=\"hidden\" name=\"form_token\" value=\"{token}\">\
         <input type=\"hidden\" name=\"data\" value=\"\"></form></div>\
         <script type=\"module\" src=\"{module}\"></script>",
        request = Html::text(request),
        primary = Variant::Primary.class(),
        invocation = Html::text(invocation.as_str()),
        open = label(None, words("wallet-open")),
        action = Html::text(state.settings().endpoint(DIGITAL_CREDENTIALS_ROUTE)),
        token = Html::text(&pending.form_token),
        module = Html::text(state.settings().endpoint(MODULE_ROUTE)),
    ));
    let body = Html::join([
        Html::raw(format!("<p>{}</p>", Html::text(words("wallet-intro")))),
        offer,
    ]);
    let title = words("wallet-title");
    let page = page_card(Some(brand_lockup(state, &locale)), title.clone(), body);
    // NOTE: CSP Level 3 §6.4.2, form-action also holds the redirect that follows the
    // post, which a refused or declined answer sends to the app.
    let app = Url::parse(&pending.redirect_uri)
        .ok()
        .map(|url| url.origin().ascii_serialization())
        .filter(|origin| origin != "null");
    respond(
        state,
        StatusCode::OK,
        &locale,
        title,
        page,
        Sources {
            form: &app.into_iter().collect::<Vec<_>>(),
            img: &[],
        },
    )
}

/// Returns the page's module, a plain ES module with no inline script, so
/// `script-src 'self'` holds.
#[must_use]
pub fn module() -> Response {
    let mut response = (StatusCode::OK, MODULE).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/javascript; charset=utf-8"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}
