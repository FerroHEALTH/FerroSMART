// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The pages of the end-session endpoint (OpenID Connect RP-Initiated
//! Logout 1.0 §2): the confirmation, its two outcomes, and the refusal.

use axum::response::Response;
use ferrohealth_ui::html::Html;
use ferrohealth_ui::i18n::{Arg, Locale};
use ferrohealth_ui::icon::Glyph;
use ferrohealth_ui::view::button::{Variant, label};
use ferrohealth_ui::view::error_page::{ErrorPage, Status, error_page};
use ferrohealth_ui::view::surface::page_card;
use http::StatusCode;

use super::{CATALOG, Sources, brand_lockup, respond};
use crate::logout::end_session::{END_SESSION_CONFIRM_ROUTE, Refused};
use crate::server::AppState;
use crate::store::logout::PendingLogout;

/// Returns the page that asks the person whether to log out.
///
/// The end-session endpoint SHOULD always ask, and MUST without a hint
/// (§2). `reach` names the origins the answer may go on to, the upstream
/// provider's end-session endpoint and the app.
#[must_use]
pub fn confirm(state: &AppState, pending: &PendingLogout, reach: &[String]) -> Response {
    let locale = Locale::default().with_catalog(&*CATALOG);
    let words = |id: &str| locale.lookup(&*CATALOG, id);
    let intro = locale.lookup_with(
        &*CATALOG,
        "logout-intro",
        &[("name", Arg::from(state.settings().name.as_str()))],
    );
    let form = Html::raw(format!(
        "<form method=\"post\" action=\"{action}\" class=\"fui-stack\">\
         <input type=\"hidden\" name=\"form_token\" value=\"{token}\">\
         <div class=\"fui-cluster\">\
         <button type=\"submit\" name=\"decision\" value=\"logout\" class=\"{primary}\">{logout}</button>\
         <button type=\"submit\" name=\"decision\" value=\"stay\" class=\"{secondary}\">{stay}</button>\
         </div></form>",
        action = Html::text(state.settings().endpoint(END_SESSION_CONFIRM_ROUTE)),
        token = Html::text(&pending.form_token),
        primary = Variant::Primary.class(),
        logout = label(Some(Glyph::CHECK), words("logout-confirm")),
        secondary = Variant::Secondary.class(),
        stay = label(None, words("logout-stay")),
    ));
    let body = Html::join([
        Html::raw(format!("<p>{}</p>", Html::text(&intro))),
        Html::raw(format!("<p>{}</p>", Html::text(words("logout-apps")))),
        form,
    ]);
    let title = words("logout-title");
    let page = page_card(Some(brand_lockup(state, &locale)), title.clone(), body);
    respond(
        state,
        StatusCode::OK,
        &locale,
        title,
        page,
        Sources {
            form: reach,
            img: &[],
        },
    )
}

/// Returns the page that says the person is logged out, when no app asked
/// to be returned to.
#[must_use]
pub fn logged_out(state: &AppState) -> Response {
    notice(state, ["logged-out-title", "logged-out-body"])
}

/// Returns the page that says the person stayed signed in.
#[must_use]
pub fn stayed(state: &AppState) -> Response {
    notice(state, ["logout-stayed-title", "logout-stayed-body"])
}

/// Returns the page of the catalog's `[title, body]`.
fn notice(state: &AppState, [title, body]: [&str; 2]) -> Response {
    let locale = Locale::default().with_catalog(&*CATALOG);
    let words = |id: &str| locale.lookup(&*CATALOG, id);
    let title = words(title);
    let body = Html::raw(format!("<p>{}</p>", Html::text(words(body))));
    let page = page_card(Some(brand_lockup(state, &locale)), title.clone(), body);
    respond(
        state,
        StatusCode::OK,
        &locale,
        title,
        page,
        Sources::default(),
    )
}

/// Returns the page of a refused logout request, which sends the browser
/// nowhere (§3).
#[must_use]
pub fn refused(state: &AppState, refused: Refused) -> Response {
    let locale = Locale::default().with_catalog(&*CATALOG);
    let body = match refused {
        Refused::Hint => "logout-refused-hint",
        Refused::Client => "logout-refused-client",
        Refused::Redirect => "logout-refused-redirect",
    };
    let title = locale.lookup(&*CATALOG, "logout-refused");
    let page = error_page(
        &locale,
        ErrorPage {
            status: Status::BadRequest,
            title: title.clone(),
            body: Html::text(locale.lookup(&*CATALOG, body)),
            hint: None,
            ways: Vec::new(),
            detail: None,
        },
    );
    let page = Html::join([brand_lockup(state, &locale), page]);
    respond(
        state,
        StatusCode::BAD_REQUEST,
        &locale,
        title,
        page,
        Sources::default(),
    )
}
