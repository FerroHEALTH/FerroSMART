// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The pages a person sees: the consent page and the error pages.
//!
//! Each is a whole document drawn on the server with FerroUI's components in the
//! FerroSMART brand (`docs/architecture.md` §13.15). Every action is a
//! form post, so a page works with no script; the policy admits scripts and
//! styles from FerroSMART's own origin alone.

use axum::response::{IntoResponse, Response};
use ferrohealth_ui::html::Html;
use ferrohealth_ui::i18n::{Arg, Locale};
use ferrohealth_ui::icon::Glyph;
use ferrohealth_ui::serve::Assets;
use ferrohealth_ui::style::Brand;
use ferrohealth_ui::theme::Preferences;
use ferrohealth_ui::view::button::{Variant, label};
use ferrohealth_ui::view::error_page::{ErrorPage, Status, Way, error_page};
use ferrohealth_ui::view::form::{check, check_field, field, fieldset};
use ferrohealth_ui::view::scope::{ScopeGrant, scope_grants};
use ferrohealth_ui::view::shell::{
    Document, Footer, centred, document, ferrosmart_mark, lockup_plain,
};
use ferrohealth_ui::view::surface::{card, page_card};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use url::Url;

pub mod logout;
pub mod saml;

use crate::authorize::{CONSENT_ROUTE, MANAGE_ROUTE};
use crate::clients::Client;
use crate::server::AppState;
use crate::store::Pending;

fluent_templates::static_loader! {
    static CATALOG = {
        locales: "./locales",
        fallback_language: "en",
        // NOTE: Fluent's guide, "Bidirectionality": the isolation marks are for
        // mixed-direction text; the English catalog draws none.
        customise: |bundle| bundle.set_use_isolating(false),
    };
}

/// Why a page answers instead of the flow going on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The client or its redirect URI is not registered, so the browser is
    /// not sent back to it (RFC 6749 §4.1.2.1).
    UnknownClient,
    /// The redirect URI is not one the client registered.
    UnknownRedirect,
    /// The request lapsed or was already decided.
    Lapsed,
    /// The request began in another browser.
    OtherBrowser,
    /// The request could not be read.
    BadRequest,
    /// The person's own record, which their `fhirUser` names, cannot be
    /// read as them, or has no EHR they may see.
    NoOwnRecord,
    /// The person's login does not reach the eIDAS level of assurance the
    /// provider or the deployment holds it to.
    Assurance,
    /// The server failed.
    Server,
}

impl Fault {
    /// The page's status, its words' ids and the HTTP status.
    const fn parts(self) -> (Status, StatusCode, &'static str, &'static str) {
        match self {
            Self::UnknownClient | Self::UnknownRedirect => (
                Status::BadRequest,
                StatusCode::BAD_REQUEST,
                "fault-unknown-client",
                "fault-unknown-client-body",
            ),
            Self::Lapsed => (
                Status::NotFound,
                StatusCode::NOT_FOUND,
                "fault-lapsed",
                "fault-lapsed-body",
            ),
            Self::OtherBrowser => (
                Status::Forbidden,
                StatusCode::FORBIDDEN,
                "fault-other-browser",
                "fault-other-browser-body",
            ),
            Self::BadRequest => (
                Status::BadRequest,
                StatusCode::BAD_REQUEST,
                "fault-bad-request",
                "fault-bad-request-body",
            ),
            Self::NoOwnRecord => (
                Status::Forbidden,
                StatusCode::FORBIDDEN,
                "fault-own-record",
                "fault-own-record-body",
            ),
            Self::Assurance => (
                Status::Forbidden,
                StatusCode::FORBIDDEN,
                "fault-assurance",
                "fault-assurance-body",
            ),
            Self::Server => (
                Status::Fault,
                StatusCode::INTERNAL_SERVER_ERROR,
                "fault-server",
                "fault-server-body",
            ),
        }
    }
}

/// Returns the lockup every page leads with: FerroSMART's mark, the shield
/// with the keyhole, drawn by FerroUI, beside the deployment's name.
fn brand_lockup(state: &AppState, locale: &Locale) -> Html {
    lockup_plain(
        ferrosmart_mark(),
        &state.settings().branding.name,
        locale.lookup(&*CATALOG, "product-word"),
    )
}

/// Returns the page `fault` names, under FerroSMART's lockup.
pub fn fault(state: &AppState, fault: Fault) -> Response {
    let locale = Locale::default().with_catalog(&*CATALOG);
    let (status, code, title, body) = fault.parts();
    let page = error_page(
        &locale,
        ErrorPage {
            status,
            title: locale.lookup(&*CATALOG, title),
            body: Html::text(locale.lookup(&*CATALOG, body)),
            hint: None,
            ways: Vec::new(),
            detail: None,
        },
    );
    let title = locale.lookup(&*CATALOG, title);
    let page = Html::join([brand_lockup(state, &locale), page]);
    respond(state, code, &locale, title, page, Sources::default())
}

/// Returns the page that tells the person no scope `client` asked is theirs.
///
/// It names the configured `roles` that would grant one, with one way on:
/// back to the app at `back`, which carries `access_denied`.
#[must_use]
pub fn no_scope(state: &AppState, client: &Client, roles: &[&str], back: &str) -> Response {
    let locale = Locale::default().with_catalog(&*CATALOG);
    let client_name = Arg::from(client.name.as_str());
    let with = |id: &str, args: &[(&'static str, Arg)]| locale.lookup_with(&*CATALOG, id, args);
    let title = with("no-scope-title", &[("client", client_name.clone())]);
    let body = if roles.is_empty() {
        with("no-scope-body-client", &[("client", client_name.clone())])
    } else {
        with(
            "no-scope-body-role",
            &[
                ("client", client_name.clone()),
                ("roles", Arg::from(roles.join(", "))),
            ],
        )
    };
    let page = error_page(
        &locale,
        ErrorPage {
            status: Status::Forbidden,
            title: title.clone(),
            body: Html::text(body),
            hint: None,
            ways: vec![Way {
                label: with("no-scope-back", &[("client", client_name)]),
                href: back.to_owned(),
                glyph: None,
            }],
            detail: None,
        },
    );
    let page = Html::join([brand_lockup(state, &locale), page]);
    respond(
        state,
        StatusCode::FORBIDDEN,
        &locale,
        title,
        page,
        Sources::default(),
    )
}

/// Logs `error` with its whole chain and returns the server's fault page.
pub fn server_error(state: &AppState, error: &dyn std::error::Error) -> Response {
    tracing::error!(error = %ferrohealth_server::run::chain(error), "a page failed");
    fault(state, Fault::Server)
}

/// Returns the consent page of `pending` for `client`.
///
/// It is drawn in the language the request's `ui_locales`, then its
/// `Accept-Language`, prefer among the catalog's, with the remember box
/// ticked when the person `remembered` a consent for the client.
pub fn consent(
    state: &AppState,
    headers: &HeaderMap,
    client: &Client,
    pending: &Pending,
    remembered: bool,
) -> Response {
    let locale = negotiated(headers, pending);
    let words = |id: &str| locale.lookup(&*CATALOG, id);
    let with = |id: &str, args: &[(&'static str, Arg)]| locale.lookup_with(&*CATALOG, id, args);
    let offered: Vec<&str> = pending
        .offered_scope
        .as_deref()
        .unwrap_or_default()
        .split(' ')
        .filter(|scope| !scope.is_empty())
        .collect();
    // NOTE: docs/architecture.md §13.6 item 3, identity, launch and refresh scopes
    // are fixed lines and resource scopes keep their boxes (owner, 2026-11-19).
    let (fixed, chosen): (Vec<&str>, Vec<&str>) = offered
        .iter()
        .partition(|scope| crate::scopes::is_fixed(scope));
    let signed_in = pending.display_name.as_deref().map_or_else(
        || words("consent-signed-in-plain"),
        |name| with("consent-signed-in", &[("name", Arg::from(name))]),
    );
    let client_name = Arg::from(client.name.as_str());
    let form = consent_form(state, &locale, &client_name, pending, &chosen, remembered);
    let deployment = &state.settings().branding;
    let own_words = if deployment.consent_text.is_empty() {
        Html::empty()
    } else {
        Html::raw(format!("<p>{}</p>", Html::text(&deployment.consent_text)))
    };
    let body = Html::join([
        Html::raw(format!("<p>{}</p>", Html::text(signed_in))),
        about(&client.about, &locale, &client_name),
        Html::raw(format!(
            "<p>{}</p>",
            Html::text(with("consent-intro", &[("client", client_name.clone())]))
        )),
        if chosen.is_empty() {
            Html::empty()
        } else {
            scope_list(&locale, &words("consent-scopes"), &chosen)
        },
        if fixed.is_empty() {
            Html::empty()
        } else {
            scope_list(
                &locale,
                &with("consent-fixed", &[("client", client_name.clone())]),
                &fixed,
            )
        },
        unknown_user(&locale, pending, &client_name),
        own_words,
        form,
    ]);
    let title = with("consent-title", &[("client", client_name)]);
    let lockup = brand_lockup(state, &locale);
    let page = page_card(Some(lockup), title.clone(), body);
    // NOTE: CSP Level 3 §6.4.2, form-action also holds the redirect that follows
    // the post, so the policy names the app's origin beside FerroSMART's.
    let origin = Url::parse(&pending.redirect_uri)
        .ok()
        .map(|url| url.origin().ascii_serialization())
        .filter(|origin| origin != "null");
    // NOTE: CSP Level 3 §6.1.8 img-src, the app's logo is loaded from its own
    // origin, which the policy names on this page alone.
    let logo_origin = client
        .about
        .logo
        .as_ref()
        .map(|url| url.origin().ascii_serialization());
    respond(
        state,
        StatusCode::OK,
        &locale,
        title,
        page,
        Sources {
            form: &origin.into_iter().collect::<Vec<_>>(),
            img: &logo_origin.into_iter().collect::<Vec<_>>(),
        },
    )
}

/// Returns the consent page's form for `pending`: a box per resource scope
/// of `chosen`, the remember box, ticked when `remembered`, and the two
/// decisions.
fn consent_form(
    state: &AppState,
    locale: &Locale,
    client_name: &Arg,
    pending: &Pending,
    chosen: &[&str],
    remembered: bool,
) -> Html {
    let words = |id: &str| locale.lookup(&*CATALOG, id);
    let with = |id: &str, args: &[(&'static str, Arg)]| locale.lookup_with(&*CATALOG, id, args);
    let checks = Html::join(chosen.iter().enumerate().map(|(index, scope)| {
        let id = format!("scope-{index}");
        let checkbox = Html::raw(format!(
            "<input type=\"checkbox\" id=\"{id}\" name=\"scope\" value=\"{}\" checked>",
            Html::text(scope)
        ));
        check(&id, *scope, checkbox)
    }));
    let action = state.settings().endpoint(CONSENT_ROUTE);
    let remember = check_field(
        "remember",
        with("consent-remember", &[("client", client_name.clone())]),
        with("consent-remember-help", &[("client", client_name.clone())]),
        Html::raw(format!(
            "<input type=\"checkbox\" id=\"remember\" name=\"remember\" value=\"yes\" aria-describedby=\"remember-help\"{}>",
            if remembered { " checked" } else { "" }
        )),
    );
    Html::raw(format!(
        "<form method=\"post\" action=\"{action}\" class=\"fui-stack\">\
         <input type=\"hidden\" name=\"form_token\" value=\"{token}\">{fields}{remember}\
         <div class=\"fui-cluster\">\
         <button type=\"submit\" name=\"decision\" value=\"approve\" class=\"{primary}\">{allow}</button>\
         <button type=\"submit\" name=\"decision\" value=\"deny\" class=\"{secondary}\">{deny}</button>\
         </div></form>",
        action = Html::text(&action),
        token = Html::text(&pending.form_token),
        fields = if chosen.is_empty() {
            Html::empty()
        } else {
            fieldset(words("consent-choose"), checks)
        },
        primary = Variant::Primary.class(),
        secondary = Variant::Secondary.class(),
        allow = label(Some(Glyph::CHECK), words("consent-allow")),
        deny = label(None, words("consent-deny")),
    ))
}

/// Returns what the consent page shows about the app `about` registers:
/// its logo, and links to its home page, privacy policy and terms.
fn about(about: &crate::clients::About, locale: &Locale, client_name: &Arg) -> Html {
    let with = |id: &str| locale.lookup_with(&*CATALOG, id, &[("client", client_name.clone())]);
    let logo = about.logo.as_ref().map_or_else(Html::empty, |logo| {
        Html::raw(format!(
            "<img src=\"{}\" alt=\"{}\" width=\"64\" height=\"64\">",
            Html::text(logo.as_str()),
            Html::text(with("consent-logo"))
        ))
    });
    let links: Vec<Html> = [
        (&about.home, "consent-about-home"),
        (&about.policy, "consent-about-policy"),
        (&about.terms, "consent-about-terms"),
    ]
    .into_iter()
    .filter_map(|(url, id)| {
        url.as_ref().map(|url| {
            Html::raw(format!(
                "<li><a href=\"{}\" rel=\"noopener noreferrer\" target=\"_blank\">{}</a></li>",
                Html::text(url.as_str()),
                Html::text(with(id))
            ))
        })
    })
    .collect();
    let links = if links.is_empty() {
        Html::empty()
    } else {
        Html::join([
            Html::raw(String::from("<ul class=\"fui-cluster\">")),
            Html::join(links),
            Html::raw(String::from("</ul>")),
        ])
    };
    Html::join([logo, links])
}

/// The origins a page names beside its own in its content security policy.
#[derive(Debug, Clone, Copy, Default)]
struct Sources<'a> {
    /// The origins its forms post to, or are redirected to.
    form: &'a [String],
    /// The origins its images load from.
    img: &'a [String],
}

/// Returns the line that tells the person the app asked who they are as a
/// FHIR resource and FerroSMART does not know it, or nothing
/// (`docs/architecture.md` §13.6 item 9).
fn unknown_user(locale: &Locale, pending: &Pending, client_name: &Arg) -> Html {
    let asked = pending.scope.split(' ').any(|scope| scope == "fhirUser");
    if !asked || pending.fhir_user.is_some() {
        return Html::empty();
    }
    let words = locale.lookup_with(
        &*CATALOG,
        "consent-no-fhir-user",
        &[("client", client_name.clone())],
    );
    Html::raw(format!("<p>{}</p>", Html::text(words)))
}

/// Returns the patient picker page of `pending`: the search form, filled
/// with `asked`, and the patients `found` when a search ran, or else the
/// words of `notice` when it names any.
#[must_use]
pub fn picker(
    state: &AppState,
    headers: &HeaderMap,
    pending: &Pending,
    asked: Option<(Option<&str>, Option<&str>)>,
    found: Option<&[crate::picker::Found]>,
    notice: Option<&str>,
) -> Response {
    let locale = negotiated(headers, pending);
    let words = |id: &str| locale.lookup(&*CATALOG, id);
    let action = state.settings().endpoint(crate::picker::PICKER_ROUTE);
    let (name, identifier) = asked.unwrap_or_default();
    let input = |id: &'static str, value: Option<&str>| {
        Html::raw(format!(
            "<input type=\"search\" id=\"{id}\" name=\"{id}\" value=\"{}\" class=\"fui-input\">",
            Html::text(value.unwrap_or_default())
        ))
    };
    let search = Html::raw(format!(
        "<form method=\"get\" action=\"{action}\" role=\"search\" class=\"fui-stack\">{name}{identifier}\
         <div class=\"fui-cluster\"><button type=\"submit\" class=\"{primary}\">{label}</button></div></form>",
        action = Html::text(&action),
        name = field("name", words("picker-name"), None, input("name", name)),
        identifier = field(
            "identifier",
            words("picker-identifier"),
            None,
            input("identifier", identifier)
        ),
        primary = Variant::Primary.class(),
        label = label(Some(Glyph::SEARCH), words("picker-search")),
    ));
    let results = match found {
        None => notice.map_or_else(Html::empty, |id| {
            Html::raw(format!("<p role=\"status\">{}</p>", Html::text(words(id))))
        }),
        Some([]) => Html::raw(format!("<p>{}</p>", Html::text(words("picker-none")))),
        Some(found) => {
            let choices = Html::join(found.iter().enumerate().map(|(index, patient)| {
                let id = format!("patient-{index}");
                let radio = Html::raw(format!(
                    "<input type=\"radio\" id=\"{id}\" name=\"patient\" value=\"{}\" required>",
                    Html::text(&patient.id)
                ));
                let mut words_of = vec![patient.name.clone()];
                if let Some(date) = &patient.birth_date {
                    words_of.push(locale.lookup_with(
                        &*CATALOG,
                        "picker-born",
                        &[("date", Arg::from(date.as_str()))],
                    ));
                }
                words_of.extend(patient.gender.clone());
                words_of.extend(patient.identifier.clone());
                check(&id, words_of.join(", "), radio)
            }));
            Html::raw(format!(
                "<form method=\"post\" action=\"{action}\" class=\"fui-stack\">\
                 <input type=\"hidden\" name=\"form_token\" value=\"{token}\">{purpose}{fields}\
                 <div class=\"fui-cluster\"><button type=\"submit\" class=\"{primary}\">{choose}</button></div></form>",
                action = Html::text(&action),
                token = Html::text(&pending.form_token),
                purpose = purpose_choice(state, &locale, pending),
                fields = fieldset(words("picker-results"), choices),
                primary = Variant::Primary.class(),
                choose = label(Some(Glyph::CHECK), words("picker-choose")),
            ))
        }
    };
    picker_card(
        state,
        &locale,
        ["picker-title", "picker-intro"],
        search,
        results,
    )
}

/// Returns the encounter step of the picker for `pending`: the encounters
/// of the chosen `patient` the search `found`, to pick one or go on
/// without.
#[must_use]
pub fn encounter_picker(
    state: &AppState,
    headers: &HeaderMap,
    (pending, patient): (&Pending, &str),
    found: &[crate::picker::encounter::FoundEncounter],
) -> Response {
    let locale = negotiated(headers, pending);
    let words = |id: &str| locale.lookup(&*CATALOG, id);
    let choices = if found.is_empty() {
        Html::raw(format!(
            "<p>{}</p>",
            Html::text(words("picker-encounter-none"))
        ))
    } else {
        let radios = Html::join(found.iter().enumerate().map(|(index, encounter)| {
            let id = format!("encounter-{index}");
            let radio = Html::raw(format!(
                "<input type=\"radio\" id=\"{id}\" name=\"encounter\" value=\"{}\" required>",
                Html::text(&encounter.id)
            ));
            let mut words_of = Vec::new();
            if !encounter.kind.is_empty() {
                words_of.push(encounter.kind.clone());
            }
            if let Some(start) = &encounter.start {
                words_of.push(locale.lookup_with(
                    &*CATALOG,
                    "picker-encounter-started",
                    &[("date", Arg::from(start.as_str()))],
                ));
            }
            words_of.extend(encounter.status.clone());
            if words_of.is_empty() {
                words_of.push(encounter.id.clone());
            }
            check(&id, words_of.join(", "), radio)
        }));
        fieldset(words("picker-encounter-results"), radios)
    };
    let choose = if found.is_empty() {
        Html::empty()
    } else {
        Html::raw(format!(
            "<button type=\"submit\" class=\"{primary}\">{choose}</button>",
            primary = Variant::Primary.class(),
            choose = label(Some(Glyph::CHECK), words("picker-encounter-choose")),
        ))
    };
    let form = Html::raw(format!(
        "<form method=\"post\" action=\"{action}\" class=\"fui-stack\">\
         <input type=\"hidden\" name=\"form_token\" value=\"{token}\">\
         <input type=\"hidden\" name=\"step\" value=\"{step}\">\
         <input type=\"hidden\" name=\"patient\" value=\"{patient}\">{choices}\
         <div class=\"fui-cluster\">{choose}\
         <button type=\"submit\" name=\"without\" value=\"yes\" formnovalidate class=\"{secondary}\">{without}</button>\
         </div></form>",
        action = Html::text(state.settings().endpoint(crate::picker::PICKER_ROUTE)),
        token = Html::text(&pending.form_token),
        step = crate::picker::encounter::STEP,
        patient = Html::text(patient),
        secondary = Variant::Secondary.class(),
        without = label(None, words("picker-encounter-without")),
    ));
    picker_card(
        state,
        &locale,
        ["picker-encounter-title", "picker-encounter-intro"],
        Html::empty(),
        form,
    )
}

/// Returns the page on which the person of `pending` chooses the provider
/// they log in at, one button per provider of `providers`.
///
/// The choice posts to FerroSMART, which sends the browser on to the
/// provider's authorization endpoint, so the page's `form-action` admits
/// each provider's origin.
#[must_use]
pub fn chooser(
    state: &AppState,
    headers: &HeaderMap,
    pending: &Pending,
    providers: &[&crate::upstream::LoginProvider],
) -> Response {
    let locale = negotiated(headers, pending);
    let words = |id: &str| locale.lookup(&*CATALOG, id);
    let buttons = Html::join(providers.iter().map(|provider| {
        Html::raw(format!(
            "<button type=\"submit\" name=\"provider\" value=\"{name}\" class=\"{primary}\">{label}</button>",
            name = Html::text(provider.name()),
            primary = Variant::Primary.class(),
            label = label(None, &provider.upstream().label),
        ))
    }));
    let form = Html::raw(format!(
        "<form method=\"post\" action=\"{action}\" class=\"fui-stack\">\
         <input type=\"hidden\" name=\"form_token\" value=\"{token}\">\
         <div class=\"fui-stack\">{buttons}</div></form>",
        action = Html::text(
            state
                .settings()
                .endpoint(crate::authorize::choose::LOGIN_ROUTE)
        ),
        token = Html::text(&pending.form_token),
    ));
    let endpoints: Vec<Url> = providers
        .iter()
        .filter_map(|provider| provider.login_endpoint())
        .collect();
    let reach = crate::upstream::origins_of(endpoints.iter());
    let body = Html::join([
        Html::raw(format!("<p>{}</p>", Html::text(words("chooser-intro")))),
        form,
    ]);
    let title = words("chooser-title");
    let page = page_card(Some(brand_lockup(state, &locale)), title.clone(), body);
    respond(
        state,
        StatusCode::OK,
        &locale,
        title,
        page,
        Sources {
            form: &reach,
            img: &[],
        },
    )
}

/// Returns the purposes of use the openEHR server of `pending` lists, as
/// the required choice of a professional's lookup: the one the request
/// kept once a lookup declared it, checked when it is the one shown, and
/// nothing when the server lists none (`docs/architecture.md` §13.6 item 4).
fn purpose_choice(state: &AppState, locale: &Locale, pending: &Pending) -> Html {
    let Some(purposes) = state.settings().purposes.get(&pending.audience) else {
        return Html::empty();
    };
    let kept = pending.purpose_of_use.as_deref();
    let shown: Vec<_> = purposes
        .codes
        .iter()
        .filter(|purpose| kept.is_none_or(|kept| kept == purpose.code))
        .collect();
    let checked = if shown.len() == 1 { " checked" } else { "" };
    let radios = Html::join(shown.iter().enumerate().map(|(index, purpose)| {
        let id = format!("purpose-{index}");
        let radio = Html::raw(format!(
            "<input type=\"radio\" id=\"{id}\" name=\"{field}\" value=\"{code}\" required{checked}>",
            field = crate::picker::purpose::FIELD,
            code = Html::text(&purpose.code),
        ));
        check(&id, purpose.display.clone(), radio)
    }));
    fieldset(locale.lookup(&*CATALOG, "picker-purpose"), radios)
}

/// Returns the picker page of `locale` with the catalog's title and intro of
/// `[title, intro]`, the form `search` and the `results` below it.
fn picker_card(
    state: &AppState,
    locale: &Locale,
    [title, intro]: [&str; 2],
    search: Html,
    results: Html,
) -> Response {
    let words = |id: &str| locale.lookup(&*CATALOG, id);
    let intro = words(intro);
    let body = Html::join([
        Html::raw(format!("<p>{}</p>", Html::text(&intro))),
        search,
        results,
    ]);
    let lockup = brand_lockup(state, locale);
    let title = words(title);
    let page = page_card(Some(lockup), title.clone(), body);
    respond(
        state,
        StatusCode::OK,
        locale,
        title,
        page,
        Sources::default(),
    )
}

/// Returns the picker page of `pending` at an openEHR resource server.
///
/// The form asks for the patient's identifier; `looked_up` is the
/// identifier a lookup ran for and the EHR it found, `None` when the server
/// holds none the person may see.
#[must_use]
pub fn ehr_picker(
    state: &AppState,
    headers: &HeaderMap,
    pending: &Pending,
    looked_up: Option<(&str, Option<&crate::picker::openehr::FoundEhr>)>,
) -> Response {
    let asked = looked_up.map(|(asked, _)| asked);
    let locale = negotiated(headers, pending);
    let words = |id: &str| locale.lookup(&*CATALOG, id);
    let action = state.settings().endpoint(crate::picker::PICKER_ROUTE);
    let input = Html::raw(format!(
        "<input type=\"search\" id=\"subject_id\" name=\"subject_id\" value=\"{}\" class=\"fui-input\" required>",
        Html::text(asked.unwrap_or_default())
    ));
    let search = Html::raw(format!(
        "<form method=\"get\" action=\"{action}\" role=\"search\" class=\"fui-stack\">{purpose}{subject}\
         <div class=\"fui-cluster\"><button type=\"submit\" class=\"{primary}\">{label}</button></div></form>",
        action = Html::text(&action),
        purpose = purpose_choice(state, &locale, pending),
        subject = field("subject_id", words("picker-identifier"), None, input),
        primary = Variant::Primary.class(),
        label = label(Some(Glyph::SEARCH), words("picker-search")),
    ));
    let results = match looked_up {
        None => Html::empty(),
        Some((_, None)) => Html::raw(format!("<p>{}</p>", Html::text(words("picker-ehr-none")))),
        Some((_, Some(ehr))) => {
            let radio = Html::raw(format!(
                "<input type=\"radio\" id=\"ehr-0\" name=\"ehr_id\" value=\"{}\" required checked>",
                Html::text(&ehr.ehr_id)
            ));
            let mut words_of = vec![ehr.subject_id.clone()];
            if let Some(created) = &ehr.time_created {
                words_of.push(locale.lookup_with(
                    &*CATALOG,
                    "picker-ehr-created",
                    &[("date", Arg::from(created.as_str()))],
                ));
            }
            Html::raw(format!(
                "<form method=\"post\" action=\"{action}\" class=\"fui-stack\">\
                 <input type=\"hidden\" name=\"form_token\" value=\"{token}\">\
                 <input type=\"hidden\" name=\"subject_id\" value=\"{subject}\">{fields}\
                 <div class=\"fui-cluster\"><button type=\"submit\" class=\"{primary}\">{choose}</button></div></form>",
                action = Html::text(&action),
                token = Html::text(&pending.form_token),
                subject = Html::text(&ehr.subject_id),
                fields = fieldset(
                    words("picker-ehr-results"),
                    check("ehr-0", words_of.join(", "), radio)
                ),
                primary = Variant::Primary.class(),
                choose = label(Some(Glyph::CHECK), words("picker-choose")),
            ))
        }
    };
    picker_card(
        state,
        &locale,
        ["picker-title", "picker-ehr-intro"],
        search,
        results,
    )
}

/// An app the person remembered a consent for or that holds live access
/// to their data, as the management page lists it.
#[derive(Debug, Clone)]
pub struct Remembered {
    /// The client.
    pub client_id: String,
    /// Its name.
    pub name: String,
    /// The scopes given.
    pub scope: String,
    /// The refresh access the app holds now, if any: how long it may reach
    /// the person's data without them.
    pub access: Option<crate::store::grant::Access>,
    /// Whether the app holds its access on the organisation's approval,
    /// which disconnecting leaves in place: only an administrator
    /// withdraws it (`docs/architecture.md` §13.6 item 6).
    pub organisation: bool,
    /// Whether that approval is of the organisation's own (first-party)
    /// app, which the page names as such.
    pub first_party: bool,
}

/// Returns the management page of `pending`'s person, listing `remembered`
/// with a Disconnect form each, an app the organisation approved marked as
/// such, and the person's own FerroSMART subject.
///
/// It is the `management_endpoint`, a "URL where an end-user can view which
/// applications currently have access to data and can make adjustments to
/// these access rights" (SMART App Launch 2.2.0, Conformance, Metadata).
pub fn manage(
    state: &AppState,
    headers: &HeaderMap,
    pending: &Pending,
    remembered: &[Remembered],
) -> Response {
    let locale = negotiated(headers, pending);
    let words = |id: &str| locale.lookup(&*CATALOG, id);
    let action = state.settings().endpoint(MANAGE_ROUTE);
    let rows = if remembered.is_empty() {
        Html::raw(format!("<p>{}</p>", Html::text(words("manage-none"))))
    } else {
        Html::join(remembered.iter().map(|each| {
            let scopes: Vec<&str> = each
                .scope
                .split(' ')
                .filter(|scope| !scope.is_empty())
                .collect();
            let organisation = if each.organisation {
                let words_id = if each.first_party {
                    "manage-first-party"
                } else {
                    "manage-organisation"
                };
                Html::raw(format!("<p>{}</p>", Html::text(words(words_id))))
            } else {
                Html::empty()
            };
            // NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, offline_access lasts
            // "as long as the authorization server and end-user will allow": every app has the form.
            let form = Html::raw(format!(
                "<form method=\"post\" action=\"{action}\">\
                 <input type=\"hidden\" name=\"form_token\" value=\"{token}\">\
                 <input type=\"hidden\" name=\"client_id\" value=\"{client}\">\
                 <button type=\"submit\" class=\"{danger}\">{disconnect}</button></form>",
                action = Html::text(&action),
                token = Html::text(&pending.form_token),
                client = Html::text(&each.client_id),
                danger = Variant::Danger.class(),
                disconnect = label(None, words("manage-disconnect")),
            ));
            let access = match each.access {
                Some(crate::store::grant::Access::Offline) => {
                    Html::raw(format!("<p>{}</p>", Html::text(words("manage-offline"))))
                }
                Some(crate::store::grant::Access::Online) => {
                    Html::raw(format!("<p>{}</p>", Html::text(words("manage-online"))))
                }
                None => Html::empty(),
            };
            card(
                each.name.clone(),
                Html::join([
                    access,
                    organisation,
                    scope_list(&locale, &words("manage-scope"), &scopes),
                    form,
                ]),
            )
        }))
    };
    // NOTE: docs/architecture.md §13.6 item 9, the person's own pairwise sub, which
    // an administrator binds them by at a resource server (#733).
    let subject = pending
        .subject
        .as_deref()
        .map_or_else(Html::empty, |subject| {
            Html::raw(format!(
                "<p>{}</p><p><code>{}</code></p>",
                Html::text(words("manage-subject")),
                Html::text(subject)
            ))
        });
    let body = Html::join([
        Html::raw(format!("<p>{}</p>", Html::text(words("manage-intro")))),
        rows,
        subject,
    ]);
    let title = words("manage-title");
    let lockup = brand_lockup(state, &locale);
    let page = page_card(Some(lockup), title.clone(), body);
    respond(
        state,
        StatusCode::OK,
        &locale,
        title,
        page,
        Sources::default(),
    )
}

/// Returns the list of `scopes` named `label` in `locale`: each SMART scope
/// as FerroUI reads it, and after them, in plain words, the extension
/// scopes, which are the server's own and no SMART grammar reads (SMART App
/// Launch 2.2.0, Scopes and Launch Context, Extensibility).
fn scope_list(locale: &Locale, label: &str, scopes: &[&str]) -> Html {
    let (extensions, smart): (Vec<&str>, Vec<&str>) = scopes
        .iter()
        .partition(|scope| crate::scopes::is_extension(scope));
    let grants: Vec<ScopeGrant> = smart
        .iter()
        .map(|scope| {
            ScopeGrant::read(locale, *scope, |read| {
                (resource_words(locale, &read.resource), read.resource == "*")
            })
        })
        .collect();
    let named = if extensions.is_empty() {
        Html::empty()
    } else {
        let words = locale.lookup_with(
            &*CATALOG,
            "scope-extension",
            &[("scopes", Arg::from(extensions.join(", ")))],
        );
        Html::raw(format!("<p>{}</p>", Html::text(words)))
    };
    Html::join([scope_grants(locale, label, grants), named])
}

/// Returns the plain words for the FHIR resource type `resource` in
/// `locale`, with the type itself after them, or the type alone when the
/// catalog has no words for it.
///
/// SMART App Launch 2.2.0, Best Practices, Considerations for Scope Consent
/// asks the authorization server to avoid jargon such as "Encounters"; the
/// words are our own.
fn resource_words(locale: &Locale, resource: &str) -> String {
    use fluent_templates::Loader as _;
    let id = format!("resource-{}", resource.to_ascii_lowercase());
    // NOTE: a tag that does not parse, or a type the catalog lacks, has no plain words.
    locale
        .tag()
        .parse::<fluent_templates::LanguageIdentifier>()
        .ok()
        .and_then(|language| CATALOG.try_lookup(&language, &id))
        .map_or_else(
            || resource.to_owned(),
            |words| format!("{words} ({resource})"),
        )
}

/// Returns the locale the request's `ui_locales`, then its
/// `Accept-Language`, prefer among the catalog's, English when none matches.
fn negotiated(headers: &HeaderMap, pending: &Pending) -> Locale {
    let accept = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    // NOTE: OpenID Connect Core 1.0 §3.1.2.1: ui_locales names the languages wanted,
    // most preferred first, so they go before the browser's own.
    let wanted = pending
        .asking
        .ui_locales
        .as_deref()
        .unwrap_or_default()
        .split(' ')
        .filter(|tag| !tag.is_empty())
        .chain(std::iter::once(accept).filter(|accept| !accept.is_empty()))
        .collect::<Vec<_>>()
        .join(", ");
    Locale::negotiate_with(&wanted, &*CATALOG, Locale::default()).with_catalog(&*CATALOG)
}

/// Returns the languages the pages are drawn in, as BCP 47 tags: the
/// catalog's (OpenID Connect Discovery 1.0 §3, `ui_locales_supported`).
#[must_use]
pub fn ui_locales() -> Vec<String> {
    use fluent_templates::Loader as _;
    let mut tags: Vec<String> = CATALOG.locales().map(ToString::to_string).collect();
    tags.sort();
    tags
}

/// Returns `content` as a whole document in the centred layout, with the
/// headers every page carries.
fn respond(
    state: &AppState,
    status: StatusCode,
    locale: &Locale,
    title: String,
    content: Html,
    sources: Sources<'_>,
) -> Response {
    let footer = Footer {
        product: "FerroSMART".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        about: state.settings().endpoint("/").into(),
    };
    let html = document(Document {
        locale: locale.clone(),
        preferences: Preferences::default(),
        title,
        assets: Assets::of(Brand::Smart),
        nonce: None,
        head: Html::empty(),
        body: centred(locale, content, Html::empty(), footer),
    });
    let mut response = (status, axum::response::Html(String::from(html))).into_response();
    let mut form_action = String::from("'self'");
    for origin in sources.form {
        form_action.push(' ');
        form_action.push_str(origin);
    }
    let mut img_src = String::from("'self'");
    for origin in sources.img {
        img_src.push(' ');
        img_src.push_str(origin);
    }
    let policy = format!(
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src {img_src}; \
         font-src 'self'; form-action {form_action}; frame-ancestors 'none'; base-uri 'none'"
    );
    let headers = response.headers_mut();
    page_headers(headers, &policy);
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

/// Sets the headers every page FerroSMART draws carries: the content
/// security `policy`, never cached, no referrer, no sniffing.
pub(crate) fn page_headers(headers: &mut HeaderMap, policy: &str) {
    if let Ok(policy) = HeaderValue::from_str(policy) {
        headers.insert(header::CONTENT_SECURITY_POLICY, policy);
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
}
