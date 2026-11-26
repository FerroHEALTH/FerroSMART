// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A synthetic console over the crate: its pages, its router, and a browser
//! that keeps the cookies it is handed.

use std::collections::BTreeMap;
use std::future::Future;

use axum::Router;
use axum::body::Body;
use axum::extract::{Extension, State};
use axum::response::{IntoResponse as _, Response};
use axum::routing::get;
use ferrohealth_secret::secret::Secret;
use ferrohealth_secret::secret_url::SecretUrl;
use ferrohealth_session::config::{OidcSection, SessionSection};
use ferrohealth_session::cookies::CookieNames;
use ferrohealth_session::record::{Credential, Held};
use ferrohealth_session::resource::ForResource;
use ferrohealth_session::routes::{Pages, SignIn, Stopped, keep_session, router};
use ferrohealth_session::sessions::Sessions;
use http::header::{COOKIE, LOCATION, SET_COOKIE};
use http::request::Parts;
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

use crate::provider::{CLIENT, Provider, REDIRECT, SECRET};

/// The words the test console gives a session that is gone.
pub(crate) const GONE: &str = "Synthetic session gone";

/// The console's pages: a stopped sign-in answers its status and the name
/// of why it stopped.
#[derive(Debug, Clone)]
pub(crate) struct TestPages;

impl Pages for TestPages {
    fn stopped(&self, _parts: Parts, why: Stopped) -> impl Future<Output = Response> + Send {
        let name = format!("{why:?}");
        let name = name.split('(').next().unwrap_or_default().to_owned();
        std::future::ready((why.status(), name).into_response())
    }

    fn sign_in_page(&self) -> &'static str {
        "/sign-in"
    }

    fn signed_out(&self) -> &'static str {
        "/signed-out"
    }

    fn session_gone(&self, _parts: &Parts) -> String {
        String::from(GONE)
    }

    fn home(&self) -> &'static str {
        "/"
    }
}

/// What the console's home page says the request holds.
async fn home(Extension(held): Extension<Held>) -> String {
    match held {
        Held::SignedIn(session) => match session.credential() {
            Credential::Bearer(token) => {
                format!(
                    "{} {}",
                    session.operator().unwrap_or_default(),
                    token.expose()
                )
            }
            Credential::Basic { username, .. } => username.clone(),
        },
        other => format!("{other:?}"),
    }
}

/// The resource server the console asks a second token for.
pub(crate) const RESOURCE: &str = "https://ehr.example.org/fhir";

/// What the console's resource page says it got for [`RESOURCE`].
async fn resource(State(sign_in): State<SignIn<TestPages>>, headers: http::HeaderMap) -> String {
    let party = sign_in.party().expect("a provider");
    match sign_in
        .sessions()
        .token_for(party, &headers, RESOURCE)
        .await
        .expect("the store is usable")
    {
        ForResource::Issued(token) => format!("Issued {}", token.expose()),
        other => {
            let name = format!("{other:?}");
            name.split('(').next().unwrap_or_default().to_owned()
        }
    }
}

/// A console signed in at `provider`.
pub(crate) async fn console(provider: &Provider) -> Router {
    console_of(sign_in(provider).await)
}

/// The sign-in of a console at `provider`.
pub(crate) async fn sign_in(provider: &Provider) -> SignIn<TestPages> {
    let oidc = OidcSection {
        issuer: SecretUrl::new(provider.uri()),
        client_id: String::from(CLIENT),
        client_secret: Some(Secret::new(SECRET)),
        redirect_uri: SecretUrl::new(REDIRECT),
        scopes: vec![String::from("openid"), String::from("profile")],
        ..OidcSection::default()
    }
    .check()
    .expect("a valid [oidc]");
    let settings = SessionSection::default()
        .check()
        .expect("a valid [session]");
    let party = oidc
        .relying_party()
        .await
        .expect("the provider is discovered");
    let sessions = Sessions::new(settings, CookieNames::for_console("synthetic_console"));
    SignIn::new(sessions, Some(party), TestPages)
}

/// The console of `sign_in`.
pub(crate) fn console_of(sign_in: SignIn<TestPages>) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/resource", get(resource).with_state(sign_in.clone()))
        .layer(axum::middleware::from_fn_with_state(
            sign_in.clone(),
            keep_session::<TestPages>,
        ))
        .merge(router(sign_in))
}

/// One answer, read whole.
#[derive(Debug)]
pub(crate) struct Answer {
    pub(crate) status: StatusCode,
    pub(crate) location: Option<String>,
    pub(crate) set_cookies: Vec<String>,
    pub(crate) cache: Option<String>,
    pub(crate) content_type: Option<String>,
    pub(crate) body: String,
}

/// A browser that keeps the cookies the console hands it.
#[derive(Debug, Default)]
pub(crate) struct Browser {
    pub(crate) jar: BTreeMap<String, String>,
}

impl Browser {
    /// Sends `method` to `path` with the cookies it holds.
    pub(crate) async fn send(&mut self, app: &Router, method: Method, path: &str) -> Answer {
        let cookies: Vec<String> = self
            .jar
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        let mut request = Request::builder().method(method).uri(path);
        if !cookies.is_empty() {
            request = request.header(COOKIE, cookies.join("; "));
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).expect("a request"))
            .await
            .expect("the router answers");
        let status = response.status();
        let header = |name| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let location = header(LOCATION);
        let cache = header(http::header::CACHE_CONTROL);
        let content_type = header(http::header::CONTENT_TYPE);
        let set_cookies: Vec<String> = response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(str::to_owned)
            .collect();
        for set in &set_cookies {
            let pair = set.split(';').next().unwrap_or_default();
            if let Some((name, value)) = pair.split_once('=') {
                if set.contains("Max-Age=0") {
                    self.jar.remove(name);
                } else {
                    self.jar.insert(name.to_owned(), value.to_owned());
                }
            }
        }
        let body = response
            .into_body()
            .collect()
            .await
            .expect("a body")
            .to_bytes();
        Answer {
            status,
            location,
            set_cookies,
            cache,
            content_type,
            body: String::from_utf8_lossy(&body).into_owned(),
        }
    }

    /// Keeps the session cookie `set`, a `Set-Cookie` value, and answers
    /// its name.
    pub(crate) fn keep(&mut self, set: &http::HeaderValue) -> String {
        let pair = set
            .to_str()
            .expect("text")
            .split(';')
            .next()
            .expect("a pair");
        let (name, value) = pair.split_once('=').expect("name=value");
        self.jar.insert(name.to_owned(), value.to_owned());
        name.to_owned()
    }

    /// `GET path`.
    pub(crate) async fn get(&mut self, app: &Router, path: &str) -> Answer {
        self.send(app, Method::GET, path).await
    }
}

/// The query of `url`, by name.
pub(crate) fn query(url: &str) -> BTreeMap<String, String> {
    url::Url::parse(url)
        .expect("a URL")
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}
