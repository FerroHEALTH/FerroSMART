// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! FerroSMART served on a loopback port for the browser, with a stub
//! upstream provider, a stub FHIR server of synthetic patients and its own
//! database schema, and the launches that bring each page about.
//!
//! The login at the provider is driven through the router itself, as the
//! authorization cases drive it, and the browser is handed the cookie the
//! launch set: the provider's own sign-in page belongs to the provider and
//! is never captured.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use ferrosmart::server::{AppState, router};
use ferrosmart::store::Store;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

use crate::authorize::{
    CHALLENGE, Provider, UPSTREAM_CLIENT, VERIFIER, form_token, location, param, set_cookie,
};
use crate::support::{ASSURANCE, Database, Keys, audit, config, from_client};

/// The clinician app's redirect URI.
const WARD_REDIRECT: &str = "https://ward.example.org/callback";

/// The patient app's redirect URI.
const CHART_REDIRECT: &str = "https://chart.example.org/callback";

/// The person every launch logs in as.
const CLINICIAN: (&str, &str) = ("synthetic-clinician", "Practitioner/synthetic-1");

/// The synthetic patients the FHIR stub holds: id, given, family, birth
/// date and record number.
const PATIENTS: [(&str, &str, &str, &str, &str); 3] = [
    ("p-1", "Sam", "Example", "1970-01-01", "MRN-1001"),
    ("p-2", "Samira", "Example", "1985-06-15", "MRN-1002"),
    ("p-3", "Samuel", "Exampleton", "2001-11-30", "MRN-1003"),
];

/// A FHIR server of the synthetic [`PATIENTS`]: every search answers them
/// all, and a read answers the one it names.
struct Patients;

impl wiremock::Respond for Patients {
    fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
        let resource = |(id, given, family, born, record): (&str, &str, &str, &str, &str)| {
            json!({
                "resourceType": "Patient", "id": id,
                "name": [{ "given": [given], "family": family }],
                "birthDate": born, "gender": "other",
                "identifier": [{ "system": "urn:example:mrn", "value": record }]
            })
        };
        let path = request.url.path();
        if let Some(patient) = PATIENTS
            .iter()
            .find(|patient| path.ends_with(&format!("/Patient/{}", patient.0)))
        {
            return ResponseTemplate::new(200).set_body_json(resource(*patient));
        }
        let entry: Vec<Value> = PATIENTS
            .iter()
            .map(|patient| json!({ "resource": resource(*patient) }))
            .collect();
        ResponseTemplate::new(200)
            .set_body_json(json!({ "resourceType": "Bundle", "type": "searchset", "entry": entry }))
    }
}

/// FerroSMART on a loopback port, with what it reaches.
pub(crate) struct Stack {
    /// The issuer, which is the address the browser loads.
    issuer: String,
    /// The application, which the launches drive.
    app: Router,
    /// The upstream provider of the staff.
    provider: Provider,
    /// The upstream provider of the patients, kept for the stack's length.
    _portal: Provider,
    /// The FHIR server.
    _fhir: MockServer,
    /// The FHIR base, the audience of every launch.
    base: String,
    /// The store.
    store: Store,
    /// The database.
    database: Database,
    /// The keys, kept for the stack's length.
    _keys: Keys,
    /// The server the browser reaches.
    served: tokio::task::JoinHandle<()>,
}

impl Stack {
    /// Starts the stack: a deployment named Example Hospital with a
    /// clinician app and a patient app.
    pub(crate) async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let issuer = format!(
            "http://{}",
            listener.local_addr().expect("the port it bound")
        );
        let provider = Provider::start().await;
        let portal = Provider::start().await;
        let fhir = MockServer::start().await;
        Mock::given(matchers::method("GET"))
            .respond_with(Patients)
            .mount(&fhir)
            .await;
        let base = format!("{}/fhir", fhir.uri());
        let keys = Keys::new();
        let database = Database::create().await;
        let assertion = crate::support::upstream_assertion(keys.dir.path());
        let text = format!(
            "[ferrosmart]\nissuer = {issuer:?}\n[ferrosmart.database]\nurl = {:?}\n\
             [[ferrosmart.upstream]]\nname = \"idp\"\nlabel = \"Hospital staff\"\n\
             [ferrosmart.upstream.oidc]\nissuer = {:?}\nclient_id = {UPSTREAM_CLIENT:?}\n\
             fhir_user_claim = \"fhir_user\"\n{assertion}{ASSURANCE}\
             [[ferrosmart.upstream]]\nname = \"portal\"\nlabel = \"Patient portal\"\n\
             [ferrosmart.upstream.oidc]\nissuer = {:?}\nclient_id = {UPSTREAM_CLIENT:?}\n\
             fhir_user_claim = \"fhir_user\"\n{assertion}{ASSURANCE}\
             [ferrosmart.branding]\nname = \"Example Hospital\"\n\
             consent_text = \"Example Hospital records every access to your record.\"\n\
             [[ferrosmart.resource]]\nbase = {base:?}\n\
             [[ferrosmart.role]]\nname = \"clinician\"\n\
             scopes = [\"user/Observation.rs\", \"user/Patient.rs\", \"patient/Observation.rs\"]\n\
             [[client]]\nclient_id = \"ward-overview\"\nclient_name = \"Ward Overview\"\ntoken_endpoint_auth_method = \"none\"\n\
             redirect_uris = [{WARD_REDIRECT:?}]\ngrant_types = [\"authorization_code\", \"refresh_token\"]\n\
             scope = [\"openid\", \"fhirUser\", \"user/Observation.rs\", \"user/Patient.rs\", \"offline_access\"]\n\
             upstreams = [\"idp\"]\n\
             [[client]]\nclient_id = \"growth-chart\"\nclient_name = \"Growth Chart\"\ntoken_endpoint_auth_method = \"none\"\n\
             redirect_uris = [{CHART_REDIRECT:?}]\ngrant_types = [\"authorization_code\"]\n\
             scope = [\"openid\", \"fhirUser\", \"launch/patient\", \"patient/Observation.rs\"]\n\
             upstreams = [\"idp\"]\n\
             [[client]]\nclient_id = \"my-record\"\nclient_name = \"My Record\"\ntoken_endpoint_auth_method = \"none\"\n\
             redirect_uris = [{WARD_REDIRECT:?}]\ngrant_types = [\"authorization_code\"]\n\
             scope = [\"openid\", \"fhirUser\", \"launch/patient\", \"patient/Observation.rs\"]",
            secrecy::ExposeSecret::expose_secret(&database.url),
            provider.server.uri(),
            portal.server.uri()
        );
        let settings = config(&crate::support::reach_every_base(&text), &keys)
            .resolve()
            .expect("resolves");
        let store = Store::connect(&settings.database_url, 4)
            .await
            .expect("connects");
        store.migrate().await.expect("migrates");
        let providers = crate::support::providers(&settings).await;
        let audit = audit(&settings);
        let state = AppState::new(settings, store.clone(), audit).with_login(providers);
        crate::support::apply(
            &state,
            &crate::support::clients(&crate::support::reach_every_base(&text)),
        )
        .await;
        let app = router(Arc::new(state));
        let served = tokio::spawn({
            let app = app.clone();
            async move {
                let service = app.into_make_service_with_connect_info::<SocketAddr>();
                axum::serve(listener, service)
                    .await
                    .expect("the server runs");
            }
        });
        Self {
            issuer,
            app,
            provider,
            _portal: portal,
            _fhir: fhir,
            base,
            store,
            database,
            _keys: keys,
            served,
        }
    }

    /// Returns the address of `path` the browser loads.
    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}{path}", self.issuer)
    }

    /// Sends `request` through the router as the browser would.
    async fn send(&self, request: Request<Body>) -> (StatusCode, http::HeaderMap, String) {
        let response = self
            .app
            .clone()
            .oneshot(from_client(request))
            .await
            .expect("an answer");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("the body")
            .to_bytes();
        (
            status,
            headers,
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    }

    /// Gets `path` with the cookie `cookie`, if any.
    async fn get(&self, path: &str, cookie: Option<&str>) -> (StatusCode, http::HeaderMap, String) {
        let mut request = Request::get(path);
        if let Some(cookie) = cookie {
            request = request.header(
                header::COOKIE,
                format!("{}={cookie}", ferrosmart::authorize::COOKIE),
            );
        }
        self.send(request.body(Body::empty()).expect("a request"))
            .await
    }

    /// Posts the form `pairs` to `path` with the cookie `cookie`.
    async fn post(
        &self,
        path: &str,
        pairs: &[(&str, &str)],
        cookie: &str,
    ) -> (StatusCode, http::HeaderMap, String) {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        let request = Request::post(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ORIGIN, &self.issuer)
            .header(
                header::COOKIE,
                format!("{}={cookie}", ferrosmart::authorize::COOKIE),
            )
            .body(Body::from(body))
            .expect("a request");
        self.send(request).await
    }

    /// Returns the authorization request of `client` for `scope` at the
    /// FHIR base.
    pub(crate) fn authorize_path(&self, client: &str, scope: &str) -> String {
        let redirect = if client == "growth-chart" {
            CHART_REDIRECT
        } else {
            WARD_REDIRECT
        };
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("response_type", "code"),
                ("client_id", client),
                ("redirect_uri", redirect),
                ("scope", scope),
                ("state", "synthetic-state"),
                ("aud", self.base.as_str()),
                ("code_challenge", CHALLENGE),
                ("code_challenge_method", "S256"),
            ])
            .finish();
        format!("/authorize?{query}")
    }

    /// Visits `path`, logs the clinician in at the provider, and returns
    /// the cookie and the path the callback sends the browser on to.
    async fn log_in(&self, path: &str) -> (String, String) {
        let (status, headers, page) = self.get(path, None).await;
        assert_eq!(StatusCode::SEE_OTHER, status, "{path}: {page}");
        let mut upstream = location(&headers);
        let cookie = set_cookie(&headers);
        // NOTE: the management page may use either provider, so the clinician
        // chooses the staff's on the chooser first.
        if upstream.path() == "/login" {
            let (_, _, page) = self.get("/login", Some(&cookie)).await;
            let token = form_token(&page);
            let (status, headers, page) = self
                .post(
                    "/login",
                    &[("form_token", token.as_str()), ("provider", "idp")],
                    &cookie,
                )
                .await;
            assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
            upstream = location(&headers);
        }
        let (subject, fhir_user) = CLINICIAN;
        self.provider
            .answer_as(
                &param(&upstream, "nonce").expect("a nonce"),
                &["clinician"],
                subject,
                fhir_user,
            )
            .await;
        let callback = format!(
            "/callback?code=synthetic-upstream-code&state={}",
            param(&upstream, "state").expect("a state")
        );
        let (status, headers, page) = self.get(&callback, Some(&cookie)).await;
        assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
        (cookie, location(&headers).path().to_owned())
    }

    /// Brings the chooser of an app whose people log in at either provider
    /// about and returns its cookie.
    pub(crate) async fn chooser(&self) -> String {
        let path = self.authorize_path("my-record", "openid fhirUser launch/patient");
        let (status, headers, page) = self.get(&path, None).await;
        assert_eq!(StatusCode::SEE_OTHER, status, "{path}: {page}");
        assert_eq!("/login", location(&headers).path(), "to the chooser");
        set_cookie(&headers)
    }

    /// Brings the clinician app's consent page about and returns its cookie.
    pub(crate) async fn clinician_consent(&self) -> String {
        let path = self.authorize_path(
            "ward-overview",
            "openid fhirUser user/Observation.rs user/Patient.rs offline_access",
        );
        let (cookie, next) = self.log_in(&path).await;
        assert_eq!("/consent", next, "to the consent page");
        cookie
    }

    /// Brings the patient app's patient picker about and returns its cookie.
    pub(crate) async fn picker(&self) -> String {
        let path = self.authorize_path(
            "growth-chart",
            "openid fhirUser launch/patient patient/Observation.rs",
        );
        let (cookie, next) = self.log_in(&path).await;
        assert_eq!("/picker", next, "to the patient picker");
        cookie
    }

    /// Brings the patient app's consent page about, with the first patient
    /// picked, and returns its cookie.
    pub(crate) async fn patient_consent(&self) -> String {
        let cookie = self.picker().await;
        let (status, _, page) = self.get("/picker?name=Example", Some(&cookie)).await;
        assert_eq!(StatusCode::OK, status, "{page}");
        let token = form_token(&page);
        let (status, headers, page) = self
            .post(
                "/picker",
                &[("form_token", token.as_str()), ("patient", PATIENTS[0].0)],
                &cookie,
            )
            .await;
        assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
        assert_eq!("/consent", location(&headers).path(), "to the consent page");
        cookie
    }

    /// Approves a launch of the clinician app with offline access and
    /// redeems its code, then logs in to the management page and returns
    /// its cookie.
    pub(crate) async fn manage(&self) -> String {
        let cookie = self.clinician_consent().await;
        let (_, _, page) = self.get("/consent", Some(&cookie)).await;
        let token = form_token(&page);
        let mut pairs = vec![("form_token", token.as_str()), ("decision", "approve")];
        for scope in [
            "openid",
            "fhirUser",
            "user/Observation.rs",
            "user/Patient.rs",
            "offline_access",
        ] {
            pairs.push(("scope", scope));
        }
        let (status, headers, page) = self.post("/consent", &pairs, &cookie).await;
        assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
        let code = param(&location(&headers), "code").expect("a code");
        let exchange = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", WARD_REDIRECT),
                ("code_verifier", VERIFIER),
                ("client_id", "ward-overview"),
            ])
            .finish();
        let request = Request::post("/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(exchange))
            .expect("a request");
        let (status, _, body) = self.send(request).await;
        assert_eq!(StatusCode::OK, status, "the code is redeemed: {body}");
        let (cookie, next) = self.log_in("/manage").await;
        assert_eq!("/manage", next, "to the management page");
        cookie
    }

    /// Returns the callback of a login the browser did not begin: a real
    /// upstream `state`, reached without the request's cookie.
    pub(crate) async fn other_browser(&self) -> String {
        let path = self.authorize_path("ward-overview", "openid fhirUser user/Observation.rs");
        let (_, headers, _) = self.get(&path, None).await;
        let upstream = location(&headers);
        format!(
            "/callback?code=synthetic-upstream-code&state={}",
            param(&upstream, "state").expect("a state")
        )
    }

    /// Stops the server and drops the database.
    pub(crate) async fn stop(self) {
        self.served.abort();
        self.database.drop(self.store).await;
    }
}
