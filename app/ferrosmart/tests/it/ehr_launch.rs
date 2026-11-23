// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The EHR launch through the whole stack against a real PostgreSQL and a
//! stub upstream OpenID Provider: an EHR registers a launch at `POST
//! /launch`, the app passes it to `/authorize` with the `launch` scope, and
//! the token response carries the context (SMART App Launch 2.2.0, Launch
//! App: EHR Launch; Scopes and Launch Context, Launch context arrives with
//! your `access_token`; `docs/architecture.md` §13.6 items 2 and 3).

use std::sync::Arc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use axum::Router;
use axum::body::Body;
use ferrohealth_smart::client::assertion::AssertionKey;
use ferrosmart::authorize::COOKIE;
use ferrosmart::server::{AppState, router};
use ferrosmart::store::Store;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt as _;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use url::Url;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

use crate::support::{
    ASSURANCE, Database, Keys, RESOURCE, audit, bases, config, ec_key, from_client, records,
};

/// FerroSMART's issuer.
const ISSUER: &str = "https://smart.example.org";
/// The app's redirect URI.
const REDIRECT: &str = "https://app.example.org/callback";
/// The client FerroSMART is at the provider.
const UPSTREAM_CLIENT: &str = "ferrosmart";
/// The style document of `[ferrosmart.branding]`.
const STYLE: &str = "https://smart.example.org/smart-style.json";
/// The PKCE verifier of RFC 7636 Appendix B.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// Its `S256` challenge.
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// The assertion type of RFC 7523 §2.2.
const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// The scope the app asks for.
const SCOPE: &str =
    "openid fhirUser launch launch/patient patient/Observation.rs user/Observation.rs";

/// FerroSMART with a login upstream, an EHR client `ehr` and the app `app`.
struct Smart {
    /// The application.
    app: Router,
    /// The provider.
    provider: MockServer,
    /// The provider's signing key.
    provider_key: EncodingKey,
    /// The EHR's signing key.
    ehr: AssertionKey,
    /// The store.
    store: Store,
    /// The database.
    database: Database,
    /// The keys, kept for the case's length.
    _keys: Keys,
}

impl Smart {
    /// Starts FerroSMART.
    async fn start() -> Self {
        Self::start_approved("").await
    }

    /// Starts FerroSMART whose app's table ends with `approval`, TOML that
    /// may give it an organisation approval.
    async fn start_approved(approval: &str) -> Self {
        let provider = MockServer::start().await;
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .expect("a key pair");
        let provider_key = EncodingKey::from_ec_der(pkcs8.as_ref());
        let mut jwk = serde_json::to_value(
            Jwk::from_encoding_key(&provider_key, Algorithm::ES256).expect("a JWK"),
        )
        .expect("serializes");
        if let Some(members) = jwk.as_object_mut() {
            members.insert(String::from("kid"), json!("op-1"));
        }
        let uri = provider.uri();
        Mock::given(matchers::path("/.well-known/oauth-authorization-server"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": uri, "authorization_endpoint": format!("{uri}/authorize"),
                "token_endpoint": format!("{uri}/token"), "jwks_uri": format!("{uri}/jwks"),
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["private_key_jwt", "client_secret_basic"]
            })))
            .mount(&provider)
            .await;
        Mock::given(matchers::path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
            .mount(&provider)
            .await;

        let keys = Keys::new();
        let pem = std::fs::read(ec_key(keys.dir.path(), "ehr.pem")).expect("the key reads");
        let ehr = AssertionKey::from_pem(&pem, Some(Algorithm::ES384), Some(String::from("ehr-1")))
            .expect("a key");
        let set = keys.dir.path().join("ehr-jwks.json");
        std::fs::write(&set, json!({"keys": [ehr.public_jwk()]}).to_string()).expect("written");
        let database = Database::create().await;
        let assertion = crate::support::upstream_assertion(keys.dir.path());
        let text = format!(
            "[ferrosmart]\nissuer = {ISSUER:?}\n[ferrosmart.database]\nurl = {:?}\n\
             [[ferrosmart.upstream]]\nname = \"idp\"\n[ferrosmart.upstream.oidc]\nissuer = {uri:?}\nclient_id = {UPSTREAM_CLIENT:?}\nfhir_user_claim = \"fhir_user\"\n{assertion}{ASSURANCE}\
             [ferrosmart.branding]\nsmart_style_url = {STYLE:?}\n\
             [[ferrosmart.role]]\nname = \"clinician\"\nscopes = [\"user/Observation.rs\", \"patient/Observation.rs\"]\n\
             [[ferrosmart.client]]\nclient_id = \"ehr\"\nkind = \"confidential_asymmetric\"\n\
             jwks_file = {:?}\nscopes = [\"system/launch.c\"]\ngrant_types = [\"client_credentials\"]\n\
             [[ferrosmart.client]]\nclient_id = \"app\"\nname = \"Synthetic App\"\nkind = \"public\"\n\
             redirect_uris = [{REDIRECT:?}]\ngrant_types = [\"authorization_code\"]\n\
             scopes = [\"openid\", \"fhirUser\", \"launch\", \"launch/patient\", \"patient/Observation.rs\", \"user/Observation.rs\"]\n\
             {approval}",
            secrecy::ExposeSecret::expose_secret(&database.url),
            set.display().to_string(),
        );
        let settings = config(&crate::support::reach_every_base(&text), &keys)
            .resolve()
            .expect("resolves");
        let store = Store::connect(&settings.database_url, 2)
            .await
            .expect("connects");
        store.migrate().await.expect("migrates");
        store.register(&settings.clients).await.expect("registered");
        let providers = crate::support::providers(&settings).await;
        let audit = audit(&settings);
        let state = AppState::new(settings, store.clone(), audit).with_login(providers);
        Self {
            app: router(Arc::new(state)),
            provider,
            provider_key,
            ehr,
            store,
            database,
            _keys: keys,
        }
    }

    /// Mounts the provider's code exchange for one login carrying `nonce`.
    async fn answer(&self, nonce: &str) {
        self.answer_as(nonce, "Practitioner/synthetic-1").await;
    }

    /// Has the provider answer the next code with an ID Token for the
    /// sign-in `nonce` of the person whose `fhirUser` is `fhir_user`.
    async fn answer_as(&self, nonce: &str, fhir_user: &str) {
        let now = jiff::Timestamp::now().as_second();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(String::from("op-1"));
        let id_token = jsonwebtoken::encode(
            &header,
            &json!({
                "iss": self.provider.uri(), "aud": UPSTREAM_CLIENT, "sub": "synthetic-person",
                "nonce": nonce, "iat": now, "exp": now + 300, "name": "Synthetic Clinician",
                "acr": crate::support::SUBSTANTIAL_ACR,
                "roles": ["clinician"], "fhir_user": fhir_user
            }),
            &self.provider_key,
        )
        .expect("signs");
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "synthetic-upstream-token", "token_type": "Bearer",
                "expires_in": 300, "id_token": id_token
            })))
            .up_to_n_times(1)
            .mount(&self.provider)
            .await;
    }

    /// Sends `request` and returns the status, the headers and the body.
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

    /// Gets `path` with the request cookie, if any.
    async fn get(&self, path: &str, cookie: Option<&str>) -> (StatusCode, http::HeaderMap, String) {
        let mut request = Request::get(path);
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, format!("{COOKIE}={cookie}"));
        }
        self.send(request.body(Body::empty()).expect("a request"))
            .await
    }

    /// Posts the form `pairs` to `path` with the cookie, if any.
    async fn post(
        &self,
        path: &str,
        pairs: &[(&str, &str)],
        cookie: Option<&str>,
    ) -> (StatusCode, http::HeaderMap, String) {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        let mut request =
            Request::post(path).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, format!("{COOKIE}={cookie}"));
        }
        self.send(request.body(Body::from(body)).expect("a request"))
            .await
    }

    /// Registers a launch of patient `123` in encounter `456` for `app` and
    /// returns its value.
    async fn launch(&self) -> String {
        self.launch_with(&[]).await
    }

    /// Registers the launch of [`Smart::launch`] with the further
    /// parameters `more`, and returns its value.
    async fn launch_with(&self, more: &[(&str, &str)]) -> String {
        let now = jiff::Timestamp::now().as_second();
        let mut bytes = [0_u8; 12];
        aws_lc_rs::rand::fill(&mut bytes).expect("draws");
        let jti = bytes.iter().fold(String::new(), |mut id, byte| {
            use std::fmt::Write as _;
            write!(id, "{byte:02x}").expect("a String takes every write");
            id
        });
        let assertion = self
            .ehr
            .sign(
                "JWT",
                &json!({"iss": "ehr", "sub": "ehr", "aud": format!("{ISSUER}/token"), "exp": now + 120, "jti": jti}),
            )
            .expect("signs");
        let (status, _, body) = self
            .post(
                "/launch",
                &[
                    ("client_assertion_type", JWT_BEARER),
                    ("client_assertion", &assertion),
                    ("app_client_id", "app"),
                    ("resource", RESOURCE),
                    ("patient", "123"),
                    ("encounter", "456"),
                    ("need_patient_banner", "false"),
                    ("fhirContext", r#"[{"reference":"DiagnosticReport/7"}]"#),
                ]
                .into_iter()
                .chain(more.iter().copied())
                .collect::<Vec<_>>(),
                None,
            )
            .await;
        assert_eq!(StatusCode::CREATED, status, "{body}");
        let body: Value = serde_json::from_str(&body).expect("JSON");
        body.get("launch")
            .and_then(Value::as_str)
            .expect("a launch value")
            .to_owned()
    }

    /// Drops the database.
    async fn stop(self) {
        self.database.drop(self.store).await;
    }
}

/// Returns the authorization request carrying `launch` and `scope`.
fn authorize_path(launch: &str, scope: &str) -> String {
    let pairs = [
        ("response_type", "code"),
        ("client_id", "app"),
        ("redirect_uri", REDIRECT),
        ("scope", scope),
        ("state", "synthetic-state"),
        ("aud", RESOURCE),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("launch", launch),
    ];
    format!(
        "/authorize?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish()
    )
}

/// Returns the location of a `303`, parsed.
fn location(headers: &http::HeaderMap) -> Url {
    let location = headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("a location");
    Url::parse(location).unwrap_or_else(|_relative| {
        Url::parse(ISSUER)
            .expect("a URL")
            .join(location)
            .expect("a URL")
    })
}

/// Returns the query parameter `name` of `url`.
fn param(url: &Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// Runs the EHR launch `launch` to the consent page and returns the
/// cookie, the form token and the page.
async fn to_consent(smart: &Smart, launch: &str) -> (String, String, String) {
    let (status, headers, _) = smart.get(&authorize_path(launch, SCOPE), None).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "on to the provider");
    let upstream = location(&headers);
    let cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie| cookie.split(';').next())
        .and_then(|pair| pair.split_once('='))
        .map(|(_, value)| value.to_owned())
        .expect("a cookie");
    smart
        .answer(&param(&upstream, "nonce").expect("a nonce"))
        .await;
    let callback = format!(
        "/callback?code=synthetic-upstream-code&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, _, _) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "on to the consent page");
    let (status, _, page) = smart.get("/consent", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    let token = page
        .split("name=\"form_token\" value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("a form token")
        .to_owned();
    (cookie, token, page)
}

/// Approves `scopes` on the consent page and exchanges the code, returning
/// the token response.
async fn approve_and_exchange(smart: &Smart, cookie: &str, token: &str, scopes: &[&str]) -> Value {
    let mut form = vec![("form_token", token), ("decision", "approve")];
    form.extend(scopes.iter().map(|scope| ("scope", *scope)));
    let (status, headers, _) = smart.post("/consent", &form, Some(cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "back to the app");
    let code = param(&location(&headers), "code").expect("a code");
    let exchange = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("client_id", "app"),
    ];
    let (status, _, body) = smart.post("/token", &exchange, None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    serde_json::from_str(&body).expect("JSON")
}

#[tokio::test]
async fn an_ehr_launch_carries_its_context_to_the_token_response() {
    let smart = Smart::start().await;
    let (_, _, document) = smart.get("/.well-known/smart-configuration", None).await;
    let document: Value = serde_json::from_str(&document).expect("JSON");
    for capability in [
        "launch-ehr",
        "context-ehr-patient",
        "context-ehr-encounter",
        "context-banner",
        "permission-patient",
    ] {
        // NOTE: SMART App Launch 2.2.0, Conformance, Capabilities.
        assert!(
            document["capabilities"]
                .as_array()
                .is_some_and(|listed| listed.contains(&json!(capability))),
            "{capability}"
        );
    }
    let launch = smart.launch().await;
    let (cookie, token, page) = to_consent(&smart, &launch).await;
    // NOTE: docs/architecture.md §13.6 item 3, the launch scopes are fixed lines
    // and the patient/ scope keeps its box.
    for scope in ["launch</code>", "launch/<wbr>patient</code>"] {
        assert!(
            page.contains(scope),
            "the launch puts a patient in context, so {scope} is offered"
        );
    }
    assert!(
        !page.contains("value=\"launch\""),
        "a fixed line has no box"
    );
    assert!(page.contains("value=\"patient/Observation.rs\""), "{page}");
    let body = approve_and_exchange(
        &smart,
        &cookie,
        &token,
        &[
            "openid",
            "launch",
            "launch/patient",
            "patient/Observation.rs",
        ],
    )
    .await;
    assert_eq!(
        json!("openid fhirUser launch launch/patient patient/Observation.rs"),
        body["scope"]
    );
    // NOTE: SMART App Launch 2.2.0, Launch context arrives with your access_token.
    assert_eq!(json!("123"), body["patient"]);
    assert_eq!(json!("456"), body["encounter"]);
    assert_eq!(json!(false), body["need_patient_banner"]);
    assert_eq!(
        json!([{"reference": "DiagnosticReport/7"}]),
        body["fhirContext"]
    );
    assert_eq!(json!(STYLE), body["smart_style_url"], "from the branding");
    let access: Value = jsonwebtoken::dangerous::insecure_decode_claims(
        body["access_token"].as_str().expect("a token"),
    )
    .expect("claims");
    // NOTE: docs/architecture.md §13.6 item 2, the context in the access token.
    assert_eq!(json!("123"), access["patient"]);
    assert_eq!(json!("456"), access["encounter"]);
    assert_eq!(Value::Null, access["need_patient_banner"]);

    // NOTE: docs/architecture.md §13.6 item 3, a launch is redeemed once.
    let (status, headers, _) = smart.get(&authorize_path(&launch, SCOPE), None).await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let back = location(&headers);
    assert!(back.as_str().starts_with(REDIRECT), "{back}");
    assert_eq!(Some(String::from("invalid_request")), param(&back, "error"));
    smart.stop().await;
}

#[tokio::test]
async fn a_launch_needs_the_launch_scope_and_a_form_cannot_drop_the_context() {
    let smart = Smart::start().await;
    let launch = smart.launch().await;
    let (status, headers, _) = smart
        .get(&authorize_path(&launch, "openid user/Observation.rs"), None)
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let back = location(&headers);
    assert!(back.as_str().starts_with(REDIRECT), "{back}");
    assert_eq!(Some(String::from("invalid_scope")), param(&back, "error"));

    let launch = smart.launch().await;
    let (cookie, token, _) = to_consent(&smart, &launch).await;
    let body = approve_and_exchange(
        &smart,
        &cookie,
        &token,
        &[
            "openid",
            "launch/patient",
            "patient/Observation.rs",
            "user/Observation.rs",
        ],
    )
    .await;
    // NOTE: docs/architecture.md §13.6 item 3, launch is a fixed line: a form
    // that leaves it out still keeps the context and the patient/ scope.
    assert!(
        body["scope"]
            .as_str()
            .is_some_and(|scope| scope.split(' ').any(|held| held == "launch")
                && scope
                    .split(' ')
                    .any(|held| held == "patient/Observation.rs")),
        "{body}"
    );
    assert_eq!(json!("123"), body["patient"]);
    smart.stop().await;
}

// NOTE: SMART App Launch 2.2.0, Task profile for requesting a SMART launch: the
// Task's appContext is "to be included in the token response" (#660).
#[tokio::test]
async fn a_launch_s_app_context_reaches_the_token_response() {
    let smart = Smart::start().await;
    let app_context = r#"{"field1":"value"}"#;
    let launch = smart.launch_with(&[("appContext", app_context)]).await;
    let (cookie, token, _) = to_consent(&smart, &launch).await;
    let body = approve_and_exchange(
        &smart,
        &cookie,
        &token,
        &[
            "openid",
            "launch",
            "launch/patient",
            "patient/Observation.rs",
        ],
    )
    .await;
    assert_eq!(json!(app_context), body["appContext"], "unchanged");
    smart.stop().await;
}

// NOTE: SMART App Launch 2.2.0, Conformance, Metadata, and RFC 8414 §2, additional
// metadata; docs/architecture.md §13.17 names the member, our own design.
#[tokio::test]
async fn both_documents_name_the_launch_registration_endpoint() {
    let smart = Smart::start().await;
    for path in [
        "/.well-known/smart-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        let (status, _, document) = smart.get(path, None).await;
        assert_eq!(StatusCode::OK, status, "{path}");
        let document: Value = serde_json::from_str(&document).expect("JSON");
        assert_eq!(
            json!(format!("{ISSUER}/launch")),
            document["launch_registration_endpoint"],
            "{path}"
        );
    }
    smart.stop().await;
}

// NOTE: docs/architecture.md §13.6 item 6; SMART App Launch 2.2.0, Obtain
// authorization code, Response: the server's local policy may stand in for the
// end-user's input, here the organisation's approval of the app.
#[tokio::test]
async fn an_approved_app_s_ehr_launch_by_a_professional_skips_the_consent_page() {
    let smart = Smart::start_approved(
        "[ferrosmart.client.organisation_approval]\n\
         scopes = [\"openid\", \"fhirUser\", \"launch\", \"launch/patient\", \"user/Observation.rs\"]\n\
         approved_by = \"Synthetic Administrator\"\napproved_at = \"2026-11-19T09:00:00Z\"",
    )
    .await;
    let launch = smart.launch().await;
    let scope = "openid fhirUser launch user/Observation.rs";
    let (status, headers, _) = smart.get(&authorize_path(&launch, scope), None).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "on to the provider");
    let upstream = location(&headers);
    let cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie| cookie.split(';').next())
        .and_then(|pair| pair.split_once('='))
        .map(|(_, value)| value.to_owned())
        .expect("a cookie");
    smart
        .answer(&param(&upstream, "nonce").expect("a nonce"))
        .await;
    let callback = format!(
        "/callback?code=synthetic-upstream-code&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, headers, _) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let back = location(&headers);
    assert!(
        back.as_str().starts_with(REDIRECT),
        "no consent page: {back}"
    );
    let code = param(&back, "code").expect("a code");
    let exchange = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("client_id", "app"),
    ];
    let (status, _, body) = smart.post("/token", &exchange, None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let body: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(json!(scope), body["scope"]);
    assert_eq!(
        json!("123"),
        body["patient"],
        "the launch context comes along"
    );
    smart.stop().await;
}

// NOTE: docs/architecture.md §13.6 item 6: the approval of the organisation's own
// (first-party) app covers a patient's EHR launch too; a third-party app's does not.
#[tokio::test]
async fn a_first_party_app_s_ehr_launch_by_a_patient_skips_the_consent_page() {
    for (first_party, skipped) in [(true, true), (false, false)] {
        let scopes = if first_party {
            "[\"openid\", \"fhirUser\", \"launch\", \"launch/patient\", \"patient/Observation.rs\"]"
        } else {
            "[\"openid\", \"fhirUser\", \"launch\", \"launch/patient\", \"user/Observation.rs\"]"
        };
        let smart = Smart::start_approved(&format!(
            "[ferrosmart.client.organisation_approval]\nscopes = {scopes}\n\
             approved_by = \"Synthetic Administrator\"\napproved_at = \"2026-11-19T09:00:00Z\"\n\
             first_party = {first_party}"
        ))
        .await;
        let launch = smart.launch().await;
        let scope = "openid fhirUser launch patient/Observation.rs";
        let (status, headers, _) = smart.get(&authorize_path(&launch, scope), None).await;
        assert_eq!(StatusCode::SEE_OTHER, status, "on to the provider");
        let upstream = location(&headers);
        let cookie = headers
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|cookie| cookie.split(';').next())
            .and_then(|pair| pair.split_once('='))
            .map(|(_, value)| value.to_owned())
            .expect("a cookie");
        smart
            .answer_as(
                &param(&upstream, "nonce").expect("a nonce"),
                "Patient/synthetic-2",
            )
            .await;
        let callback = format!(
            "/callback?code=synthetic-upstream-code&state={}",
            param(&upstream, "state").expect("a state")
        );
        let (status, headers, _) = smart.get(&callback, Some(&cookie)).await;
        assert_eq!(StatusCode::SEE_OTHER, status);
        let back = location(&headers);
        if skipped {
            assert!(
                back.as_str().starts_with(REDIRECT),
                "no consent page for the organisation's own app: {back}"
            );
        } else {
            assert_eq!("/consent", back.path(), "a third-party app shows the page");
        }
        smart.stop().await;
    }
}

/// Runs the EHR launch asking for `scope` and the login of the person whose
/// `fhirUser` is `fhir_user`, and returns where the callback sends the
/// browser.
async fn launched_as(smart: &Smart, scope: &str, fhir_user: &str) -> Url {
    let launch = smart.launch().await;
    let (status, headers, _) = smart.get(&authorize_path(&launch, scope), None).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "on to the provider");
    let upstream = location(&headers);
    let cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie| cookie.split(';').next())
        .and_then(|pair| pair.split_once('='))
        .map(|(_, value)| value.to_owned())
        .expect("a cookie");
    smart
        .answer_as(&param(&upstream, "nonce").expect("a nonce"), fhir_user)
        .await;
    let callback = format!(
        "/callback?code=synthetic-upstream-code&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, headers, _) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "the login returns");
    location(&headers)
}

// NOTE: OpenID Connect Core 1.0 §3.1.2.4 (owner, 2026-11-20, #727): the organisation's
// approval is administrative consent, and in an EHR launch it covers staff patient/ scopes.
#[tokio::test]
async fn an_approved_app_s_ehr_launch_covers_a_professional_s_patient_scopes() {
    let smart = Smart::start_approved(
        "[ferrosmart.client.organisation_approval]\n\
         scopes = [\"openid\", \"fhirUser\", \"launch\", \"launch/patient\", \"patient/Observation.rs\"]\n\
         approved_by = \"Synthetic Administrator\"\napproved_at = \"2026-11-19T09:00:00Z\"",
    )
    .await;
    let scope = "openid fhirUser launch patient/Observation.rs";
    let back = launched_as(&smart, scope, "Practitioner/synthetic-1").await;
    assert!(
        back.as_str().starts_with(REDIRECT),
        "no consent page for staff: {back}"
    );
    let code = param(&back, "code").expect("a code");
    let exchange = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("client_id", "app"),
    ];
    let (status, _, body) = smart.post("/token", &exchange, None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let body: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(json!(scope), body["scope"]);
    // NOTE: docs/architecture.md §13.2, the code's record names its basis.
    assert_eq!(
        vec![String::from("organisation")],
        bases(&records(&smart.store).await)
    );

    let back = launched_as(&smart, scope, "Patient/synthetic-2").await;
    assert_eq!(
        "/consent",
        back.path(),
        "a staff approval never answers for a patient"
    );
    smart.stop().await;
}
