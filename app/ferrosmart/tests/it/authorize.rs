// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The authorization code flow through the whole stack against a real
//! PostgreSQL and a stub upstream OpenID Provider: SMART App Launch 2.2.0,
//! standalone launch, with the consent page between the login and the code.

use std::sync::Arc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use axum::Router;
use axum::body::Body;
use ferrosmart::authorize::COOKIE;
use ferrosmart::authorize::consent::{FhirUser, offer};
use ferrosmart::clients::{ClientKind, ClientSection, GrantType, resolve};
use ferrosmart::picker::Reach;
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
    ASSURANCE, Database, Keys, RESOURCE, SUBSTANTIAL_ACR, audit, bases, commit, config, events,
    from_client, iua_71, records,
};

/// FerroSMART's issuer in every case.
const ISSUER: &str = "https://smart.example.org";
/// The app's redirect URI.
const REDIRECT: &str = "https://app.example.org/callback";
const POST_LOGOUT: &str = "https://app.example.org/logged-out";
/// FerroSMART's client id at the provider.
pub(crate) const UPSTREAM_CLIENT: &str = "ferrosmart";
/// The deployment's SMART style document.
const STYLE: &str = "https://smart.example.org/smart-style.json";
/// The app's PKCE verifier and its S256 challenge (RFC 7636 Appendix B).
pub(crate) const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// The challenge of [`VERIFIER`].
pub(crate) const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// The stub upstream provider and its signing key.
pub(crate) struct Provider {
    /// The server.
    pub(crate) server: MockServer,
    /// The key its ID Tokens are signed with.
    encoding: EncodingKey,
}

impl Provider {
    /// Starts a provider serving its metadata and its key set.
    pub(crate) async fn start() -> Self {
        let server = MockServer::start().await;
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .expect("a key pair");
        let encoding = EncodingKey::from_ec_der(pkcs8.as_ref());
        let mut jwk = serde_json::to_value(
            Jwk::from_encoding_key(&encoding, Algorithm::ES256).expect("a JWK"),
        )
        .expect("serializes");
        if let Some(members) = jwk.as_object_mut() {
            members.insert(String::from("kid"), json!("op-1"));
            members.insert(String::from("use"), json!("sig"));
        }
        let uri = server.uri();
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/.well-known/oauth-authorization-server"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": uri,
                "authorization_endpoint": format!("{uri}/authorize"),
                "token_endpoint": format!("{uri}/token"),
                "jwks_uri": format!("{uri}/jwks"),
                "end_session_endpoint": format!("{uri}/logout"),
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["private_key_jwt", "client_secret_basic"]
            })))
            .mount(&server)
            .await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
            .mount(&server)
            .await;
        Self { server, encoding }
    }

    /// Mounts the code exchange answering an ID Token with `nonce` for a
    /// person holding `roles`.
    async fn answer(&self, nonce: &str, roles: &[&str]) {
        self.answer_as(nonce, roles, "synthetic-person", "Practitioner/synthetic-1")
            .await;
    }

    /// Answers the next code exchange with an ID Token for the person
    /// `subject` whose `fhir_user` is `fhir_user`.
    pub(crate) async fn answer_as(
        &self,
        nonce: &str,
        roles: &[&str],
        subject: &str,
        fhir_user: &str,
    ) {
        let claims = json!({
            "sub": subject, "nonce": nonce, "name": "Synthetic Clinician",
            "roles": roles, "fhir_user": fhir_user
        });
        self.answer_claims(&claims).await;
    }

    /// Answers the next code exchange with an ID Token carrying `claims`
    /// beside its `iss`, `aud`, `iat` and `exp`.
    pub(crate) async fn answer_claims(&self, claims: &Value) {
        let now = jiff::Timestamp::now().as_second();
        let mut body = json!({
            "iss": self.server.uri(), "aud": UPSTREAM_CLIENT, "iat": now, "exp": now + 300,
            "acr": SUBSTANTIAL_ACR
        });
        if let (Some(base), Some(over)) = (body.as_object_mut(), claims.as_object()) {
            base.extend(over.clone());
        }
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(String::from("op-1"));
        let id_token = jsonwebtoken::encode(&header, &body, &self.encoding).expect("signs");
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "synthetic-upstream-token", "token_type": "Bearer",
                "expires_in": 300, "id_token": id_token
            })))
            .up_to_n_times(1)
            .mount(&self.server)
            .await;
    }
}

impl Provider {
    /// Returns a Logout Token for FerroSMART's client naming the person
    /// `subject`, with `claims` over the valid set (OpenID Connect
    /// Back-Channel Logout 1.0 §2.4).
    fn logout_token(&self, claims: &Value) -> String {
        let now = jiff::Timestamp::now().as_second();
        let mut body = json!({
            "iss": self.server.uri(), "aud": UPSTREAM_CLIENT, "sub": "synthetic-person",
            "iat": now, "exp": now + 120, "jti": "synthetic-logout",
            "events": { "http://schemas.openid.net/event/backchannel-logout": {} }
        });
        if let (Some(base), Some(over)) = (body.as_object_mut(), claims.as_object()) {
            base.extend(over.clone());
        }
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(String::from("op-1"));
        header.typ = Some(String::from("logout+jwt"));
        jsonwebtoken::encode(&header, &body, &self.encoding).expect("signs")
    }
}

/// FerroSMART with a login upstream, over a fresh database.
struct Smart {
    /// The application.
    app: Router,
    /// The provider.
    provider: Provider,
    /// The store.
    store: Store,
    /// The database.
    database: Database,
    /// The keys, kept for the case's length.
    _keys: Keys,
    /// The settings it runs on.
    settings: ferrosmart::config::settings::Settings,
}

impl Smart {
    /// Starts FerroSMART with the public app `app` and the clinician role.
    async fn start() -> Self {
        Self::start_with(
            "[\"authorization_code\"]",
            "[\"openid\", \"fhirUser\", \"user/Observation.rs\", \"user/Patient.rs\"]",
            "[\"user/Observation.rs\"]",
        )
        .await
    }

    /// Starts FerroSMART with the public app `app` registering the grant
    /// types `grants` and the ceiling `ceiling`, and the clinician role
    /// granting `role`, each a TOML array.
    async fn start_with(grants: &str, ceiling: &str, role: &str) -> Self {
        Self::start_on(grants, ceiling, role, None).await
    }

    /// Starts the server of [`Smart::start_with`] whose one resource server
    /// is the FHIR base `fhir`, when it names one.
    async fn start_on(grants: &str, ceiling: &str, role: &str, fhir: Option<&str>) -> Self {
        let resource = fhir.map_or_else(String::new, |base| {
            format!("[[ferrosmart.resource]]\nbase = {base:?}\n")
        });
        Self::start_over(grants, ceiling, role, &resource).await
    }

    /// Starts the server of [`Smart::start_with`] over the
    /// `[[ferrosmart.resource]]` tables `resource`.
    async fn start_over(grants: &str, ceiling: &str, role: &str, resource: &str) -> Self {
        Self::start_full(grants, ceiling, role, resource, &[REDIRECT]).await
    }

    /// Starts the server of [`Smart::start_with`] whose app registers the
    /// redirect URIs `redirects`.
    async fn start_redirecting(
        grants: &str,
        ceiling: &str,
        role: &str,
        redirects: &[&str],
    ) -> Self {
        Self::start_full(grants, ceiling, role, "", redirects).await
    }

    /// Starts the server of [`Smart::start_over`] whose app registers the
    /// redirect URIs `redirects`.
    async fn start_full(
        grants: &str,
        ceiling: &str,
        role: &str,
        resource: &str,
        redirects: &[&str],
    ) -> Self {
        let provider = Provider::start().await;
        let keys = Keys::new();
        let database = Database::create().await;
        let assertion = crate::support::upstream_assertion(keys.dir.path());
        let text = format!(
            "[ferrosmart]\nissuer = {ISSUER:?}\n[ferrosmart.database]\nurl = {:?}\n\
             [[ferrosmart.upstream]]\nname = \"idp\"\n[ferrosmart.upstream.oidc]\nissuer = {:?}\nclient_id = {UPSTREAM_CLIENT:?}\nfhir_user_claim = \"fhir_user\"\n{assertion}{ASSURANCE}\
             [ferrosmart.branding]\nsmart_style_url = {STYLE:?}\n{resource}\
             [[ferrosmart.role]]\nname = \"clinician\"\nscopes = {role}\n\
             [[ferrosmart.client]]\nclient_id = \"app\"\nname = \"Synthetic App\"\nkind = \"public\"\n\
             client_uri = \"https://app.example.org/\"\nlogo_uri = \"https://cdn.example.org/app.png\"\n\
             policy_uri = \"https://app.example.org/privacy\"\ntos_uri = \"https://app.example.org/terms\"\n\
             redirect_uris = {redirects:?}\npost_logout_redirect_uris = [{POST_LOGOUT:?}]\n\
             {listing}grant_types = {grants}\nscopes = {ceiling}",
            secrecy::ExposeSecret::expose_secret(&database.url),
            provider.server.uri(),
            listing = crate::support::resources_of(resource),
        );
        let settings = config(&text, &keys).resolve().expect("resolves");
        let store = Store::connect(&settings.database_url, 2)
            .await
            .expect("connects");
        store.migrate().await.expect("migrates");
        store.register(&settings.clients).await.expect("registered");
        let providers = crate::support::providers(&settings).await;
        let audit = audit(&settings);
        let state = AppState::new(settings.clone(), store.clone(), audit).with_login(providers);
        Self {
            app: router(Arc::new(state)),
            provider,
            store,
            database,
            _keys: keys,
            settings,
        }
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

    /// Gets `path` with the request cookie `cookie`, if any.
    async fn get(&self, path: &str, cookie: Option<&str>) -> (StatusCode, http::HeaderMap, String) {
        let mut request = Request::get(path);
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, format!("{COOKIE}={cookie}"));
        }
        self.send(request.body(Body::empty()).expect("a request"))
            .await
    }

    /// Posts the form `pairs` to `path` as a browser on `origin` would.
    async fn post_from(
        &self,
        path: &str,
        pairs: &[(&str, &str)],
        origin: &str,
    ) -> (StatusCode, http::HeaderMap, String) {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        let request = Request::post(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ORIGIN, origin)
            .body(Body::from(body))
            .expect("a request");
        self.send(request).await
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

    /// Drops the database.
    async fn stop(self) {
        self.database.drop(self.store).await;
    }
}

/// Returns the authorization request with `overrides` over the defaults.
fn authorize_path(overrides: &[(&str, &str)]) -> String {
    let mut pairs: Vec<(&str, &str)> = vec![
        ("response_type", "code"),
        ("client_id", "app"),
        ("redirect_uri", REDIRECT),
        (
            "scope",
            "openid fhirUser user/Observation.rs user/Patient.rs launch/patient",
        ),
        ("state", "synthetic-state"),
        ("aud", RESOURCE),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("nonce", "synthetic-nonce"),
    ];
    for (name, value) in overrides {
        pairs.retain(|(kept, _)| kept != name);
        if !value.is_empty() {
            pairs.push((name, value));
        }
    }
    format!(
        "/authorize?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish()
    )
}

/// Returns the location of a `303`, parsed.
pub(crate) fn location(headers: &http::HeaderMap) -> Url {
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
pub(crate) fn param(url: &Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// Returns the cookie value a response set.
pub(crate) fn set_cookie(headers: &http::HeaderMap) -> String {
    let cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("a cookie");
    cookie
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .map(|(_, value)| value.to_owned())
        .expect("a value")
}

/// Checks that the store of `smart` holds the login and the token of the
/// person `claims` names, under their pairwise subject.
async fn login_and_token_recorded(smart: &Smart, claims: &Value, access: &Value) {
    // NOTE: DICOM PS3.15 A.5.3.12 and IHE IUA ITI TF-2 3.71.5.1, the login and
    // the token, each recorded for the person under their pairwise subject.
    let stored = records(&smart.store).await;
    let of = |code: &str| {
        stored
            .iter()
            .find(|record| record.pointer("/subtype/0/code") == Some(&json!(code)))
            .map(Value::to_string)
    };
    let subject = claims.get("sub").and_then(Value::as_str).expect("a sub");
    let login = of("110122").expect("the login is recorded");
    assert!(
        login.contains("\"outcome\":\"0\""),
        "a login that held: {login}"
    );
    assert!(login.contains(subject), "the pairwise subject: {login}");
    assert!(
        !login.contains("synthetic-person"),
        "no upstream sub: {login}"
    );
    let token_record = stored
        .iter()
        .find(|record| record.pointer("/subtype/0/code") == Some(&json!("ITI-71")))
        .expect("the token is recorded");
    // NOTE: BALP 1.1.4 IHE.IUA.71, with the person as agent:user.
    let verdict = iua_71(token_record);
    assert!(
        verdict.is_ok(),
        "the token record breaks IHE.IUA.71: {verdict:?}"
    );
    let issued = of("ITI-71").expect("the token is recorded");
    let jti = access.get("jti").and_then(Value::as_str).expect("a jti");
    assert!(issued.contains(jti), "the token's jti: {issued}");
    assert!(issued.contains(subject), "the person: {issued}");
}

/// Runs the flow to the consent page and returns the cookie and the form
/// token it drew.
async fn to_consent(smart: &Smart, roles: &[&str]) -> (String, String) {
    to_consent_with(smart, roles, &[]).await
}

/// Runs the flow with the authorization request `overrides` to the consent
/// page and returns the cookie and the form token it drew.
async fn to_consent_with(
    smart: &Smart,
    roles: &[&str],
    overrides: &[(&str, &str)],
) -> (String, String) {
    let (status, headers, _) = smart.get(&authorize_path(overrides), None).await;
    assert_eq!(
        StatusCode::SEE_OTHER,
        status,
        "the authorization endpoint sends the browser on"
    );
    let upstream = location(&headers);
    assert!(
        upstream.as_str().starts_with(&smart.provider.server.uri()),
        "the browser goes to the provider"
    );
    let cookie = set_cookie(&headers);
    smart
        .provider
        .answer(&param(&upstream, "nonce").expect("a nonce"), roles)
        .await;
    let callback = format!(
        "/callback?code=synthetic-upstream-code&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, headers, _) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(
        StatusCode::SEE_OTHER,
        status,
        "the callback sends the browser on"
    );
    assert_eq!("/consent", location(&headers).path(), "to the consent page");
    let (status, headers, page) = smart.get("/consent", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    let policy = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .expect("a policy");
    assert!(
        policy.contains("script-src 'self'")
            && policy.contains("form-action 'self' https://app.example.org"),
        "{policy}"
    );
    let token = page
        .split("name=\"form_token\" value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("a form token")
        .to_owned();
    (cookie, token)
}

#[tokio::test]
async fn a_standalone_launch_logs_in_upstream_asks_consent_and_issues_tokens() {
    let smart = Smart::start().await;
    let (cookie, token) = to_consent(&smart, &["clinician"]).await;
    let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
    assert!(page.contains("Synthetic App") && page.contains("Synthetic Clinician"));
    assert_eq!(
        1,
        page.matches("<h1").count(),
        "the page card titles the page: {page}"
    );
    assert!(
        page.contains("<h1 class=\"fui-page-card-title\">Allow"),
        "{page}"
    );
    assert!(page.contains("user/Observation.rs"), "the role grants it");
    assert!(
        !page.contains("value=\"user/Patient.rs\""),
        "no role grants it"
    );
    assert!(
        !page.contains("value=\"launch/patient\""),
        "the picker arrives with #516"
    );

    let (status, headers, _) = smart
        .post(
            "/consent",
            &[
                ("form_token", &token),
                ("decision", "approve"),
                ("scope", "openid"),
                ("scope", "fhirUser"),
                ("scope", "user/Observation.rs"),
            ],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let back = location(&headers);
    assert!(back.as_str().starts_with(REDIRECT));
    // NOTE: RFC 6749 §4.1.2, the state; RFC 9207 §2, the iss.
    assert_eq!(Some(String::from("synthetic-state")), param(&back, "state"));
    assert_eq!(Some(String::from(ISSUER)), param(&back, "iss"));
    let code = param(&back, "code").expect("a code");

    let exchange = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("client_id", "app"),
    ];
    let (status, headers, body) = smart.post("/token", &exchange, None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    assert_eq!(
        Some("no-store"),
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
    );
    // NOTE: SMART App Launch 2.2.0, Obtain access token, Response, Pragma no-cache.
    assert_eq!(
        Some("no-cache"),
        headers.get(header::PRAGMA).and_then(|v| v.to_str().ok())
    );
    let body: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(json!("Bearer"), body["token_type"]);
    assert_eq!(json!("openid fhirUser user/Observation.rs"), body["scope"]);
    // NOTE: SMART App Launch 2.2.0, App Launch, the launch context parameters.
    assert_eq!(json!(STYLE), body["smart_style_url"]);
    let id_token = body["id_token"].as_str().expect("an ID Token");
    let claims: Value = jsonwebtoken::dangerous::insecure_decode_claims(id_token).expect("claims");
    // NOTE: OpenID Connect Core 1.0 §2; SMART App Launch 2.2.0, fhirUser.
    assert_eq!(json!(ISSUER), claims["iss"]);
    assert_eq!(json!("app"), claims["aud"]);
    assert_eq!(json!("synthetic-nonce"), claims["nonce"]);
    assert_eq!(json!("Practitioner/synthetic-1"), claims["fhirUser"]);
    assert_ne!(
        json!("synthetic-person"),
        claims["sub"],
        "the upstream sub never leaves"
    );
    let access: Value = jsonwebtoken::dangerous::insecure_decode_claims(
        body["access_token"].as_str().expect("a token"),
    )
    .expect("claims");
    assert_eq!(json!(RESOURCE), access["aud"]);
    assert_eq!(claims["sub"], access["sub"]);
    assert_eq!(
        Value::Null,
        body["refresh_token"],
        "no offline_access or online_access, no refresh token"
    );

    login_and_token_recorded(&smart, &claims, &access).await;

    // NOTE: OAuth 2.1 draft §4.1.3, a second use is refused and revokes.
    let (status, _, body) = smart.post("/token", &exchange, None).await;
    assert_eq!(StatusCode::BAD_REQUEST, status);
    assert!(
        events(&records(&smart.store).await).contains(&String::from("code-reused")),
        "the reuse is recorded"
    );
    assert!(body.contains("invalid_grant"));
    let jti = access["jti"].as_str().expect("a jti");
    assert!(
        smart.store.revoked(jti).await.expect("read"),
        "the first token is revoked"
    );
    smart.stop().await;
}

/// Runs the flow asking `scope` for a person holding `roles` through the
/// callback, and returns the callback's answer.
async fn through_callback(
    smart: &Smart,
    roles: &[&str],
    scope: &str,
) -> (StatusCode, http::HeaderMap, String) {
    let (_, headers, _) = smart.get(&authorize_path(&[("scope", scope)]), None).await;
    let upstream = location(&headers);
    let cookie = set_cookie(&headers);
    smart
        .provider
        .answer(&param(&upstream, "nonce").expect("a nonce"), roles)
        .await;
    let callback = format!(
        "/callback?code=synthetic-upstream-code&state={}",
        param(&upstream, "state").expect("a state")
    );
    smart.get(&callback, Some(&cookie)).await
}

// NOTE: RFC 6749 §4.1.2.1, access_denied; the page that names the missing role
// first is our own design (owner, 2026-11-19, #672).
#[tokio::test]
async fn a_person_without_a_granting_role_sees_which_role_is_missing() {
    let smart = Smart::start().await;
    let (status, headers, page) = through_callback(&smart, &[], "user/Observation.rs").await;
    assert_eq!(StatusCode::FORBIDDEN, status, "{page}");
    assert!(
        page.contains("Synthetic App cannot be given any access for your account"),
        "{page}"
    );
    assert!(page.contains("A role that would: clinician."), "{page}");
    assert!(
        !page.contains("synthetic-person") && !page.contains("Practitioner/synthetic-1"),
        "no claim value: {page}"
    );
    assert!(
        headers.get(header::LOCATION).is_none(),
        "the page, no redirect"
    );
    let back = page
        .split("href=\"")
        .map(|rest| {
            rest.split('"')
                .next()
                .unwrap_or_default()
                .replace("&#38;", "&")
        })
        .find(|href| href.starts_with(REDIRECT))
        .expect("the way back to the app");
    let back = Url::parse(&back).expect("a URL");
    // NOTE: RFC 6749 §4.1.2.1 the error and state; RFC 9207 §2 the iss.
    assert_eq!(Some(String::from("access_denied")), param(&back, "error"));
    assert_eq!(Some(String::from("synthetic-state")), param(&back, "state"));
    assert_eq!(Some(String::from(ISSUER)), param(&back, "iss"));
    assert!(param(&back, "code").is_none());
    smart.stop().await;
}

#[tokio::test]
async fn a_request_the_client_may_never_be_granted_names_no_role() {
    let smart = Smart::start().await;
    let (status, _, page) = through_callback(&smart, &["clinician"], "user/Encounter.rs").await;
    assert_eq!(StatusCode::FORBIDDEN, status, "{page}");
    assert!(
        page.contains("Synthetic App asks for access this server does not give it."),
        "{page}"
    );
    smart.stop().await;
}

// NOTE: docs/architecture.md §13.6 item 3 (owner, 2026-11-19, #668): identity,
// launch and refresh scopes are fixed lines; resource scopes keep their boxes.
#[tokio::test]
async fn the_consent_page_draws_identity_scopes_as_fixed_lines_and_the_app_s_links() {
    let smart = Smart::start().await;
    let (cookie, _token) = to_consent(&smart, &["clinician"]).await;
    let (_, headers, page) = smart.get("/consent", Some(&cookie)).await;
    for fixed in ["openid", "fhirUser"] {
        assert!(
            !page.contains(&format!("value=\"{fixed}\"")),
            "no box: {page}"
        );
        assert!(
            page.contains(&format!("<code class=\"fui-scope-raw\">{fixed}</code>")),
            "a fixed line: {page}"
        );
    }
    assert!(
        page.contains("value=\"user/Observation.rs\" checked"),
        "{page}"
    );
    // NOTE: RFC 7591 §2, client_uri, logo_uri, policy_uri and tos_uri.
    for link in [
        "href=\"https://app.example.org/\"",
        "href=\"https://app.example.org/privacy\"",
        "href=\"https://app.example.org/terms\"",
        "<img src=\"https://cdn.example.org/app.png\" alt=\"Logo of Synthetic App\"",
    ] {
        assert!(page.contains(link), "{link}: {page}");
    }
    let policy = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|value| value.to_str().ok())
        .expect("a policy");
    assert!(
        policy.contains("img-src 'self' https://cdn.example.org;"),
        "the logo's origin alone: {policy}"
    );
    smart.stop().await;
}

#[tokio::test]
async fn a_consent_form_without_its_fixed_scopes_still_grants_them() {
    let smart = Smart::start().await;
    let (cookie, token) = to_consent(&smart, &["clinician"]).await;
    let (status, headers, _) = smart
        .post(
            "/consent",
            &[("form_token", &token), ("decision", "approve")],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let code = param(&location(&headers), "code").expect("a code: the fixed scopes are granted");
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
    assert_eq!(
        json!("openid fhirUser"),
        body["scope"],
        "every resource scope unticked, the identity scopes kept"
    );
    smart.stop().await;
}

#[tokio::test]
async fn a_consent_form_cannot_add_a_scope_that_was_not_offered() {
    let smart = Smart::start().await;
    let (cookie, token) = to_consent(&smart, &["clinician"]).await;
    let (_, headers, _) = smart
        .post(
            "/consent",
            &[
                ("form_token", &token),
                ("decision", "approve"),
                ("scope", "user/Patient.rs"),
                ("scope", "offline_access"),
            ],
            Some(&cookie),
        )
        .await;
    let code = param(&location(&headers), "code").expect("a code");
    let exchange = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("client_id", "app"),
    ];
    let (_, _, body) = smart.post("/token", &exchange, None).await;
    let body: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(json!("openid fhirUser"), body["scope"], "{body}");
    smart.stop().await;
}

/// Runs a login asking `scope` whose upstream ID Token carries `extra`, then
/// approves, and returns the token response.
async fn with_claims(smart: &Smart, scope: &str, extra: &Value) -> Value {
    let (_, headers, _) = smart.get(&authorize_path(&[("scope", scope)]), None).await;
    let upstream = location(&headers);
    let cookie = set_cookie(&headers);
    let mut claims = json!({
        "sub": "synthetic-person", "roles": ["clinician"],
        "fhir_user": "Practitioner/synthetic-1",
        "nonce": param(&upstream, "nonce").expect("a nonce")
    });
    if let (Some(base), Some(over)) = (claims.as_object_mut(), extra.as_object()) {
        base.extend(over.clone());
    }
    smart.provider.answer_claims(&claims).await;
    let callback = format!(
        "/callback?code=synthetic-upstream-code&state={}",
        param(&upstream, "state").expect("a state")
    );
    smart.get(&callback, Some(&cookie)).await;
    let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
    let token = form_token(&page);
    let (_, headers, _) = smart
        .post(
            "/consent",
            &[("form_token", token.as_str()), ("decision", "approve")],
            Some(&cookie),
        )
        .await;
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

/// Returns the claims of the JWT `name` of the token response `body`.
fn jwt_claims(body: &Value, name: &str) -> Value {
    let token = body.get(name).and_then(Value::as_str).expect("a token");
    jsonwebtoken::dangerous::insecure_decode_claims(token).expect("claims")
}

// NOTE: OpenID Connect Core 1.0 §5.4, profile asks for name and
// preferred_username, email for email and email_verified (#676).
#[tokio::test]
async fn profile_and_email_pass_the_upstream_claims_into_the_id_token() {
    let smart = Smart::start_with(
        "[\"authorization_code\"]",
        "[\"openid\", \"fhirUser\", \"profile\", \"email\", \"user/Observation.rs\"]",
        "[\"user/Observation.rs\"]",
    )
    .await;
    let upstream = json!({
        "name": "Synthetic Clinician", "preferred_username": "sclinician",
        "email": "clinician@example.org", "email_verified": true
    });
    let body = with_claims(&smart, "openid fhirUser profile email", &upstream).await;
    assert_eq!(json!("openid fhirUser profile email"), body["scope"]);
    let id = jwt_claims(&body, "id_token");
    assert_eq!(json!("Synthetic Clinician"), id["name"]);
    assert_eq!(json!("sclinician"), id["preferred_username"]);
    assert_eq!(json!("clinician@example.org"), id["email"]);
    assert_eq!(json!(true), id["email_verified"]);
    let access = jwt_claims(&body, "access_token");
    for claim in ["name", "preferred_username", "email", "email_verified"] {
        assert!(
            access.get(claim).is_none(),
            "never in the access token: {claim}"
        );
    }

    let body = with_claims(&smart, "openid profile", &upstream).await;
    let id = jwt_claims(&body, "id_token");
    assert_eq!(json!("sclinician"), id["preferred_username"]);
    assert!(
        id.get("email").is_none() && id.get("email_verified").is_none(),
        "{id}"
    );

    let body = with_claims(&smart, "openid", &upstream).await;
    let id = jwt_claims(&body, "id_token");
    assert!(
        id.get("name").is_none() && id.get("email").is_none(),
        "{id}"
    );

    let body = with_claims(&smart, "openid profile email", &json!({})).await;
    let id = jwt_claims(&body, "id_token");
    for claim in ["name", "preferred_username", "email", "email_verified"] {
        assert!(
            id.get(claim).is_none(),
            "absent upstream, absent here: {claim}"
        );
    }
    smart.stop().await;
}

#[tokio::test]
async fn profile_and_email_are_offered_within_the_ceiling_and_listed_in_discovery() {
    let smart = Smart::start().await;
    let (_, _, document) = smart.get("/.well-known/openid-configuration", None).await;
    let document: Value = serde_json::from_str(&document).expect("JSON");
    for scope in ["profile", "email"] {
        assert!(
            document["scopes_supported"]
                .as_array()
                .is_some_and(|listed| listed.contains(&json!(scope))),
            "{scope}: {document}"
        );
    }
    for claim in ["name", "preferred_username", "email", "email_verified"] {
        assert!(
            document["claims_supported"]
                .as_array()
                .is_some_and(|listed| listed.contains(&json!(claim))),
            "{claim}: {document}"
        );
    }
    // NOTE: the default client's ceiling names neither, so neither is granted.
    let body = with_claims(&smart, "openid profile email", &json!({"name": "X"})).await;
    assert_eq!(json!("openid"), body["scope"]);
    smart.stop().await;
}

#[tokio::test]
async fn a_declined_consent_sends_access_denied_back() {
    let smart = Smart::start().await;
    let (cookie, token) = to_consent(&smart, &["clinician"]).await;
    let (status, headers, _) = smart
        .post(
            "/consent",
            &[("form_token", &token), ("decision", "deny")],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let back = location(&headers);
    assert_eq!(Some(String::from("access_denied")), param(&back, "error"));
    assert_eq!(Some(String::from("synthetic-state")), param(&back, "state"));
    let (status, _, _) = smart.get("/consent", Some(&cookie)).await;
    assert_eq!(StatusCode::NOT_FOUND, status, "decided once");
    smart.stop().await;
}

#[tokio::test]
async fn a_consent_post_without_its_page_s_token_or_cookie_is_refused() {
    let smart = Smart::start().await;
    let (cookie, _token) = to_consent(&smart, &["clinician"]).await;
    let (status, _, _) = smart
        .post(
            "/consent",
            &[("form_token", "forged"), ("decision", "approve")],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "RFC 6749 §10.12");
    let (status, _, _) = smart.get("/consent", Some("another-browser")).await;
    assert_eq!(StatusCode::NOT_FOUND, status);
    smart.stop().await;
}

#[tokio::test]
async fn a_request_the_endpoint_cannot_trust_is_shown_never_redirected() {
    let smart = Smart::start().await;
    for overrides in [
        &[("client_id", "unknown")][..],
        &[("redirect_uri", "https://evil.example.org/cb")][..],
        &[("redirect_uri", "")][..],
    ] {
        let (status, headers, page) = smart.get(&authorize_path(overrides), None).await;
        assert_eq!(StatusCode::BAD_REQUEST, status, "{overrides:?}");
        assert!(headers.get(header::LOCATION).is_none(), "RFC 6749 §4.1.2.1");
        assert!(
            page.contains("Bad request · 400") && page.contains("<h1>"),
            "the error page of a 400: {page}"
        );
    }
    smart.stop().await;
}

// NOTE: SMART App Launch 2.2.0 requires aud of the app; with one base configured
// FerroSMART defaults a missing one to it, as the token endpoint does (#670).
#[tokio::test]
async fn a_request_without_aud_defaults_to_the_one_configured_base() {
    let smart = Smart::start().await;
    let (status, headers, _) = smart.get(&authorize_path(&[("aud", "")]), None).await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let upstream = location(&headers);
    assert!(
        param(&upstream, "error").is_none() && param(&upstream, "nonce").is_some(),
        "on to the login: {upstream}"
    );
    let (_, headers, _) = smart
        .get(
            &authorize_path(&[("aud", "https://other.example.org/fhir")]),
            None,
        )
        .await;
    assert_eq!(
        Some(String::from("invalid_request")),
        param(&location(&headers), "error"),
        "a wrong aud is refused with one base too"
    );
    smart.stop().await;
}

#[tokio::test]
async fn a_request_without_aud_is_refused_with_two_bases() {
    let smart = Smart::start_over(
        "[\"authorization_code\"]",
        "[\"openid\", \"user/Observation.rs\"]",
        "[\"user/Observation.rs\"]",
        &format!(
            "[[ferrosmart.resource]]\nbase = {RESOURCE:?}\n\
             [[ferrosmart.resource]]\nbase = \"https://second.example.org/fhir\"\n"
        ),
    )
    .await;
    let (_, headers, _) = smart.get(&authorize_path(&[("aud", "")]), None).await;
    let back = location(&headers);
    assert!(back.as_str().starts_with(REDIRECT), "{back}");
    assert_eq!(Some(String::from("invalid_request")), param(&back, "error"));
    let (_, headers, _) = smart
        .get(
            &authorize_path(&[("aud", "https://second.example.org/fhir")]),
            None,
        )
        .await;
    assert!(
        param(&location(&headers), "error").is_none(),
        "a named base"
    );
    smart.stop().await;
}

#[tokio::test]
async fn a_request_that_breaks_the_profile_is_sent_back_with_its_error() {
    let smart = Smart::start().await;
    for (overrides, error) in [
        (&[("code_challenge_method", "plain")][..], "invalid_request"),
        (&[("code_challenge", "")][..], "invalid_request"),
        (
            &[("aud", "https://other.example.org/fhir")][..],
            "invalid_request",
        ),
        (&[("state", "")][..], "invalid_request"),
        (
            &[("response_type", "token")][..],
            "unsupported_response_type",
        ),
        (
            &[("launch", "synthetic-launch"), ("scope", "openid launch")][..],
            "invalid_request",
        ),
        (&[("launch", "synthetic-launch")][..], "invalid_scope"),
        (&[("scope", "")][..], "invalid_scope"),
    ] {
        let (status, headers, _) = smart.get(&authorize_path(overrides), None).await;
        assert_eq!(StatusCode::SEE_OTHER, status, "{overrides:?}");
        let back = location(&headers);
        assert!(back.as_str().starts_with(REDIRECT), "{overrides:?}");
        assert_eq!(
            Some(String::from(error)),
            param(&back, "error"),
            "{overrides:?}"
        );
        assert_eq!(Some(String::from(ISSUER)), param(&back, "iss"));
    }
    smart.stop().await;
}

#[tokio::test]
async fn a_login_declined_at_the_provider_is_recorded_and_sent_back() {
    let smart = Smart::start().await;
    let (_, headers, _) = smart.get(&authorize_path(&[]), None).await;
    let cookie = set_cookie(&headers);
    let upstream = location(&headers);
    let callback = format!(
        "/callback?error=access_denied&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, headers, _) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    assert_eq!(
        Some(String::from("access_denied")),
        param(&location(&headers), "error")
    );
    let stored = records(&smart.store).await;
    assert_eq!(1, stored.len(), "{stored:?}");
    let login = stored.first().expect("the login");
    // NOTE: DICOM PS3.15 A.5.3.12, a failed User Authentication is recorded too.
    assert_eq!(json!("110114"), login["type"]["code"]);
    assert_eq!(json!("110122"), login["subtype"][0]["code"]);
    assert_eq!(json!("4"), login["outcome"]);
    smart.stop().await;
}

#[tokio::test]
async fn a_callback_from_another_browser_is_refused() {
    let smart = Smart::start().await;
    let (_, headers, _) = smart.get(&authorize_path(&[]), None).await;
    let upstream = location(&headers);
    let callback = format!(
        "/callback?code=x&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, _, _) = smart.get(&callback, Some("another-browser")).await;
    assert_eq!(StatusCode::FORBIDDEN, status, "RFC 9700 §4.7");
    smart.stop().await;
}

#[tokio::test]
async fn a_code_exchange_that_does_not_hold_is_refused_and_burns_nothing() {
    let smart = Smart::start().await;
    let (cookie, token) = to_consent(&smart, &["clinician"]).await;
    let (_, headers, _) = smart
        .post(
            "/consent",
            &[
                ("form_token", &token),
                ("decision", "approve"),
                ("scope", "user/Observation.rs"),
            ],
            Some(&cookie),
        )
        .await;
    let code = param(&location(&headers), "code").expect("a code");
    for (name, value, error) in [
        (
            "code_verifier",
            "wrong-verifier-wrong-verifier-wrong-verifier-xx",
            "invalid_grant",
        ),
        (
            "redirect_uri",
            "https://app.example.org/other",
            "invalid_grant",
        ),
        ("client_id", "unknown", "invalid_client"),
    ] {
        let mut exchange = vec![
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
            ("client_id", "app"),
        ];
        exchange.retain(|(kept, _)| *kept != name);
        exchange.push((name, value));
        let (status, _, body) = smart.post("/token", &exchange, None).await;
        assert_eq!(StatusCode::BAD_REQUEST, status);
        assert!(body.contains(error), "{name}: {body}");
    }
    // NOTE: OAuth 2.1 draft §7.5.3, a request with invalid parameters burns nothing.
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
    // NOTE: docs/architecture.md §13.6 item 3, openid is a fixed line, granted
    // with the app though the form left it out.
    assert!(
        body.get("id_token").is_some(),
        "openid is granted, so an ID Token"
    );
    smart.stop().await;
}

#[tokio::test]
async fn the_documents_describe_the_login_once_it_is_configured() {
    let smart = Smart::start().await;
    let (_, _, body) = smart.get("/.well-known/smart-configuration", None).await;
    let smart_doc: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(
        json!(format!("{ISSUER}/authorize")),
        smart_doc["authorization_endpoint"]
    );
    let capabilities = smart_doc["capabilities"].as_array().expect("capabilities");
    for capability in [
        "launch-standalone",
        "client-public",
        "client-confidential-asymmetric",
        "sso-openid-connect",
        "permission-user",
        "permission-v2",
    ] {
        assert!(capabilities.contains(&json!(capability)), "{capability}");
    }
    assert_eq!(
        json!(ISSUER),
        smart_doc["issuer"],
        "with sso-openid-connect"
    );
    let (status, _, body) = smart.get("/.well-known/openid-configuration", None).await;
    assert_eq!(StatusCode::OK, status);
    let openid: Value = serde_json::from_str(&body).expect("JSON");
    // NOTE: OpenID Connect Discovery 1.0 §3, the members it requires.
    assert_eq!(json!(["code"]), openid["response_types_supported"]);
    assert_eq!(json!(["pairwise"]), openid["subject_types_supported"]);
    assert_eq!(
        json!(["RS256"]),
        openid["id_token_signing_alg_values_supported"]
    );
    smart.stop().await;
}

// NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, Extensibility; the
// owner's decision on #647: the request, the ceiling and a held role together.
#[tokio::test]
async fn a_person_is_granted_an_extension_scope_that_the_ceiling_and_a_role_list() {
    let smart = Smart::start_with(
        "[\"authorization_code\"]",
        "[\"openid\", \"fhirUser\", \"user/Observation.rs\", \"__ferroehr.platform\", \"admin\"]",
        "[\"user/Observation.rs\", \"__ferroehr.platform\"]",
    )
    .await;
    let (_, _, document) = smart.get("/.well-known/smart-configuration", None).await;
    let document: Value = serde_json::from_str(&document).expect("JSON");
    assert!(
        document["scopes_supported"]
            .as_array()
            .is_some_and(|listed| listed.contains(&json!("__ferroehr.platform"))),
        "the server advertises its extension scope"
    );
    let scope = "openid fhirUser user/Observation.rs __ferroehr.platform admin";
    let (cookie, token) = to_consent_with(&smart, &["clinician"], &[("scope", scope)]).await;
    let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
    assert!(
        page.contains("value=\"__ferroehr.platform\""),
        "shown on the consent page: {page}"
    );
    assert!(
        page.contains("Access this server defines for its own use: __ferroehr.platform"),
        "{page}"
    );
    assert!(
        !page.contains("value=\"admin\""),
        "a scope outside the SMART set and not __-prefixed is never offered"
    );
    let approve = [
        ("form_token", token.as_str()),
        ("decision", "approve"),
        ("scope", "openid"),
        ("scope", "user/Observation.rs"),
        ("scope", "__ferroehr.platform"),
    ];
    let (status, headers, _) = smart.post("/consent", &approve, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status);
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
    let body: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(
        json!("openid fhirUser user/Observation.rs __ferroehr.platform"),
        body["scope"]
    );
    let claims: Value = jsonwebtoken::dangerous::insecure_decode_claims(
        body["access_token"].as_str().expect("a token"),
    )
    .expect("claims");
    assert_eq!(
        json!("openid fhirUser user/Observation.rs __ferroehr.platform"),
        claims["scope"]
    );
    smart.stop().await;
}

#[test]
fn an_extension_scope_needs_the_ceiling_and_a_role() {
    let client = resolve(&[ClientSection {
        client_id: String::from("app"),
        kind: ClientKind::Public,
        redirect_uris: vec![String::from(REDIRECT)],
        grant_types: vec![GrantType::AuthorizationCode],
        scopes: ["openid", "__ferroehr.platform", "__ferroehr.audit", "admin"]
            .into_iter()
            .map(String::from)
            .collect(),
        ..ClientSection::default()
    }])
    .expect("admitted")
    .remove(0);
    let roles = [(
        String::from("administrator"),
        vec![
            String::from("__ferroehr.platform"),
            String::from("__ferroehr.other"),
        ],
    )]
    .into_iter()
    .collect();
    let requested = "openid __ferroehr.platform __ferroehr.audit __ferroehr.other admin";
    // NOTE: the ceiling and the role list __ferroehr.platform; the ceiling alone
    // lists __ferroehr.audit and the role alone __ferroehr.other.
    assert_eq!(
        vec!["openid", "__ferroehr.platform"],
        offer(
            requested,
            &client,
            &[String::from("administrator")],
            &roles,
            FhirUser::Absent,
            None,
            Reach::Nothing
        )
    );
    assert_eq!(
        vec!["openid"],
        offer(
            requested,
            &client,
            &[],
            &roles,
            FhirUser::Absent,
            None,
            Reach::Nothing
        ),
        "no held role grants no extension scope"
    );
}

#[test]
fn the_consent_page_offers_what_the_ceiling_and_the_roles_allow() {
    let client = resolve(&[ClientSection {
        client_id: String::from("app"),
        kind: ClientKind::Public,
        redirect_uris: vec![String::from(REDIRECT)],
        grant_types: vec![GrantType::AuthorizationCode],
        scopes: [
            "openid",
            "fhirUser",
            "user/Observation.rs",
            "user/Patient.rs",
            "offline_access",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        ..ClientSection::default()
    }])
    .expect("admitted")
    .remove(0);
    let roles = [(
        String::from("clinician"),
        vec![String::from("user/Observation.rs")],
    )]
    .into_iter()
    .collect();
    let held = vec![String::from("clinician")];
    let requested = "openid fhirUser user/Observation.rs user/Patient.rs system/Patient.rs offline_access user/Observation.rs";
    assert_eq!(
        vec!["openid", "fhirUser", "user/Observation.rs"],
        offer(
            requested,
            &client,
            &held,
            &roles,
            FhirUser::Present,
            None,
            Reach::Nothing
        )
    );
    assert_eq!(
        vec!["openid", "user/Observation.rs"],
        offer(
            requested,
            &client,
            &held,
            &roles,
            FhirUser::Absent,
            None,
            Reach::Nothing
        ),
        "no fhirUser to give"
    );
    assert_eq!(
        vec!["user/Observation.rs"],
        offer(
            "fhirUser user/Observation.rs",
            &client,
            &held,
            &roles,
            FhirUser::Present,
            None,
            Reach::Nothing
        ),
        "fhirUser rides on openid"
    );
    assert!(
        offer(
            requested,
            &client,
            &[],
            &roles,
            FhirUser::Present,
            None,
            Reach::Nothing
        )
        .iter()
        .all(|scope| !scope.starts_with("user/")),
        "no role, no user scope"
    );
}

#[tokio::test]
async fn a_remembered_consent_answers_again_until_it_is_withdrawn() {
    let smart = Smart::start().await;
    let (cookie, token) = to_consent(&smart, &["clinician"]).await;
    let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
    assert!(
        page.contains("name=\"remember\""),
        "the person may choose to remember"
    );
    let granted = [
        ("form_token", token.as_str()),
        ("decision", "approve"),
        ("scope", "openid"),
        ("scope", "fhirUser"),
        ("scope", "user/Observation.rs"),
        ("remember", "yes"),
    ];
    let (status, _, _) = smart.post("/consent", &granted, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status);

    // NOTE: docs/architecture.md §13.6 item 6, the remembered consent covers
    // the same request, so the browser goes back with a code at once.
    let (_, headers, _) = smart.get(&authorize_path(&[]), None).await;
    let upstream = location(&headers);
    let cookie = set_cookie(&headers);
    smart
        .provider
        .answer(&param(&upstream, "nonce").expect("a nonce"), &["clinician"])
        .await;
    let callback = format!(
        "/callback?code=c&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, headers, _) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let back = location(&headers);
    assert!(back.as_str().starts_with(REDIRECT), "{back}");
    assert!(param(&back, "code").is_some(), "no consent page this time");

    // NOTE: SMART App Launch 2.2.0, Conformance, management_endpoint.
    let (cookie, page) = manage_visit(&smart).await;
    assert!(page.contains("Synthetic App"));
    assert!(
        page.contains("<h1 class=\"fui-page-card-title\">Apps you allowed</h1>"),
        "{page}"
    );
    // NOTE: docs/architecture.md §13.6 item 9, the page shows the person their own
    // pairwise sub, the one `ferrosmart subject` prints (#733).
    let own = ferrosmart::upstream::pairwise(&smart.provider.server.uri(), "synthetic-person");
    assert!(page.contains(&format!("<code>{own}</code>")), "{page}");
    assert!(
        !page.contains("synthetic-person"),
        "no upstream sub: {page}"
    );
    let form_token = page
        .split("name=\"form_token\" value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("a form token")
        .to_owned();
    let (status, _, _) = smart
        .post(
            "/manage",
            &[("form_token", &form_token), ("client_id", "app")],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let (_, _, page) = smart.get("/manage", Some(&cookie)).await;
    assert!(!page.contains("Synthetic App"), "withdrawn");

    // The next request asks again.
    let (_, headers, _) = smart.get(&authorize_path(&[]), None).await;
    let upstream = location(&headers);
    let cookie = set_cookie(&headers);
    smart
        .provider
        .answer(&param(&upstream, "nonce").expect("a nonce"), &["clinician"])
        .await;
    let callback = format!(
        "/callback?code=d&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (_, headers, _) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!("/consent", location(&headers).path(), "asked again");
    // NOTE: docs/architecture.md §13.2, each code and each consent change commits
    // with its record.
    let happened = events(&records(&smart.store).await);
    for event in [
        "authorization-code",
        "consent-remembered",
        "consent-withdrawn",
    ] {
        assert!(
            happened.contains(&String::from(event)),
            "{event}: {happened:?}"
        );
    }
    smart.stop().await;
}

/// Logs the person in at the management page and returns the cookie and
/// the page (SMART App Launch 2.2.0, Conformance, `management_endpoint`).
async fn manage_visit(smart: &Smart) -> (String, String) {
    let (status, headers, _) = smart.get("/manage", None).await;
    assert_eq!(
        StatusCode::SEE_OTHER,
        status,
        "the visit begins with a login"
    );
    let upstream = location(&headers);
    let cookie = set_cookie(&headers);
    smart
        .provider
        .answer(&param(&upstream, "nonce").expect("a nonce"), &["clinician"])
        .await;
    let callback = format!(
        "/callback?code=m&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, headers, _) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "the login returns");
    assert_eq!("/manage", location(&headers).path(), "to the page");
    let (status, _, page) = smart.get("/manage", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    (cookie, page)
}

// NOTE: SMART App Launch 2.2.0, Best Practices, remind users which apps have offline
// access; the management page lists a live refresh grant that no consent remembered.
#[tokio::test]
async fn the_management_page_lists_an_app_with_offline_access_and_withdraws_it() {
    let (smart, body) = launch_with("offline_access").await;
    let token = body["refresh_token"].as_str().expect("a refresh token");
    let (_cookie, page) = manage_visit(&smart).await;
    assert!(
        page.contains("Synthetic App")
            && page.contains("This app stays connected after you sign out"),
        "{page}"
    );
    // NOTE: SMART App Launch 2.2.0, Best Practices, Considerations for Scope
    // Consent: plain words before the resource type.
    assert!(
        page.contains("Measurements and test results (Observation)"),
        "{page}"
    );
    let (cookie, page) = manage_visit(&smart).await;
    let (status, _, _) = smart
        .post(
            "/manage",
            &[
                ("form_token", form_token(&page).as_str()),
                ("client_id", "app"),
            ],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let (status, refused) = refresh(&smart, token).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "withdrawn: {refused}");
    let (_, _, page) = smart.get("/manage", Some(&cookie)).await;
    assert!(page.contains("No app keeps access to your data."), "{page}");
    smart.stop().await;
}
/// Starts FerroSMART whose app may refresh, and runs a launch asking for
/// `access` (`offline_access` or `online_access`) to its token response.
async fn launch_with(access: &str) -> (Smart, Value) {
    launch_holding(access, &["clinician"]).await
}

/// Runs the launch of [`launch_with`] as a person holding `roles`.
async fn launch_holding(access: &str, roles: &[&str]) -> (Smart, Value) {
    let smart = Smart::start_with(
        "[\"authorization_code\", \"refresh_token\"]",
        "[\"openid\", \"fhirUser\", \"user/Observation.rs\", \"offline_access\", \"online_access\"]",
        "[\"user/Observation.rs\"]",
    )
    .await;
    let scope = format!("openid fhirUser user/Observation.rs {access}");
    let (cookie, token) = to_consent_with(&smart, roles, &[("scope", &scope)]).await;
    let (status, headers, _) = smart
        .post(
            "/consent",
            &[
                ("form_token", &token),
                ("decision", "approve"),
                ("scope", "openid"),
                ("scope", "fhirUser"),
                ("scope", "user/Observation.rs"),
                ("scope", access),
            ],
            Some(&cookie),
        )
        .await;
    assert_eq!(
        StatusCode::SEE_OTHER,
        status,
        "the consent sends the browser back"
    );
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
    (smart, serde_json::from_str(&body).expect("JSON"))
}

/// Refreshes with `token` as the public app and returns the status and
/// the JSON body.
async fn refresh(smart: &Smart, token: &str) -> (StatusCode, Value) {
    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", token),
        ("client_id", "app"),
    ];
    let (status, _, body) = smart.post("/token", &form, None).await;
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
}

// NOTE: RFC 9068 §2.2.3.1, the roles attribute; the owner's decision on #649: the
// roles FerroSMART maps, in a user flow, and through every refresh.
#[tokio::test]
async fn the_access_token_carries_the_person_s_mapped_roles_through_a_refresh() {
    let (smart, body) = launch_holding("offline_access", &["reception", "clinician"]).await;
    let roles = |body: &Value| -> Value {
        let claims: Value = jsonwebtoken::dangerous::insecure_decode_claims(
            body["access_token"].as_str().expect("a token"),
        )
        .expect("claims");
        claims["roles"].clone()
    };
    assert_eq!(
        json!(["clinician"]),
        roles(&body),
        "a role no [[ferrosmart.role]] names stays at the provider"
    );
    let (status, refreshed) = refresh(
        &smart,
        body["refresh_token"].as_str().expect("a refresh token"),
    )
    .await;
    assert_eq!(StatusCode::OK, status, "{refreshed}");
    assert_eq!(json!(["clinician"]), roles(&refreshed));
    smart.stop().await;
}

#[tokio::test]
async fn an_offline_access_launch_issues_a_refresh_token_that_rotates() {
    let (smart, body) = launch_with("offline_access").await;
    // NOTE: SMART App Launch 2.2.0, Obtain access token, Response: refresh_token.
    let first = body["refresh_token"].as_str().expect("a refresh token");
    assert_eq!(
        json!("openid fhirUser user/Observation.rs offline_access"),
        body["scope"]
    );
    let (status, renewed) = refresh(&smart, first).await;
    assert_eq!(StatusCode::OK, status, "{renewed}");
    assert_eq!(json!("bearer"), renewed["token_type"]);
    assert_eq!(body["scope"], renewed["scope"]);
    assert_eq!(
        json!(STYLE),
        renewed["smart_style_url"],
        "the launch context"
    );
    assert!(renewed["id_token"].is_null());
    let access: Value = jsonwebtoken::dangerous::insecure_decode_claims(
        renewed["access_token"].as_str().expect("a token"),
    )
    .expect("claims");
    // NOTE: docs/architecture.md §13.6 item 2, fhirUser rides in the access token.
    assert_eq!(json!("Practitioner/synthetic-1"), access["fhirUser"]);
    let second = renewed["refresh_token"].as_str().expect("rotated");
    assert_ne!(first, second);
    // NOTE: RFC 9700 §4.14.2, the rotated token presented again after the repeat
    // window revokes the grant (docs/architecture.md §13.6 item 11).
    crate::support::rotated_ago(
        secrecy::ExposeSecret::expose_secret(&smart.database.url),
        first,
        11,
    )
    .await;
    let (status, replay) = refresh(&smart, first).await;
    assert_eq!(StatusCode::BAD_REQUEST, status);
    assert_eq!(json!("invalid_grant"), replay["error"]);
    let (status, _) = refresh(&smart, second).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "the grant is revoked");
    let jti = access["jti"].as_str().expect("a jti");
    assert!(smart.store.revoked(jti).await.expect("read"));
    smart.stop().await;
}

#[tokio::test]
async fn an_online_access_launch_ends_with_its_upstream_login() {
    let (smart, body) = launch_with("online_access").await;
    let token = body["refresh_token"].as_str().expect("a refresh token");
    let (status, renewed) = refresh(&smart, token).await;
    assert_eq!(StatusCode::OK, status, "{renewed}");
    let session: String = {
        use sqlx::Connection as _;
        let mut connection =
            sqlx::PgConnection::connect(secrecy::ExposeSecret::expose_secret(&smart.database.url))
                .await
                .expect("connects");
        sqlx::query_scalar("SELECT upstream_session FROM authorization_grant")
            .fetch_one(&mut connection)
            .await
            .expect("the grant names its session")
    };
    let mut tx = smart.store.begin().await.expect("begins");
    assert!(tx.end_session(&session).await.expect("ended"));
    commit(tx).await;
    // NOTE: docs/architecture.md §13.6 item 7, online_access ends with the upstream login.
    let next = renewed["refresh_token"].as_str().expect("rotated");
    let (status, refused) = refresh(&smart, next).await;
    assert_eq!(StatusCode::BAD_REQUEST, status);
    assert_eq!(json!("invalid_grant"), refused["error"]);
    smart.stop().await;
}

#[tokio::test]
async fn withdrawing_a_consent_revokes_the_grants_it_covered() {
    let (smart, body) = launch_with("offline_access").await;
    let token = body["refresh_token"].as_str().expect("a refresh token");
    let access: Value = jsonwebtoken::dangerous::insecure_decode_claims(
        body["access_token"].as_str().expect("a token"),
    )
    .expect("claims");
    let subject = access["sub"].as_str().expect("a sub");
    let mut tx = smart.store.begin().await.expect("begins");
    tx.revoke_consent(subject, "app").await.expect("withdrawn");
    commit(tx).await;
    // NOTE: docs/architecture.md §13.6 item 6, revoking a consent revokes its grants.
    let (status, refused) = refresh(&smart, token).await;
    assert_eq!(StatusCode::BAD_REQUEST, status);
    assert_eq!(json!("invalid_grant"), refused["error"]);
    smart.stop().await;
}

#[test]
fn offline_and_online_access_are_offered_to_a_client_that_refreshes() {
    let client = resolve(&[ClientSection {
        client_id: String::from("app"),
        kind: ClientKind::Public,
        redirect_uris: vec![String::from(REDIRECT)],
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        scopes: ["openid", "offline_access", "online_access"]
            .into_iter()
            .map(String::from)
            .collect(),
        ..ClientSection::default()
    }])
    .expect("admitted")
    .remove(0);
    let roles = std::collections::BTreeMap::new();
    assert_eq!(
        vec!["openid", "offline_access", "online_access"],
        offer(
            "openid offline_access online_access",
            &client,
            &[],
            &roles,
            FhirUser::Absent,
            None,
            Reach::Nothing,
        )
    );
}

/// Posts the Logout Token `token` to the back-channel logout URI and
/// returns the status, the headers and the body.
async fn log_out(smart: &Smart, token: &str) -> (StatusCode, http::HeaderMap, String) {
    smart
        .post("/backchannel-logout", &[("logout_token", token)], None)
        .await
}

#[tokio::test]
async fn a_back_channel_logout_ends_the_online_access_grants_of_the_login() {
    let (smart, body) = launch_with("online_access").await;
    let token = body["refresh_token"].as_str().expect("a refresh token");
    let access: Value = jsonwebtoken::dangerous::insecure_decode_claims(
        body["access_token"].as_str().expect("a token"),
    )
    .expect("claims");
    let logout = smart.provider.logout_token(&json!({}));
    // NOTE: Back-Channel Logout 1.0 §2.8, a 200 that is never cached.
    let (status, headers, _) = log_out(&smart, &logout).await;
    assert_eq!(StatusCode::OK, status, "the logout succeeds");
    assert_eq!(
        Some("no-store"),
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        "Back-Channel Logout 1.0 §2.8, SHOULD include no-store"
    );
    // NOTE: Back-Channel Logout 1.0 §2.7, a refresh token without offline_access
    // SHOULD be revoked; docs/architecture.md §13.6 item 7.
    let (status, refused) = refresh(&smart, token).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{refused}");
    assert_eq!(json!("invalid_grant"), refused["error"]);
    let jti = access["jti"].as_str().expect("a jti");
    assert!(
        smart.store.revoked(jti).await.expect("read"),
        "the grant's access token is revoked with it"
    );
    // NOTE: DICOM PS3.15 A.5.3.12, the session end commits with its Logout record.
    let logged_out = |records: &[Value]| {
        records
            .iter()
            .filter(|record| {
                record.pointer("/type/code") == Some(&json!("110114"))
                    && record.pointer("/subtype/0/code") == Some(&json!("110123"))
            })
            .count()
    };
    let stored = records(&smart.store).await;
    assert_eq!(1, logged_out(&stored), "one Logout record");
    assert!(events(&stored).contains(&String::from("session-ended")));
    let (status, _, _) = log_out(&smart, &logout).await;
    assert_eq!(StatusCode::OK, status, "a second logout ends nothing more");
    assert_eq!(
        1,
        logged_out(&records(&smart.store).await),
        "a logout that ends nothing writes nothing"
    );
    smart.stop().await;
}

#[tokio::test]
async fn a_back_channel_logout_leaves_an_offline_access_grant() {
    let (smart, body) = launch_with("offline_access").await;
    let token = body["refresh_token"].as_str().expect("a refresh token");
    let logout = smart.provider.logout_token(&json!({}));
    let (status, _, _) = log_out(&smart, &logout).await;
    assert_eq!(StatusCode::OK, status, "the logout succeeds");
    // NOTE: Back-Channel Logout 1.0 §2.7, offline_access SHOULD NOT be revoked.
    let (status, renewed) = refresh(&smart, token).await;
    assert_eq!(StatusCode::OK, status, "{renewed}");
    smart.stop().await;
}

#[tokio::test]
async fn a_logout_token_that_does_not_check_is_a_400() {
    let (smart, body) = launch_with("online_access").await;
    let token = body["refresh_token"].as_str().expect("a refresh token");
    let cases = [
        smart
            .provider
            .logout_token(&json!({"aud": "another-client"})),
        smart.provider.logout_token(&json!({"events": {}})),
        smart.provider.logout_token(&json!({"nonce": "n-1"})),
        String::from("not-a-token"),
    ];
    for logout in &cases {
        let (status, headers, refused) = log_out(&smart, logout).await;
        // NOTE: Back-Channel Logout 1.0 §2.6 and §2.8, a 400 with an error body.
        assert_eq!(StatusCode::BAD_REQUEST, status, "{refused}");
        assert!(refused.contains("invalid_request"), "{refused}");
        assert_eq!(
            Some("no-store"),
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            "never cached"
        );
    }
    let (status, _, _) = smart.post("/backchannel-logout", &[], None).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "no logout_token");
    let (status, renewed) = refresh(&smart, token).await;
    assert_eq!(StatusCode::OK, status, "the login lives on: {renewed}");
    smart.stop().await;
}

/// A FHIR server that holds the patient `p-1`, which only the person whose
/// `fhirUser` is `Practitioner/synthetic-1` may see, and keeps the claims
/// of every token it was shown.
struct Fhir {
    /// The claims of the tokens it was shown.
    seen: Arc<std::sync::Mutex<Vec<Value>>>,
}

impl wiremock::Respond for Fhir {
    fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
        let token = request
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .unwrap_or_default();
        let Ok(claims) = jsonwebtoken::dangerous::insecure_decode_claims::<Value>(token) else {
            return ResponseTemplate::new(401);
        };
        // The clinician sees every patient; the patient p-1 sees their own record.
        let allowed = claims.get("scope") == Some(&json!("user/Patient.rs"))
            && (claims.get("fhirUser") == Some(&json!("Practitioner/synthetic-1"))
                || claims
                    .get("fhirUser")
                    .and_then(Value::as_str)
                    .is_some_and(|user| {
                        user == "Patient/p-1" || user.ends_with("/fhir/Patient/p-1")
                    }));
        self.seen.lock().expect("held").push(claims);
        let patient = json!({
            "resourceType": "Patient", "id": "p-1",
            "name": [{"given": ["Synthetic"], "family": "Patient"}],
            "birthDate": "1970-01-01", "gender": "other",
            "identifier": [{"system": "urn:example:mrn", "value": "MRN-1"}]
        });
        if let Some((_, id)) = request.url.path().rsplit_once("/Patient/") {
            return match (allowed, id) {
                (true, "p-1") => ResponseTemplate::new(200).set_body_json(patient),
                (true, _) => ResponseTemplate::new(404),
                (false, _) => ResponseTemplate::new(403),
            };
        }
        let entry = if allowed {
            vec![json!({ "resource": patient })]
        } else {
            Vec::new()
        };
        ResponseTemplate::new(200)
            .set_body_json(json!({ "resourceType": "Bundle", "type": "searchset", "entry": entry }))
    }
}

/// Starts FerroSMART over a FHIR server for a standalone launch with
/// `launch/patient`, and returns them with the claims the server sees.
async fn picker_launch() -> (Smart, MockServer, Arc<std::sync::Mutex<Vec<Value>>>) {
    let fhir = MockServer::start().await;
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    Mock::given(matchers::method("GET"))
        .respond_with(Fhir {
            seen: Arc::clone(&seen),
        })
        .mount(&fhir)
        .await;
    let base = format!("{}/fhir", fhir.uri());
    let smart = Smart::start_on(
        "[\"authorization_code\"]",
        "[\"openid\", \"fhirUser\", \"launch/patient\", \"patient/Observation.rs\"]",
        "[\"patient/Observation.rs\"]",
        Some(&base),
    )
    .await;
    (smart, fhir, seen)
}

/// Runs the standalone launch to the picker as the person `subject` with
/// `fhir_user`, and returns the cookie.
async fn to_picker(smart: &Smart, base: &str, subject: &str, fhir_user: &str) -> String {
    to_picker_asking(
        smart,
        base,
        "openid fhirUser launch/patient patient/Observation.rs",
        subject,
        fhir_user,
    )
    .await
}

/// Runs the standalone launch asking for `scope` at `base` to the picker as
/// the person `subject` with `fhir_user`, and returns the cookie.
async fn to_picker_asking(
    smart: &Smart,
    base: &str,
    scope: &str,
    subject: &str,
    fhir_user: &str,
) -> String {
    let path = authorize_path(&[("aud", base), ("scope", scope)]);
    let (_, headers, _) = smart.get(&path, None).await;
    let upstream = location(&headers);
    let cookie = set_cookie(&headers);
    smart
        .provider
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
    let (status, headers, _) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(
        StatusCode::SEE_OTHER,
        status,
        "the callback sends the browser on"
    );
    // NOTE: SMART App Launch 2.2.0, Obtain authorization code, a standalone
    // launch/patient is answered by the patient selection widget.
    assert_eq!("/picker", location(&headers).path(), "to the picker");
    cookie
}

/// Returns the form token of the page `page`.
pub(crate) fn form_token(page: &str) -> String {
    page.split("name=\"form_token\" value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("a form token")
        .to_owned()
}

/// Runs the standalone launch asking `scope` at `base` through the callback
/// as the person `subject` with `fhir_user` and no role, and returns the
/// cookie with the callback's answer.
async fn as_patient(
    smart: &Smart,
    base: &str,
    scope: &str,
    fhir_user: &str,
) -> (String, (StatusCode, http::HeaderMap, String)) {
    let path = authorize_path(&[("aud", base), ("scope", scope)]);
    let (_, headers, _) = smart.get(&path, None).await;
    let upstream = location(&headers);
    let cookie = set_cookie(&headers);
    smart
        .provider
        .answer_as(
            &param(&upstream, "nonce").expect("a nonce"),
            &[],
            "synthetic-patient",
            fhir_user,
        )
        .await;
    let callback = format!(
        "/callback?code=synthetic-upstream-code&state={}",
        param(&upstream, "state").expect("a state")
    );
    let answer = smart.get(&callback, Some(&cookie)).await;
    (cookie, answer)
}

// NOTE: SMART App Launch 2.2.0, Obtain authorization code: the server acquires
// the context it needs; a patient's own record needs no picker (#673).
#[tokio::test]
async fn a_patient_gets_their_own_record_in_context_with_no_picker_and_no_role() {
    let (smart, fhir, seen) = picker_launch().await;
    let base = format!("{}/fhir", fhir.uri());
    for fhir_user in ["Patient/p-1", &format!("{base}/Patient/p-1")] {
        let (cookie, (status, headers, body)) = as_patient(
            &smart,
            &base,
            "openid fhirUser launch/patient patient/Observation.rs",
            fhir_user,
        )
        .await;
        assert_eq!(StatusCode::SEE_OTHER, status, "{body}");
        assert_eq!(
            "/consent",
            location(&headers).path(),
            "no picker: {fhir_user}"
        );
        let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
        assert!(
            page.contains("value=\"patient/Observation.rs\""),
            "their own patient/ scope with no role: {page}"
        );
        let token = form_token(&page);
        let (_, headers, _) = smart
            .post(
                "/consent",
                &[
                    ("form_token", token.as_str()),
                    ("decision", "approve"),
                    ("scope", "openid"),
                    ("scope", "fhirUser"),
                    ("scope", "launch/patient"),
                    ("scope", "patient/Observation.rs"),
                ],
                Some(&cookie),
            )
            .await;
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
        let body: Value = serde_json::from_str(&body).expect("JSON");
        assert_eq!(json!("p-1"), body["patient"]);
        assert_eq!(
            json!("openid fhirUser launch/patient patient/Observation.rs"),
            body["scope"]
        );
        // NOTE: docs/architecture.md §3.13, a resource server reads the patient's
        // own token under the `ferrosmart` preset as the person (#681).
        let (_, _, jwks) = smart.get("/jwks", None).await;
        let caller = crate::support::read_under_preset(
            &serde_json::from_str(&jwks).expect("a JWK Set"),
            ISSUER,
            &base,
            ferrohealth_smart::kind::IssuerKind::Persons,
            &crate::support::one_table("app"),
            body["access_token"].as_str().expect("a token"),
        )
        .await
        .expect("admitted");
        assert!(caller.is_the_person(), "{fhir_user}: {:?}", caller.kind());
    }
    // NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, the record is read
    // again as the person before it is put in context.
    let reads = seen.lock().expect("held").clone();
    assert!(
        reads
            .iter()
            .any(|claims| claims.get("fhirUser") == Some(&json!("Patient/p-1"))),
        "{reads:?}"
    );
    smart.stop().await;
}

#[tokio::test]
async fn a_patient_whose_own_record_cannot_be_read_is_told_so_and_never_picks() {
    let (smart, fhir, _) = picker_launch().await;
    let base = format!("{}/fhir", fhir.uri());
    let (_, (status, headers, page)) = as_patient(
        &smart,
        &base,
        "openid fhirUser launch/patient patient/Observation.rs",
        "Patient/p-2",
    )
    .await;
    assert_eq!(StatusCode::FORBIDDEN, status, "{page}");
    assert!(headers.get(header::LOCATION).is_none(), "never the picker");
    assert!(
        page.contains("Your own record cannot be opened here"),
        "{page}"
    );
    smart.stop().await;
}

#[tokio::test]
async fn a_patient_at_another_server_s_record_still_picks() {
    let (smart, fhir, _) = picker_launch().await;
    let base = format!("{}/fhir", fhir.uri());
    let (_, (status, headers, _)) = as_patient(
        &smart,
        &base,
        "openid fhirUser launch/patient",
        "https://elsewhere.example.org/fhir/Patient/p-1",
    )
    .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    assert_eq!(
        "/picker",
        location(&headers).path(),
        "not their record here"
    );
    smart.stop().await;
}

// NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, Standalone apps: the
// server may infer launch/patient for a patient/ scope (#669).
#[tokio::test]
async fn a_standalone_patient_scope_without_launch_patient_goes_to_the_picker() {
    let (smart, fhir, _) = picker_launch().await;
    let base = format!("{}/fhir", fhir.uri());
    let cookie = to_picker_asking(
        &smart,
        &base,
        "openid fhirUser patient/Observation.rs",
        "synthetic-person",
        "Practitioner/synthetic-1",
    )
    .await;
    let (_, _, page) = smart.get("/picker?name=Synthetic", Some(&cookie)).await;
    let token = form_token(&page);
    let (_, headers, _) = smart
        .post(
            "/picker",
            &[("form_token", &token), ("patient", "p-1")],
            Some(&cookie),
        )
        .await;
    assert_eq!("/consent", location(&headers).path());
    let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
    assert!(page.contains("value=\"patient/Observation.rs\""), "{page}");
    let token = form_token(&page);
    let (_, headers, _) = smart
        .post(
            "/consent",
            &[
                ("form_token", token.as_str()),
                ("decision", "approve"),
                ("scope", "openid"),
                ("scope", "fhirUser"),
                ("scope", "launch/patient"),
                ("scope", "patient/Observation.rs"),
            ],
            Some(&cookie),
        )
        .await;
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
    let body: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(
        json!("openid fhirUser patient/Observation.rs launch/patient"),
        body["scope"],
        "the granted scope names the inferred launch/patient"
    );
    assert_eq!(json!("p-1"), body["patient"]);
    smart.stop().await;
}

#[tokio::test]
async fn a_standalone_launch_picks_a_patient_the_person_may_see() {
    let (smart, fhir, seen) = picker_launch().await;
    let base = format!("{}/fhir", fhir.uri());
    let cookie = to_picker(
        &smart,
        &base,
        "synthetic-person",
        "Practitioner/synthetic-1",
    )
    .await;
    let (status, _, page) = smart.get("/picker", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(page.contains("<h1 class=\"fui-page-card-title\">Choose a patient</h1>"));
    let (status, _, page) = smart.get("/picker?name=Synthetic", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(
        page.contains("value=\"p-1\"") && page.contains("Synthetic Patient"),
        "{page}"
    );
    let token = form_token(&page);
    let (status, headers, _) = smart
        .post(
            "/picker",
            &[("form_token", &token), ("patient", "p-1")],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    assert_eq!("/consent", location(&headers).path());
    let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
    let token = form_token(&page);
    let (_, headers, _) = smart
        .post(
            "/consent",
            &[
                ("form_token", token.as_str()),
                ("decision", "approve"),
                ("scope", "openid"),
                ("scope", "launch/patient"),
                ("scope", "patient/Observation.rs"),
            ],
            Some(&cookie),
        )
        .await;
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
    let body: Value = serde_json::from_str(&body).expect("JSON");
    // NOTE: SMART App Launch 2.2.0, Launch context arrives with your access_token.
    assert_eq!(json!("p-1"), body["patient"]);
    let access: Value = jsonwebtoken::dangerous::insecure_decode_claims(
        body["access_token"].as_str().expect("a token"),
    )
    .expect("claims");
    assert_eq!(json!("p-1"), access["patient"], "the token carries it too");

    // The picker searched and read as the person, with a token for this
    // request alone, revoked once it was answered.
    let shown = seen.lock().expect("held").clone();
    assert_eq!(2, shown.len(), "the search and the read");
    for claims in &shown {
        assert_eq!(access["sub"], claims["sub"], "the person, never a system");
        assert_eq!(json!("Practitioner/synthetic-1"), claims["fhirUser"]);
        assert_eq!(json!(base), claims["aud"]);
        let lifetime = claims["exp"].as_i64().expect("exp") - claims["iat"].as_i64().expect("iat");
        assert!(lifetime <= 30, "a minimal lifetime: {lifetime}");
        let jti = claims["jti"].as_str().expect("a jti");
        assert!(
            smart.store.revoked(jti).await.expect("read"),
            "revoked after use"
        );
    }
    let stored = records(&smart.store).await;
    let happened = events(&stored);
    assert!(
        happened.contains(&String::from("picker-token")),
        "{happened:?}"
    );
    // NOTE: Regulation (EU) 2025/327 Annex II 3.2, the search and the read are
    // each an access record.
    let accesses = stored
        .iter()
        .filter(|record| {
            matches!(
                record.pointer("/subtype/0/code").and_then(Value::as_str),
                Some("search" | "read")
            )
        })
        .count();
    let subtypes: Vec<_> = stored
        .iter()
        .map(|record| record.pointer("/subtype"))
        .collect();
    assert_eq!(2, accesses, "{subtypes:?}");
    smart.stop().await;
}

// NOTE: FerroHEALTH/FerroUI#686: FerroSMART's own mark, the shield with the
// keyhole, drawn by FerroUI on the consent, picker and error pages.
#[tokio::test]
async fn every_page_draws_the_ferrosmart_mark() {
    let mark = "fui-mark fui-mark-ferrosmart";
    let smart = Smart::start().await;
    let (cookie, _) = to_consent(&smart, &["clinician"]).await;
    let (_, _, consent) = smart.get("/consent", Some(&cookie)).await;
    assert!(consent.contains(mark), "the consent page: {consent}");
    let (status, _, fault) = smart.get("/consent", None).await;
    assert!(status.is_client_error(), "{status}");
    assert!(fault.contains(mark), "an error page: {fault}");
    smart.stop().await;
    let (smart, fhir, _seen) = picker_launch().await;
    let base = format!("{}/fhir", fhir.uri());
    let cookie = to_picker(
        &smart,
        &base,
        "synthetic-person",
        "Practitioner/synthetic-1",
    )
    .await;
    let (_, _, picker) = smart.get("/picker", Some(&cookie)).await;
    assert!(picker.contains(mark), "the picker: {picker}");
    smart.stop().await;
}

#[tokio::test]
async fn a_person_never_sees_or_picks_a_patient_they_may_not_see() {
    let (smart, fhir, _seen) = picker_launch().await;
    let base = format!("{}/fhir", fhir.uri());
    let cookie = to_picker(&smart, &base, "other-person", "Practitioner/synthetic-2").await;
    let (status, _, page) = smart.get("/picker?name=Synthetic", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(
        !page.contains("p-1"),
        "the server shows them no such patient: {page}"
    );
    assert!(page.contains("No patient you may see matches the search."));
    let token = smart
        .store
        .pending(&cookie)
        .await
        .expect("read")
        .expect("pending")
        .form_token;
    let (status, _, _) = smart
        .post(
            "/picker",
            &[("form_token", &token), ("patient", "p-1")],
            Some(&cookie),
        )
        .await;
    assert_eq!(
        StatusCode::BAD_REQUEST,
        status,
        "a forged choice is refused"
    );
    let (_, headers, _) = smart.get("/consent", Some(&cookie)).await;
    assert_eq!(
        "/picker",
        location(&headers).path(),
        "no patient entered the context"
    );
    smart.stop().await;
}

#[tokio::test]
async fn a_failed_search_is_an_error_page_never_an_empty_context() {
    let fhir = MockServer::start().await;
    Mock::given(matchers::method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&fhir)
        .await;
    let base = format!("{}/fhir", fhir.uri());
    let smart = Smart::start_on(
        "[\"authorization_code\"]",
        "[\"openid\", \"fhirUser\", \"launch/patient\", \"patient/Observation.rs\"]",
        "[\"patient/Observation.rs\"]",
        Some(&base),
    )
    .await;
    let cookie = to_picker(
        &smart,
        &base,
        "synthetic-person",
        "Practitioner/synthetic-1",
    )
    .await;
    let (status, _, page) = smart.get("/picker?name=Synthetic", Some(&cookie)).await;
    assert_eq!(StatusCode::INTERNAL_SERVER_ERROR, status, "{page}");
    assert!(!page.contains("No patient"), "a failure is no empty result");
    let pending = smart
        .store
        .pending(&cookie)
        .await
        .expect("read")
        .expect("pending");
    assert!(pending.launch_context.is_none(), "no context entered");
    smart.stop().await;
}

// NOTE: SMART App Launch 2.2.0, App Launch, Considerations for CORS support: the token
// endpoint is readable from a client's registered origins and from no other.
#[tokio::test]
async fn a_token_response_is_readable_from_the_app_s_origin_alone() {
    let smart = Smart::start().await;
    let (cookie, token) = to_consent(&smart, &["clinician"]).await;
    let (_, headers, _) = smart
        .post(
            "/consent",
            &[
                ("form_token", &token),
                ("decision", "approve"),
                ("scope", "openid"),
                ("scope", "user/Observation.rs"),
            ],
            Some(&cookie),
        )
        .await;
    let code = param(&location(&headers), "code").expect("a code");
    let exchange = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("client_id", "app"),
    ];
    let allowed = |headers: &http::HeaderMap| {
        headers
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let (status, headers, body) = smart
        .post_from("/token", &exchange, "https://app.example.org")
        .await;
    assert_eq!(StatusCode::OK, status, "{body}");
    assert_eq!(
        Some(String::from("https://app.example.org")),
        allowed(&headers)
    );
    assert!(
        headers
            .get_all(header::VARY)
            .iter()
            .any(|value| value.as_bytes().eq_ignore_ascii_case(b"origin")),
        "the answer varies by origin"
    );

    // A second use is refused; from another origin the browser reads nothing.
    let (status, headers, _) = smart
        .post_from("/token", &exchange, "https://elsewhere.example.org")
        .await;
    assert_eq!(StatusCode::BAD_REQUEST, status);
    assert_eq!(None, allowed(&headers));
    let (_, headers, _) = smart.post_from("/token", &exchange, "null").await;
    assert_eq!(None, allowed(&headers));
    smart.stop().await;
}

mod approval;
mod assurance;
mod consent_basis;
mod core_op;
mod ehr_picker;
mod encounter_picker;
mod fhir_user_lookup;
mod logout;
mod paired_picker;
mod picker_purpose;
mod preset;
mod providers;
mod public_redirect;
mod saml;
mod secret_basic;
mod token_exchange;

/// The capabilities FerroSMART supports with a FHIR resource server and a
/// SMART style document configured, each with the case that exercises it
/// (`docs/architecture.md` §13.23).
const SUPPORTED: [(&str, &str); 19] = [
    (
        "authorize-post",
        "an_authorization_request_by_post_is_the_get_s_twin",
    ),
    (
        "client-confidential-asymmetric",
        "token::a_backend_services_client_gets_an_rfc_9068_token",
    ),
    (
        "client-confidential-symmetric",
        "symmetric::a_symmetric_client_authenticates_by_http_basic",
    ),
    (
        "client-public",
        "a_standalone_launch_logs_in_upstream_asks_consent_and_issues_tokens",
    ),
    (
        "context-banner",
        "ehr_launch::an_ehr_launch_carries_its_context_to_the_token_response",
    ),
    (
        "context-ehr-encounter",
        "ehr_launch::an_ehr_launch_carries_its_context_to_the_token_response",
    ),
    (
        "context-ehr-patient",
        "ehr_launch::an_ehr_launch_carries_its_context_to_the_token_response",
    ),
    (
        "context-standalone-encounter",
        "encounter_picker::a_standalone_launch_picks_an_encounter_of_the_chosen_patient",
    ),
    (
        "context-standalone-patient",
        "a_standalone_launch_picks_a_patient_the_person_may_see",
    ),
    (
        "context-style",
        "a_standalone_launch_logs_in_upstream_asks_consent_and_issues_tokens",
    ),
    (
        "launch-ehr",
        "ehr_launch::an_ehr_launch_carries_its_context_to_the_token_response",
    ),
    (
        "launch-standalone",
        "a_standalone_launch_logs_in_upstream_asks_consent_and_issues_tokens",
    ),
    (
        "permission-offline",
        "an_offline_access_launch_issues_a_refresh_token_that_rotates",
    ),
    (
        "permission-online",
        "an_online_access_launch_ends_with_its_upstream_login",
    ),
    (
        "permission-patient",
        "a_standalone_launch_picks_a_patient_the_person_may_see",
    ),
    (
        "permission-user",
        "a_standalone_launch_logs_in_upstream_asks_consent_and_issues_tokens",
    ),
    (
        "permission-v1",
        "a_v1_scope_is_offered_by_its_v2_form_and_granted_as_asked",
    ),
    (
        "permission-v2",
        "a_standalone_launch_logs_in_upstream_asks_consent_and_issues_tokens",
    ),
    (
        "sso-openid-connect",
        "a_standalone_launch_logs_in_upstream_asks_consent_and_issues_tokens",
    ),
];

// NOTE: RFC 8414 §2, `grant_types_supported` lists the grant types the
// server supports, and RFC 6749 §5.2 refuses any other as unsupported.
#[tokio::test]
async fn with_a_login_every_listed_grant_is_served_and_every_served_one_listed() {
    let smart = Smart::start().await;
    let read = |body: String| -> Vec<String> {
        crate::support::listed_grants(&serde_json::from_str(&body).expect("JSON"))
    };
    let (_, _, metadata) = smart
        .get("/.well-known/oauth-authorization-server", None)
        .await;
    let listed = read(metadata);
    assert_eq!(
        vec![
            "authorization_code",
            "client_credentials",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:token-exchange"
        ],
        listed
    );
    let (_, _, openid) = smart.get("/.well-known/openid-configuration", None).await;
    assert_eq!(
        listed,
        read(openid),
        "both metadata documents list the same"
    );
    // NOTE: SMART App Launch 2.2.0, Conformance, Metadata, `grant_types_supported`
    // names two options, so the SMART document keeps those of the metadata.
    let (_, _, smart_document) = smart.get("/.well-known/smart-configuration", None).await;
    assert_eq!(
        vec!["authorization_code", "client_credentials"],
        read(smart_document)
    );
    for grant in crate::support::GRANT_TYPES {
        let (_, _, body) = smart.post("/token", &[("grant_type", grant)], None).await;
        let answer: Value = serde_json::from_str(&body).expect("JSON");
        let supported = answer["error"] != json!("unsupported_grant_type");
        assert_eq!(
            listed.iter().any(|listed| listed == grant),
            supported,
            "{grant}"
        );
    }
    smart.stop().await;
}

// NOTE: SMART App Launch 2.2.0, Conformance, Metadata: `capabilities` lists the
// SMART capabilities "that the server supports", and nothing else.
#[tokio::test]
async fn the_document_lists_exactly_the_capabilities_the_server_supports() {
    let fhir = MockServer::start().await;
    let smart = Smart::start_on(
        "[\"authorization_code\"]",
        "[\"openid\", \"fhirUser\"]",
        "[\"user/Observation.rs\"]",
        Some(&format!("{}/fhir", fhir.uri())),
    )
    .await;
    let (_, _, body) = smart.get("/.well-known/smart-configuration", None).await;
    let document: Value = serde_json::from_str(&body).expect("JSON");
    let mut listed: Vec<String> = document["capabilities"]
        .as_array()
        .expect("capabilities")
        .iter()
        .map(|capability| capability.as_str().expect("a string").to_owned())
        .collect();
    listed.sort();
    let supported: Vec<String> = SUPPORTED
        .iter()
        .map(|(capability, _)| (*capability).to_owned())
        .collect();
    assert_eq!(supported, listed);
    for (capability, case) in SUPPORTED {
        let (source, name) = match case.split_once("::") {
            Some(("token", name)) => (include_str!("token.rs"), name),
            Some(("ehr_launch", name)) => (include_str!("ehr_launch.rs"), name),
            Some(("symmetric", name)) => (include_str!("symmetric.rs"), name),
            Some(("encounter_picker", name)) => {
                (include_str!("authorize/encounter_picker.rs"), name)
            }
            Some((module, _)) => panic!("{capability}: no source for {module}"),
            None => (include_str!("authorize.rs"), case),
        };
        assert!(
            source.contains(&format!("fn {name}()")),
            "{capability}: the case {case} exists"
        );
    }
    // NOTE: SMART App Launch 2.2.0, Client Authentication: Asymmetric, Advertising
    // server support, the algorithms beside `private_key_jwt`.
    assert_eq!(
        json!(["RS384", "ES384"]),
        document["token_endpoint_auth_signing_alg_values_supported"]
    );
    assert_eq!(
        json!(["S256"]),
        document["code_challenge_methods_supported"]
    );
    assert_eq!(
        json!(["authorization_code", "client_credentials"]),
        document["grant_types_supported"]
    );
    assert_eq!(
        json!([
            "openid",
            "fhirUser",
            "profile",
            "email",
            "launch",
            "launch/patient",
            "launch/encounter",
            "offline_access",
            "online_access"
        ]),
        document["scopes_supported"]
    );
    smart.stop().await;
}

// NOTE: SMART App Launch 2.2.0, Conformance, Capabilities, the capabilities the
// server does not support stay unlisted and their requests are refused.
#[tokio::test]
async fn what_the_document_leaves_out_the_server_refuses() {
    let smart = Smart::start().await;
    let (_, _, body) = smart.get("/.well-known/smart-configuration", None).await;
    let document: Value = serde_json::from_str(&body).expect("JSON");
    let listed = document["capabilities"].as_array().expect("capabilities");
    assert!(
        !listed.contains(&json!("smart-app-state")),
        "App State lives at the resource server"
    );
    let client = resolve(&[ClientSection {
        client_id: String::from("app"),
        kind: ClientKind::Public,
        redirect_uris: vec![String::from(REDIRECT)],
        grant_types: vec![GrantType::AuthorizationCode],
        scopes: vec![
            String::from("launch/patient"),
            String::from("launch/encounter"),
        ],
        ..ClientSection::default()
    }])
    .expect("admitted")
    .remove(0);
    let roles = std::collections::BTreeMap::new();
    assert_eq!(
        vec!["launch/patient"],
        offer(
            "launch/patient launch/encounter",
            &client,
            &[],
            &roles,
            FhirUser::Present,
            None,
            Reach::Patient
        ),
        "at an openEHR server the picker puts a patient in context and no encounter"
    );
    assert_eq!(
        vec!["launch/encounter"],
        offer(
            "launch/encounter",
            &client,
            &[],
            &roles,
            FhirUser::Present,
            Some(&ferrosmart::launch::context::Context {
                encounter: Some(String::from("e-1")),
                ..ferrosmart::launch::context::Context::default()
            }),
            Reach::Nothing
        ),
        "an EHR launch's encounter is offered"
    );
    assert!(
        offer(
            "launch/encounter",
            &client,
            &[],
            &roles,
            FhirUser::Present,
            None,
            Reach::Encounter
        )
        .is_empty(),
        "the picker chooses an encounter only with a patient"
    );
    smart.stop().await;
}

// NOTE: SMART App Launch 2.2.0, Obtain authorization code, the endpoint SHALL
// support both GET and POST (`authorize-post`).
#[tokio::test]
async fn an_authorization_request_by_post_is_the_get_s_twin() {
    let smart = Smart::start().await;
    let path = authorize_path(&[]);
    let query = path.split_once('?').expect("a query").1.to_owned();
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    let borrowed: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let (status, headers, _) = smart.post("/authorize", &borrowed, None).await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let upstream = location(&headers);
    assert!(
        upstream.as_str().starts_with(&smart.provider.server.uri()),
        "the browser goes to the provider"
    );
    assert!(param(&upstream, "state").is_some() && param(&upstream, "nonce").is_some());
    smart.stop().await;
}

// NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, Scopes for requesting
// FHIR Resources: v1 scopes are processed as v2 and returned as v1.
#[test]
fn a_v1_scope_is_offered_by_its_v2_form_and_granted_as_asked() {
    let client = resolve(&[ClientSection {
        client_id: String::from("app"),
        kind: ClientKind::Public,
        redirect_uris: vec![String::from(REDIRECT)],
        grant_types: vec![GrantType::AuthorizationCode],
        scopes: vec![String::from("user/Observation.rs")],
        ..ClientSection::default()
    }])
    .expect("admitted")
    .remove(0);
    let roles = [(
        String::from("clinician"),
        vec![String::from("user/Observation.rs")],
    )]
    .into_iter()
    .collect();
    let held = vec![String::from("clinician")];
    assert_eq!(
        vec!["user/Observation.read"],
        offer(
            "user/Observation.read user/Observation.write user/Patient.read",
            &client,
            &held,
            &roles,
            FhirUser::Present,
            None,
            Reach::Nothing
        )
    );
}
