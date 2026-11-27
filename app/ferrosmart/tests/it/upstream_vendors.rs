// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The contract of FerroSMART's upstream login with the two hosted providers
//! it is documented against, Microsoft Entra ID (#524) and Okta (#525).
//! Neither runs in a container, so a stub serves the discovery document,
//! the key set and the token answer each publishes, at its own paths, and
//! the example configuration under `examples/` drives a SMART standalone
//! launch through it to a token whose ID Token carries the mapped
//! `fhirUser`. FerroSMART holds no code for either provider.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use ferrohealth_smart::client::assertion::AssertionKey;
use ferrohealth_smart::metadata::DiscoveryError;
use ferrohealth_smart::oidc::OidcError;
use ferrosmart::authorize::COOKIE;
use ferrosmart::config::Config;
use ferrosmart::server::{AppState, router};
use ferrosmart::store::Store;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt as _;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use url::Url;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

use crate::support::{Database, Keys, audit, from_client, rsa_key};

/// The Entra ID example, run as published.
const ENTRA: &str = include_str!("../../examples/entra/ferrosmart.toml");
/// The Entra ID example's app.
const ENTRA_APP: &str = include_str!("../../examples/entra/example-app.json");
/// The Okta example, run as published.
const OKTA: &str = include_str!("../../examples/okta/ferrosmart.toml");
/// The Okta example's app.
const OKTA_APP: &str = include_str!("../../examples/okta/example-app.json");
/// The examples' SMART app and its redirect URI.
const APP: &str = "example-app";
/// The redirect URI of [`APP`].
const REDIRECT: &str = "https://app.example.org/callback";
/// The examples' FHIR resource server.
const RESOURCE: &str = "https://ehr.example.org/fhir";
/// The `fhirUser` the provider holds for the person.
const FHIR_USER: &str = "https://ehr.example.org/fhir/RelatedPerson/example-1";
/// The app's PKCE verifier and its S256 challenge (RFC 7636 Appendix B).
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// The challenge of [`VERIFIER`].
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// The `kid` of the stub's signing key.
const KID: &str = "synthetic-key-1";

/// What one provider publishes, at paths under its issuer's path.
struct Contract {
    /// The example configuration.
    example: &'static str,
    /// The client document of its app.
    app: &'static str,
    /// The paths its metadata is served at, each given the issuer path.
    discovery: fn(&str) -> Vec<String>,
    /// Its metadata, given the issuer.
    metadata: fn(&str) -> Value,
    /// The path of its key set, given the issuer path.
    jwks: fn(&str) -> String,
    /// The path of its token endpoint, given the issuer path.
    token: fn(&str) -> String,
    /// The ID Token claims beyond `iss`, `aud`, `nonce`, `iat` and `exp`.
    claims: Value,
}

/// Microsoft Entra ID's v2.0 tenant authority.
///
/// The metadata names the endpoints `v2-protocols-oidc.md` (OIDC endpoint
/// overview, Fetch the OpenID configuration document) places under
/// `https://login.microsoftonline.com/{tenant}`, and the client
/// authentication methods its sample lists with the Basic form
/// `v2-oauth2-auth-code-flow.md` (Request an access token with a
/// `client_secret`) supports. The claims are those
/// `id-token-claims-reference.md` (Payload claims) lists for a v2.0 ID
/// Token, with the app roles and the `extn.` optional claim. Entra serves its
/// UserInfo Endpoint at `https://graph.microsoft.com/oidc/userinfo`; the stub
/// serves it under the tenant, since no case reaches the network.
fn entra() -> Contract {
    Contract {
        example: ENTRA,
        app: ENTRA_APP,
        discovery: |path| vec![format!("{path}/.well-known/openid-configuration")],
        metadata: |issuer| {
            let tenant = issuer.trim_end_matches("/v2.0");
            json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{tenant}/oauth2/v2.0/authorize"),
                "token_endpoint": format!("{tenant}/oauth2/v2.0/token"),
                "token_endpoint_auth_methods_supported":
                    ["client_secret_post", "private_key_jwt", "client_secret_basic"],
                "jwks_uri": format!("{tenant}/discovery/v2.0/keys"),
                "end_session_endpoint": format!("{tenant}/oauth2/v2.0/logout"),
                "response_types_supported": ["code", "id_token", "code id_token", "id_token token"],
                "response_modes_supported": ["query", "fragment", "form_post"],
                "scopes_supported": ["openid", "profile", "email", "offline_access"],
                "subject_types_supported": ["pairwise"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "userinfo_endpoint": format!("{tenant}/oidc/userinfo")
            })
        },
        jwks: |path| format!("{}/discovery/v2.0/keys", path.trim_end_matches("/v2.0")),
        token: |path| format!("{}/oauth2/v2.0/token", path.trim_end_matches("/v2.0")),
        claims: json!({
            "ver": "2.0",
            "sub": "AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ",
            "oid": "00000000-0000-0000-66f3-3332eca7ea81",
            "tid": "aaaabbbb-0000-cccc-1111-dddd2222eeee",
            "name": "Example Clinician",
            "preferred_username": "clinician@example.org",
            "roles": ["clinician"],
            "extn.fhirUser": FHIR_USER,
            "aio": "synthetic-aio",
            "rh": "synthetic-rh",
            "sid": "00000000-0000-0000-0000-000000000001",
            "uti": "synthetic-uti"
        }),
    }
}

/// Okta's `default` custom authorization server.
///
/// It serves its RFC 8414 metadata and its OpenID Connect metadata (Okta,
/// Authorization servers, Discovery endpoints - custom authorization
/// server), with the endpoints and members the OpenID Connect & OAuth 2.0
/// API reference (Custom Authorization Servers, Retrieve the OAuth 2.0
/// metadata) names. The claims are the ID Token's base claims, the
/// `profile` claims, the groups claim and the custom `fhir_user` claim
/// (Overview, ID token claims; Customize tokens returned from Okta, Add a
/// custom claim to a token). OpenID Connect Core 1.0 §2 has `nonce` in it.
fn okta() -> Contract {
    Contract {
        example: OKTA,
        app: OKTA_APP,
        discovery: |path| {
            vec![
                format!("/.well-known/oauth-authorization-server{path}"),
                format!("{path}/.well-known/openid-configuration"),
            ]
        },
        metadata: |issuer| {
            json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/v1/authorize"),
                "token_endpoint": format!("{issuer}/v1/token"),
                "jwks_uri": format!("{issuer}/v1/keys"),
                "end_session_endpoint": format!("{issuer}/v1/logout"),
                "revocation_endpoint": format!("{issuer}/v1/revoke"),
                "introspection_endpoint": format!("{issuer}/v1/introspect"),
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported":
                    ["client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "none"],
                "response_types_supported": ["code", "id_token", "code id_token"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "scopes_supported": ["openid", "profile", "email", "address", "phone", "offline_access", "groups"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"]
            })
        },
        jwks: |path| format!("{path}/v1/keys"),
        token: |path| format!("{path}/v1/token"),
        claims: json!({
            "ver": 1,
            "sub": "00uexampleclinician1",
            "jti": "ID.synthetic-id-token",
            "amr": ["pwd"],
            "idp": "00oexampleorg1",
            "auth_time": jiff::Timestamp::now().as_second(),
            "name": "Example Clinician",
            "preferred_username": "clinician@example.org",
            "groups": ["clinician"],
            "fhir_user": FHIR_USER
        }),
    }
}

/// The stub provider: the server, its issuer and its signing key.
struct Provider {
    /// The server.
    server: MockServer,
    /// The issuer, the server's origin with the example's issuer path.
    issuer: String,
    /// The key its ID Tokens are signed with.
    encoding: EncodingKey,
}

impl Provider {
    /// Starts the provider `contract` describes, at the path of `example_issuer`.
    async fn start(contract: &Contract, example_issuer: &str, keys: &Keys) -> Self {
        let server = MockServer::start().await;
        let path = Url::parse(example_issuer).expect("a URL").path().to_owned();
        let issuer = format!("{}{path}", server.uri());
        let pem = std::fs::read(rsa_key(keys.dir.path(), "upstream.pem")).expect("the key");
        let encoding = EncodingKey::from_rsa_pem(&pem).expect("an RSA key");
        // NOTE: both providers sign their ID Tokens with RS256 alone
        // (id-token-claims-reference.md, Header claims; Okta, ID token claims).
        let mut jwk = serde_json::to_value(
            Jwk::from_encoding_key(&encoding, Algorithm::RS256).expect("a JWK"),
        )
        .expect("serializes");
        if let Some(members) = jwk.as_object_mut() {
            members.insert(String::from("kid"), json!(KID));
            members.insert(String::from("use"), json!("sig"));
            members.remove("alg");
        }
        for location in (contract.discovery)(&path) {
            Mock::given(matchers::method("GET"))
                .and(matchers::path(location))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json((contract.metadata)(&issuer)),
                )
                .mount(&server)
                .await;
        }
        Mock::given(matchers::method("GET"))
            .and(matchers::path((contract.jwks)(&path)))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
            .mount(&server)
            .await;
        Self {
            server,
            issuer,
            encoding,
        }
    }

    /// Mounts the code exchange of FerroSMART's client `client_id`: a client
    /// assertion (OpenID Connect Core 1.0 §9), the PKCE verifier, and an
    /// answer whose ID Token carries `claims` and `nonce`.
    async fn answer(&self, contract: &Contract, client_id: &str, nonce: &str) {
        let now = jiff::Timestamp::now().as_second();
        let mut claims = json!({
            "iss": self.issuer, "aud": client_id, "nonce": nonce,
            "iat": now, "nbf": now, "exp": now + 3600
        });
        if let (Some(base), Some(over)) = (claims.as_object_mut(), contract.claims.as_object()) {
            base.extend(over.clone());
        }
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(String::from(KID));
        header.typ = Some(String::from("JWT"));
        let id_token = jsonwebtoken::encode(&header, &claims, &self.encoding).expect("signs");
        let path = Url::parse(&self.issuer).expect("a URL").path().to_owned();
        Mock::given(matchers::method("POST"))
            .and(matchers::path((contract.token)(&path)))
            .and(matchers::body_string_contains(
                "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
            ))
            .and(matchers::body_string_contains(
                "grant_type=authorization_code",
            ))
            .and(matchers::body_string_contains("code_verifier="))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "token_type": "Bearer", "expires_in": 3599, "scope": "openid profile",
                "access_token": "synthetic-upstream-access-token", "id_token": id_token
            })))
            .expect(1)
            .mount(&self.server)
            .await;
        // NOTE: OpenID Connect Core 1.0 §5.3, a provider naming a UserInfo Endpoint
        // is asked for the claims about the ID Token's subject.
        if let Some(endpoint) = (contract.metadata)(&self.issuer)["userinfo_endpoint"].as_str() {
            let userinfo = Url::parse(endpoint).expect("a URL").path().to_owned();
            Mock::given(matchers::method("GET"))
                .and(matchers::path(userinfo))
                .and(matchers::header(
                    "authorization",
                    "Bearer synthetic-upstream-access-token",
                ))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({ "sub": contract.claims["sub"] })),
                )
                .expect(1)
                .mount(&self.server)
                .await;
        }
    }
}

/// FerroSMART running a contract's example against its stub provider.
struct Smart {
    /// The application.
    app: Router,
    /// The provider.
    provider: Provider,
    /// The client id the example registers FerroSMART under.
    client_id: String,
    /// The store.
    store: Store,
    /// The database.
    database: Database,
    /// The keys and the credential files, kept for the case's length.
    keys: Keys,
}

/// Returns the configuration of `example`, with the key and the database
/// of the case, and its assertion key with, when the example names one, a
/// certificate of it, each a file under `keys`.
fn example_config(example: &str, keys: &Keys, database: Option<&Database>) -> Config {
    let mut environment = std::collections::BTreeMap::new();
    environment.insert(
        String::from("FERROSMART__FERROSMART__KEYS__PRIVATE_KEY_FILES"),
        keys.current.display().to_string(),
    );
    let url = database.map_or_else(
        || String::from(crate::support::UNREACHED_DATABASE),
        |database| secrecy::ExposeSecret::expose_secret(&database.url).to_owned(),
    );
    environment.insert(String::from("FERROSMART__FERROSMART__DATABASE__URL"), url);
    let mut config = Config::from_sources(Some(example), &environment).expect("the example reads");
    let upstream = config
        .ferrosmart
        .upstream
        .first_mut()
        .and_then(|upstream| upstream.oidc.as_mut())
        .expect("the example names its OpenID Connect provider");
    let jwt = upstream
        .private_key_jwt
        .as_mut()
        .expect("the example authenticates by private_key_jwt");
    let assertion = rsa_key(keys.dir.path(), "assertion.pem");
    jwt.keys.private_key_file = Some(assertion.clone());
    if jwt.certificate_file.is_some() {
        let pem = std::fs::read_to_string(&assertion).expect("the key");
        let pair = rcgen::KeyPair::from_pem_and_sign_algo(&pem, &rcgen::PKCS_RSA_SHA256)
            .expect("an RSA key");
        let certificate = rcgen::CertificateParams::new(vec![String::from("smart.example.org")])
            .expect("parameters")
            .self_signed(&pair)
            .expect("a certificate");
        let path = keys.dir.path().join("assertion.crt");
        std::fs::write(&path, certificate.pem()).expect("the certificate is written");
        jwt.certificate_file = Some(path);
    }
    let backend = config
        .ferrosmart
        .backend
        .as_mut()
        .expect("the example names FerroSMART's Backend Services client");
    backend.keys.private_key_file = Some(crate::support::ec_key(keys.dir.path(), "backend.pem"));
    config
}

impl Smart {
    /// Starts FerroSMART with the example of `contract` against its stub.
    async fn start(contract: &Contract) -> Self {
        let keys = Keys::new();
        let database = Database::create().await;
        let mut config = example_config(contract.example, &keys, Some(&database));
        let upstream = config
            .ferrosmart
            .upstream
            .first_mut()
            .and_then(|upstream| upstream.oidc.as_mut())
            .expect("a provider");
        let provider = Provider::start(contract, &upstream.issuer, &keys).await;
        upstream.issuer.clone_from(&provider.issuer);
        let client_id = upstream.client_id.clone();
        let settings = config.resolve().expect("the example resolves");
        let store = Store::connect(&settings.database_url, 2)
            .await
            .expect("connects");
        store.migrate().await.expect("migrates");
        let providers = crate::support::providers(&settings).await;
        let audit = audit(&settings);
        let state = AppState::new(settings, store.clone(), audit).with_login(providers);
        let app: Value = serde_json::from_str(contract.app).expect("the example's app");
        crate::support::apply(&state, &[app]).await;
        Self {
            app: router(Arc::new(state)),
            provider,
            client_id,
            store,
            database,
            keys,
        }
    }

    /// Sends `request` with the cookie `cookie`, if any, and returns the
    /// status, the headers and the body.
    async fn send(
        &self,
        request: http::request::Builder,
        cookie: Option<&str>,
        body: Body,
    ) -> (StatusCode, http::HeaderMap, String) {
        let request = match cookie {
            Some(cookie) => request.header(header::COOKIE, format!("{COOKIE}={cookie}")),
            None => request,
        };
        let response = self
            .app
            .clone()
            .oneshot(from_client(request.body(body).expect("a request")))
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

    /// Gets `path`.
    async fn get(&self, path: &str, cookie: Option<&str>) -> (StatusCode, http::HeaderMap, String) {
        self.send(Request::get(path), cookie, Body::empty()).await
    }

    /// Posts the form `pairs` to `path`.
    async fn post(
        &self,
        path: &str,
        pairs: &[(&str, &str)],
        cookie: Option<&str>,
    ) -> (StatusCode, http::HeaderMap, String) {
        let form = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        let request =
            Request::post(path).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        self.send(request, cookie, Body::from(form)).await
    }

    /// Drops the database.
    async fn stop(self) {
        self.database.drop(self.store).await;
    }
}

/// Returns the location of a `303`, against FerroSMART's issuer.
fn location(headers: &http::HeaderMap) -> Url {
    let location = headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("a location");
    Url::parse("https://smart.example.org")
        .expect("a URL")
        .join(location)
        .expect("a URL")
}

/// Returns the query parameter `name` of `url`.
fn param(url: &Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// Sends the examples' app's authorization request and returns where
/// FerroSMART sends the browser at the provider, and the cookie it set.
async fn to_provider(smart: &Smart, contract: &Contract) -> (Url, String) {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("response_type", "code"),
            ("client_id", APP),
            ("redirect_uri", REDIRECT),
            (
                "scope",
                "openid fhirUser user/Patient.rs user/Observation.rs",
            ),
            ("state", "synthetic-state"),
            ("aud", RESOURCE),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
            ("nonce", "synthetic-nonce"),
        ])
        .finish();
    let (status, headers, body) = smart.get(&format!("/authorize?{query}"), None).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{body}");
    let upstream = location(&headers);
    let metadata = (contract.metadata)(&smart.provider.issuer);
    let endpoint = metadata
        .get("authorization_endpoint")
        .and_then(Value::as_str)
        .expect("an endpoint");
    assert!(
        upstream.as_str().starts_with(endpoint),
        "the browser goes to the provider's authorization endpoint: {upstream}"
    );
    // NOTE: OpenID Connect Core 1.0 §3.1.2.1, RFC 7636 §4.3: the code flow with
    // the scopes the example asks for and an S256 challenge.
    for (name, value) in [
        ("response_type", "code"),
        ("client_id", smart.client_id.as_str()),
        ("scope", "openid profile"),
        ("code_challenge_method", "S256"),
        ("redirect_uri", "https://smart.example.org/callback"),
    ] {
        assert_eq!(
            Some(value),
            param(&upstream, name).as_deref(),
            "the request's {name}"
        );
    }
    let cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie| cookie.split(';').next())
        .and_then(|pair| pair.split_once('='))
        .map(|(_, value)| value.to_owned())
        .expect("a cookie");
    (upstream, cookie)
}

/// Comes back from the provider's login at `upstream` and returns the form
/// token of the consent page, which shows what the provider's claims grant.
async fn to_consent(smart: &Smart, contract: &Contract, upstream: &Url, cookie: &str) -> String {
    smart
        .provider
        .answer(
            contract,
            &smart.client_id,
            &param(upstream, "nonce").expect("a nonce"),
        )
        .await;
    let callback = format!(
        "/callback?code=synthetic-upstream-code&state={}",
        param(upstream, "state").expect("a state")
    );
    let (status, headers, body) = smart.get(&callback, Some(cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{body}");
    assert_eq!("/consent", location(&headers).path(), "to the consent page");
    let (status, _, page) = smart.get("/consent", Some(cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(
        page.contains("Example Clinician"),
        "the provider's name: {page}"
    );
    assert!(
        page.contains("value=\"user/Observation.rs\"")
            && page.contains("<code class=\"fui-scope-raw\">fhirUser</code>"),
        "the role the provider names grants its scopes, and fhirUser is offered: {page}"
    );
    page.split("name=\"form_token\" value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("a form token")
        .to_owned()
}

/// Approves the consent and redeems the code, returning the token response
/// and the claims of its ID Token.
async fn to_token(smart: &Smart, cookie: &str, form_token: &str) -> (Value, Value) {
    let (status, headers, body) = smart
        .post(
            "/consent",
            &[
                ("form_token", form_token),
                ("decision", "approve"),
                ("scope", "openid"),
                ("scope", "fhirUser"),
                ("scope", "user/Observation.rs"),
            ],
            Some(cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{body}");
    let code = param(&location(&headers), "code").expect("a code");
    let (status, _, body) = smart
        .post(
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", REDIRECT),
                ("code_verifier", VERIFIER),
                ("client_id", APP),
            ],
            None,
        )
        .await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let token: Value = serde_json::from_str(&body).expect("JSON");
    let id_token = token
        .get("id_token")
        .and_then(Value::as_str)
        .expect("an ID Token");
    let claims: Value = jsonwebtoken::dangerous::insecure_decode_claims(id_token).expect("claims");
    (token, claims)
}

/// Runs a standalone launch of the examples' app through `contract`'s
/// provider and returns the token response and the claims of its ID Token.
async fn launch(contract: &Contract) -> (Smart, Value, Value) {
    let smart = Smart::start(contract).await;
    let (upstream, cookie) = to_provider(&smart, contract).await;
    let form_token = to_consent(&smart, contract, &upstream, &cookie).await;
    let (token, claims) = to_token(&smart, &cookie, &form_token).await;
    (smart, token, claims)
}

#[tokio::test]
async fn an_entra_id_login_maps_its_app_role_and_extension_attribute() {
    let contract = entra();
    let (smart, token, claims) = launch(&contract).await;
    assert_eq!(json!("openid fhirUser user/Observation.rs"), token["scope"]);
    // NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, fhirUser: the
    // `extn.fhirUser` optional claim, as the example maps it.
    assert_eq!(json!(FHIR_USER), claims["fhirUser"]);
    assert_eq!(json!("https://smart.example.org"), claims["iss"]);
    assert_eq!(json!(APP), claims["aud"]);
    assert_ne!(
        contract.claims["sub"], claims["sub"],
        "the provider's sub never leaves"
    );
    assert_ne!(contract.claims["oid"], claims["sub"], "nor its oid");
    let (header, assertion) = assertion_sent(&smart, &contract).await;
    // NOTE: certificate-credentials.md, Assertion format: PS256 and the
    // certificate's x5t#S256; RFC 10070 §4: the explicit type.
    assert_eq!(Algorithm::PS256, header.alg);
    assert_eq!(Some("client-authentication+jwt"), header.typ.as_deref());
    let certificate = std::fs::read_to_string(smart.keys.dir.path().join("assertion.crt"))
        .expect("the certificate");
    let der = x509_der(&certificate);
    let thumbprint = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &der);
    assert_eq!(
        Some(base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            thumbprint.as_ref()
        )),
        header.x5t_s256
    );
    assert_eq!(json!(smart.client_id), assertion["iss"]);
    assert_eq!(json!(smart.client_id), assertion["sub"]);
    // NOTE: RFC 8725 §3.12: the assertion keys are published apart, and the
    // token key set holds none of them.
    let (status, _, tokens) = smart.get("/jwks", None).await;
    assert_eq!(StatusCode::OK, status);
    let (status, _, assertions) = smart.get("/upstream-jwks", None).await;
    assert_eq!(StatusCode::OK, status);
    let moduli = |set: &str| -> Vec<Value> {
        let set: Value = serde_json::from_str(set).expect("a JWK Set");
        set["keys"]
            .as_array()
            .expect("keys")
            .iter()
            .map(|key| key["n"].clone())
            .collect()
    };
    let (tokens, assertions) = (moduli(&tokens), moduli(&assertions));
    assert_eq!(
        1,
        assertions.len(),
        "the current assertion key: {assertions:?}"
    );
    assert!(
        tokens.iter().all(|key| !assertions.contains(key)),
        "the token and assertion key sets share no key"
    );
    assert!(
        assertion["jti"].as_str().is_some_and(|jti| !jti.is_empty()),
        "a jti"
    );
    smart.stop().await;
}

#[tokio::test]
async fn an_okta_login_maps_its_groups_and_custom_claim() {
    let contract = okta();
    let (smart, token, claims) = launch(&contract).await;
    assert_eq!(json!("openid fhirUser user/Observation.rs"), token["scope"]);
    // NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, fhirUser: the
    // custom `fhir_user` claim, as the example maps it.
    assert_eq!(json!(FHIR_USER), claims["fhirUser"]);
    assert_eq!(json!("https://smart.example.org"), claims["iss"]);
    assert_eq!(json!(APP), claims["aud"]);
    assert_ne!(
        contract.claims["sub"], claims["sub"],
        "the provider's sub never leaves"
    );
    let (header, assertion) = assertion_sent(&smart, &contract).await;
    // NOTE: Okta, Client authentication, JWT with private key: RS256, and
    // `iss` and `sub` the client id; RFC 10070 §4: the explicit type.
    assert_eq!(Algorithm::RS256, header.alg);
    assert_eq!(Some("client-authentication+jwt"), header.typ.as_deref());
    assert_eq!(None, header.x5t_s256, "Okta knows the key by its JWK");
    assert_eq!(json!(smart.client_id), assertion["iss"]);
    assert_eq!(json!(smart.client_id), assertion["sub"]);
    let (status, _, assertions) = smart.get("/upstream-jwks", None).await;
    assert_eq!(StatusCode::OK, status);
    let published: Value = serde_json::from_str(&assertions).expect("a JWK Set");
    assert_eq!(
        header.kid.as_deref().map(Value::from),
        published["keys"].get(0).map(|key| key["kid"].clone()),
        "the assertion names the JWK the integration holds"
    );
    smart.stop().await;
}

// NOTE: OpenID Connect Discovery 1.0 §4.3: the metadata's issuer must be the
// URL it was read under; howto-convert-app-to-be-multi-tenant.md: /organizations is no issuer.
#[tokio::test]
async fn the_entra_id_multitenant_authority_is_refused() {
    let keys = Keys::new();
    let mut config = example_config(ENTRA, &keys, None);
    let server = MockServer::start().await;
    let authority = format!("{}/organizations/v2.0", server.uri());
    let template = "https://login.microsoftonline.com/{tenantid}/v2.0";
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/organizations/v2.0/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": template,
            "authorization_endpoint": format!("{}/organizations/oauth2/v2.0/authorize", server.uri()),
            "token_endpoint": format!("{}/organizations/oauth2/v2.0/token", server.uri()),
            "jwks_uri": format!("{}/organizations/discovery/v2.0/keys", server.uri())
        })))
        .mount(&server)
        .await;
    config
        .ferrosmart
        .upstream
        .first_mut()
        .and_then(|upstream| upstream.oidc.as_mut())
        .expect("a provider")
        .issuer = authority.clone();
    let settings = config.resolve().expect("the configuration resolves");
    let ferrosmart::upstream::Protocol::Oidc(oidc) =
        &settings.upstreams.first().expect("an upstream").protocol
    else {
        panic!("the provider speaks OpenID Connect");
    };
    let refused = oidc
        .relying_party(Url::parse("https://smart.example.org/callback").expect("a URL"))
        .await
        .expect_err("no relying party for a metadata issuer that is not the authority");
    assert!(
        matches!(
            &refused,
            ferrosmart::upstream::UpstreamError::Oidc(OidcError::Discovery(DiscoveryError::IssuerMismatch { expected, found }))
                if *expected == authority && found == template
        ),
        "{refused:?}"
    );
}

/// Returns the DER of the PEM certificate `pem`.
fn x509_der(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body).expect("base64")
}

/// Returns the header and the verified claims of the client assertion
/// FerroSMART sent the provider's token endpoint: signed by the current
/// assertion key for the provider's issuer identifier as the sole audience
/// (RFC 10070 §4, where certificate-credentials.md and Okta's Client
/// authentication name the token endpoint URL; §6 has the issuer work with
/// both).
async fn assertion_sent(smart: &Smart, contract: &Contract) -> (Header, Value) {
    let path = Url::parse(&smart.provider.issuer)
        .expect("a URL")
        .path()
        .to_owned();
    let token_path = (contract.token)(&path);
    let requests = smart
        .provider
        .server
        .received_requests()
        .await
        .unwrap_or_default();
    let request = requests
        .iter()
        .find(|request| request.url.path() == token_path)
        .expect("the code exchange");
    assert!(
        !request.headers.contains_key("authorization"),
        "no secret beside the assertion"
    );
    let assertion = url::form_urlencoded::parse(&request.body)
        .find(|(name, _)| name == "client_assertion")
        .map(|(_, value)| value.into_owned())
        .expect("a client assertion");
    let header = jsonwebtoken::decode_header(&assertion).expect("a header");
    let pem = std::fs::read(smart.keys.dir.path().join("assertion.pem")).expect("the key");
    let public =
        AssertionKey::from_pem(&pem, Some(crate::support::jws_algorithm(header.alg)), None)
            .expect("the key")
            .public_jwk();
    let decoding =
        DecodingKey::from_jwk(&serde_json::from_value(public).expect("a JWK")).expect("a key");
    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[smart.provider.issuer.as_str()]);
    validation.set_issuer(&[smart.client_id.as_str()]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    let claims = jsonwebtoken::decode::<Value>(&assertion, &decoding, &validation)
        .expect("the assertion verifies with FerroSMART's current key")
        .claims;
    assert_eq!(
        Some(&json!(smart.provider.issuer)),
        claims.get("aud"),
        "the issuer identifier as the sole audience"
    );
    (header, claims)
}

#[test]
fn both_examples_resolve_to_their_claim_mapping() {
    let keys = Keys::new();
    for (example, fhir_user, roles) in [
        (ENTRA, "extn.fhirUser", "roles"),
        (OKTA, "fhir_user", "groups"),
    ] {
        let settings = example_config(example, &keys, None)
            .resolve()
            .expect("the example resolves");
        let upstream = settings.upstreams.first().expect("a provider");
        assert_eq!(Some(fhir_user), upstream.fhir_user_claim.as_deref());
        assert_eq!(vec![String::from(roles)], upstream.role_claims);
    }
}
