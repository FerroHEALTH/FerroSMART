// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A standalone launch through a FHIR resource server that carries every
//! user caller onto its CDR by token exchange (RFC 8693 §2.1) and keeps its
//! own credential for a Backend Services client, as FerroBRIDGE does under
//! `[cdr.endpoint.credentials.onward]` (`docs/architecture.md` §13.33).

use std::sync::OnceLock;

use super::ehr_picker::{EHR_ID, NAMESPACE, OpenEhr};
use super::*;

/// The resource server's secret at FerroSMART.
const SECRET: &str = "synthetic-bridge-secret";
/// The system of the identifier that names an EHR's subject.
const SYSTEM: &str = "urn:example:mrn";

/// What the resource server did with one request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Route {
    /// A Backend Services token: no exchange, its own credential onward.
    Own,
    /// A user token, exchanged at FerroSMART for one naming `sub`.
    Exchanged {
        /// The `sub` of the token FerroSMART issued.
        sub: String,
    },
    /// The exchange was refused.
    Refused,
}

/// The resource server: FerroSMART's router to exchange tokens at once it
/// runs, and the route of every request.
#[derive(Clone)]
struct Bridge {
    /// FerroSMART, set once it started.
    smart: Arc<OnceLock<Router>>,
    /// The route each request took.
    routes: Arc<std::sync::Mutex<Vec<Route>>>,
}

impl Bridge {
    /// Starts the resource server on a port of its own and returns it with
    /// its FHIR base.
    async fn start() -> (Self, String) {
        let bridge = Self {
            smart: Arc::new(OnceLock::new()),
            routes: Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let port = listener.local_addr().expect("an address").port();
        let app = Router::new().fallback(answer).with_state(bridge.clone());
        drop(tokio::spawn(async move {
            axum::serve(listener, app).await.expect("the server runs");
        }));
        (bridge, format!("http://127.0.0.1:{port}/fhir"))
    }

    /// Returns the routes the requests took.
    fn routes(&self) -> Vec<Route> {
        self.routes.lock().expect("held").clone()
    }
}

/// Answers one FHIR request: a Backend Services token reads under the
/// server's own credential, any other token is exchanged first and a
/// refused exchange is refused.
async fn answer(
    axum::extract::State(bridge): axum::extract::State<Bridge>,
    request: Request<Body>,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default()
        .to_owned();
    let Ok(claims) = jsonwebtoken::dangerous::insecure_decode_claims::<Value>(&token) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let system = claims
        .get("scope")
        .and_then(Value::as_str)
        .is_some_and(|scope| scope.split(' ').all(|scope| scope.starts_with("system/")))
        && claims.get("sub").is_some()
        && claims.get("sub") == claims.get("client_id");
    let route = if system {
        Route::Own
    } else {
        exchanged(&bridge, &token).await
    };
    let refused = route == Route::Refused;
    bridge.routes.lock().expect("held").push(route);
    if refused {
        return StatusCode::FORBIDDEN.into_response();
    }
    let patient = json!({
        "resourceType": "Patient", "id": "p-1",
        "name": [{"given": ["Synthetic"], "family": "Patient"}],
        "identifier": [{"system": SYSTEM, "value": "MRN-1"}]
    });
    let body = if request.uri().path().ends_with("/Patient/p-1") {
        patient
    } else {
        json!({ "resourceType": "Bundle", "type": "searchset", "entry": [{ "resource": patient }] })
    };
    axum::Json(body).into_response()
}

/// Exchanges `token` at FerroSMART as the resource server's client.
async fn exchanged(bridge: &Bridge, token: &str) -> Route {
    let smart = bridge.smart.get().expect("FerroSMART runs").clone();
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair(
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        )
        .append_pair("client_id", "bridge")
        .append_pair("client_secret", SECRET)
        .append_pair("subject_token", token)
        .append_pair(
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        )
        .finish();
    let request = Request::post("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form))
        .expect("a request");
    let response = smart
        .oneshot(from_client(request))
        .await
        .expect("an answer");
    if response.status() != StatusCode::OK {
        return Route::Refused;
    }
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("the body")
        .to_bytes();
    let body: Value = serde_json::from_slice(&bytes).expect("JSON");
    let issued = jwt_claims(&body, "access_token");
    Route::Exchanged {
        sub: issued
            .get("sub")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    }
}

/// FerroSMART over the resource server and the openEHR base paired with
/// it, and what each was shown.
struct Platform {
    /// FerroSMART.
    smart: Smart,
    /// The resource server.
    bridge: Bridge,
    /// The openEHR base.
    openehr_base: String,
    /// The claims of the tokens the openEHR server was shown.
    openehr_seen: Arc<std::sync::Mutex<Vec<Value>>>,
    /// The openEHR server, kept for the case's length.
    _openehr: MockServer,
}

/// Starts the platform, the resource server holding patient `p-1` and the
/// openEHR server their EHR.
async fn platform() -> Platform {
    let (bridge, fhir_base) = Bridge::start().await;
    let openehr = MockServer::start().await;
    let openehr_seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/openehr/v1/ehr"))
        .respond_with(OpenEhr {
            subject: "MRN-1",
            seen: Arc::clone(&openehr_seen),
        })
        .mount(&openehr)
        .await;
    let openehr_base = format!("{}/openehr/v1", openehr.uri());
    let grants = format!(
        "[\"authorization_code\"]\n\
         scope = [\"openid\", \"fhirUser\", \"launch/patient\", \"patient/composition-*.r\", \"user/composition-*.r\"]\n\
         [[client]]\nclient_id = \"bridge\"\ntoken_endpoint_auth_method = \"client_secret_post\"\n\
         resources = [{fhir_base:?}, {openehr_base:?}]\n\
         grant_types = [\"urn:ietf:params:oauth:grant-type:token-exchange\"]"
    );
    let smart = Smart::start_over(
        &grants,
        "[\"patient/composition-*.r\", \"patient/aql-*.s\", \"user/composition-*.r\", \"user/aql-*.s\"]",
        "[\"user/composition-*.r\"]",
        &format!(
            "[[ferrosmart.resource]]\nbase = {fhir_base:?}\n\
             [[ferrosmart.resource]]\nbase = {openehr_base:?}\nkind = \"openehr\"\n\
             subject_namespace = {NAMESPACE:?}\nfhir_base = {fhir_base:?}\n\
             subject_system = {SYSTEM:?}\n"
        ),
    )
    .await;
    crate::support::set_secret(&smart.store, "bridge", SECRET).await;
    assert!(bridge.smart.set(smart.app.clone()).is_ok(), "set once");
    Platform {
        smart,
        bridge,
        openehr_base,
        openehr_seen,
        _openehr: openehr,
    }
}

/// Returns whether every token the openEHR server was shown names `sub`
/// and was issued under a grant of that person, as an exchange requires.
async fn granted_to(platform: &Platform, sub: &str) -> bool {
    let seen = platform.openehr_seen.lock().expect("held").clone();
    let mut all = !seen.is_empty();
    for claims in seen {
        let jti = claims
            .get("jti")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let record = platform
            .smart
            .store
            .access_token(jti)
            .await
            .expect("the record reads")
            .expect("a recorded token");
        all &= claims.get("sub") == Some(&json!(sub))
            && record.grant.is_some_and(|grant| {
                grant.subject == sub && grant.audience == platform.openehr_base
            });
    }
    all
}

// NOTE: SMART App Launch 2.2.0, Scopes and Launch Context, a professional's
// `user/` reads run as them, so the resource server exchanges each (RFC 8693).
#[tokio::test]
async fn a_professional_s_picker_search_and_ehr_lookup_run_as_them_through_the_exchange() {
    let platform = platform().await;
    let smart = &platform.smart;
    let cookie = to_picker_asking(
        smart,
        &platform.openehr_base,
        "openid fhirUser launch/patient patient/composition-*.r",
        "synthetic-person",
        "Practitioner/synthetic-1",
    )
    .await;
    let (status, _, page) = smart.get("/picker?name=Synthetic", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(page.contains("value=\"p-1\""), "{page}");
    let token = form_token(&page);
    let (status, headers, page) = smart
        .post(
            "/picker",
            &[("form_token", token.as_str()), ("patient", "p-1")],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    assert_eq!("/consent", location(&headers).path());
    let routes = platform.bridge.routes();
    assert_eq!(2, routes.len(), "the search and the read again: {routes:?}");
    let sub = match routes.first() {
        Some(Route::Exchanged { sub }) => sub.clone(),
        other => panic!("the search is exchanged: {other:?}"),
    };
    assert!(
        routes
            .iter()
            .all(|route| route == &Route::Exchanged { sub: sub.clone() }),
        "each request exchanged for the same person: {routes:?}"
    );
    assert!(
        granted_to(&platform, &sub).await,
        "the EHR lookup runs as them"
    );
    platform.smart.stop().await;
}

// NOTE: SMART App Launch 2.2.0, Backend Services, the patient's own record is
// read by FerroSMART's client, which the resource server never exchanges.
#[tokio::test]
async fn a_patient_launch_reads_their_record_as_a_backend_service_with_no_exchange() {
    let platform = platform().await;
    let smart = &platform.smart;
    let (cookie, (status, headers, body)) = as_patient(
        smart,
        &platform.openehr_base,
        "openid fhirUser launch/patient patient/composition-*.r",
        "Patient/p-1",
    )
    .await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{body}");
    assert_eq!("/consent", location(&headers).path(), "no picker");
    assert_eq!(vec![Route::Own], platform.bridge.routes());
    let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
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
                ("scope", "patient/composition-*.r"),
            ],
            Some(&cookie),
        )
        .await;
    let code = param(&location(&headers), "code").expect("a code");
    let redeem = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("client_id", "app"),
    ];
    let (status, _, body) = smart.post("/token", &redeem, None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let body: Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(json!("p-1"), body["patient"]);
    assert_eq!(json!(EHR_ID), body["ehrId"]);
    let sub = jwt_claims(&body, "access_token")["sub"].clone();
    assert!(
        granted_to(&platform, sub.as_str().expect("a sub")).await,
        "the EHR lookup runs as the patient"
    );
    platform.smart.stop().await;
}
