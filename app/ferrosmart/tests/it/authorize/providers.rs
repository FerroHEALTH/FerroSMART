// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Several upstream providers: each `[[ferrosmart.upstream]]` entry by
//! name, chosen per client or on the chooser page (#678).

use super::*;

/// FerroSMART over two providers, `staff` and `patients`, with the clients
/// `app` (both providers, so the chooser) and `staff-app` (`staff` alone).
struct Two {
    /// The server, whose `provider` is `staff`.
    smart: Smart,
    /// The `patients` provider.
    patients: Provider,
}

impl Two {
    async fn start() -> Self {
        let staff = Provider::start().await;
        let patients = Provider::start().await;
        let keys = Keys::new();
        let database = Database::create().await;
        let assertion = crate::support::upstream_assertion(keys.dir.path());
        let text = format!(
            "[ferrosmart]\nissuer = {ISSUER:?}\n[ferrosmart.database]\nurl = {:?}\n\
             [[ferrosmart.upstream]]\nname = \"staff\"\nlabel = \"Hospital staff\"\n\
             [ferrosmart.upstream.oidc]\nissuer = {:?}\nclient_id = {UPSTREAM_CLIENT:?}\n\
             fhir_user_claim = \"fhir_user\"\n{assertion}{ASSURANCE}\
             [[ferrosmart.upstream]]\nname = \"patients\"\nlabel = \"Patients\"\n\
             [ferrosmart.upstream.oidc]\nissuer = {:?}\nclient_id = {UPSTREAM_CLIENT:?}\n\
             fhir_user_claim = \"fhir_user\"\n{assertion}{ASSURANCE}\
             [[ferrosmart.role]]\nname = \"clinician\"\nscopes = [\"user/Observation.rs\"]\n\
             [[client]]\nclient_id = \"app\"\nname = \"Synthetic App\"\nkind = \"public\"\n\
             redirect_uris = [{REDIRECT:?}]\ngrant_types = [\"authorization_code\", \"refresh_token\"]\n\
             scopes = [\"openid\", \"fhirUser\", \"user/Observation.rs\", \"online_access\"]\n\
             upstreams = [\"staff\", \"patients\"]\n\
             [[client]]\nclient_id = \"staff-app\"\nname = \"Staff App\"\nkind = \"public\"\n\
             redirect_uris = [{REDIRECT:?}]\ngrant_types = [\"authorization_code\"]\n\
             scopes = [\"openid\", \"user/Observation.rs\"]\nupstreams = [\"staff\"]",
            secrecy::ExposeSecret::expose_secret(&database.url),
            staff.server.uri(),
            patients.server.uri(),
        );
        let settings = config(&crate::support::reach_every_base(&text), &keys)
            .resolve()
            .expect("resolves");
        let store = Store::connect(&settings.database_url, 2)
            .await
            .expect("connects");
        store.migrate().await.expect("migrates");
        let providers = crate::support::providers(&settings).await;
        let audit = audit(&settings);
        let state = AppState::new(settings.clone(), store.clone(), audit).with_login(providers);
        let clients = crate::support::clients(&crate::support::reach_every_base(&text));
        crate::support::apply(&state, &clients).await;
        Self {
            smart: Smart {
                app: router(Arc::new(state)),
                provider: staff,
                store,
                database,
                _keys: keys,
                settings,
                clients,
            },
            patients,
        }
    }

    async fn stop(self) {
        self.smart.stop().await;
    }
}

/// Completes the login whose upstream request is `upstream` at `provider`,
/// with the browser's `cookie`, and returns the callback's answer.
async fn answered(
    smart: &Smart,
    provider: &Provider,
    upstream: &Url,
    cookie: &str,
) -> (StatusCode, http::HeaderMap, String) {
    provider
        .answer(&param(upstream, "nonce").expect("a nonce"), &["clinician"])
        .await;
    let callback = format!(
        "/callback?code=synthetic-upstream-code&state={}",
        param(upstream, "state").expect("a state")
    );
    smart.get(&callback, Some(cookie)).await
}

/// Chooses `provider` on the chooser page of the browser's `cookie` and
/// returns the upstream request it sends the browser to.
async fn choose(smart: &Smart, cookie: &str, provider: &str) -> Url {
    let (status, _, page) = smart.get("/login", Some(cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    let (status, headers, _) = smart
        .post(
            "/login",
            &[("form_token", &form_token(&page)), ("provider", provider)],
            Some(cookie),
        )
        .await;
    assert_eq!(
        StatusCode::SEE_OTHER,
        status,
        "the choice sends the browser on"
    );
    location(&headers)
}

#[tokio::test]
async fn a_client_of_two_providers_shows_the_chooser_and_logs_in_at_the_chosen_one() {
    let two = Two::start().await;
    let smart = &two.smart;
    let (status, headers, _) = smart.get(&authorize_path(&[]), None).await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    assert_eq!(format!("{ISSUER}/login"), location(&headers).as_str());
    let cookie = set_cookie(&headers);
    let (status, headers, page) = smart.get("/login", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(
        page.contains("Hospital staff") && page.contains("Patients"),
        "{page}"
    );
    let policy = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(
        policy.contains(&two.patients.server.uri())
            && policy.contains(&smart.provider.server.uri()),
        "the choice may go on to either provider: {policy}"
    );
    let upstream = choose(smart, &cookie, "patients").await;
    assert!(
        upstream.as_str().starts_with(&two.patients.server.uri()),
        "the browser goes to the chosen provider: {upstream}"
    );
    let (status, headers, page) = answered(smart, &two.patients, &upstream, &cookie).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    assert_eq!("/consent", location(&headers).path());
    let (status, _, _) = smart.get("/login", Some(&cookie)).await;
    assert_eq!(StatusCode::NOT_FOUND, status, "the provider is chosen once");
    two.stop().await;
}

#[tokio::test]
async fn a_client_of_one_provider_goes_straight_to_it() {
    let two = Two::start().await;
    let smart = &two.smart;
    let (status, headers, _) = smart
        .get(
            &authorize_path(&[
                ("client_id", "staff-app"),
                ("scope", "openid user/Observation.rs"),
            ]),
            None,
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    assert!(
        location(&headers)
            .as_str()
            .starts_with(&smart.provider.server.uri()),
        "no chooser for one provider"
    );
    two.stop().await;
}

#[tokio::test]
async fn a_choice_the_client_does_not_allow_or_with_another_form_token_is_refused() {
    let two = Two::start().await;
    let smart = &two.smart;
    let (_, headers, _) = smart.get(&authorize_path(&[]), None).await;
    let cookie = set_cookie(&headers);
    let (_, _, page) = smart.get("/login", Some(&cookie)).await;
    let token = form_token(&page);
    for form in [
        [("form_token", token.as_str()), ("provider", "unknown")],
        [("form_token", "synthetic-forged"), ("provider", "patients")],
    ] {
        let (status, headers, _) = smart.post("/login", &form, Some(&cookie)).await;
        assert_eq!(StatusCode::BAD_REQUEST, status, "{form:?}");
        assert!(headers.get(header::LOCATION).is_none(), "{form:?}");
    }
    two.stop().await;
}

#[tokio::test]
async fn a_callback_answered_with_another_provider_s_token_is_refused() {
    let two = Two::start().await;
    let smart = &two.smart;
    let (_, headers, _) = smart.get(&authorize_path(&[]), None).await;
    let cookie = set_cookie(&headers);
    let upstream = choose(smart, &cookie, "staff").await;
    // NOTE: OpenID Connect Core 1.0 §3.1.3.7 item 2, the ID Token's iss is the
    // chosen provider's; one the other provider signed and names is refused.
    let now = jiff::Timestamp::now().as_second();
    let claims = json!({
        "iss": two.patients.server.uri(), "aud": UPSTREAM_CLIENT, "iat": now, "exp": now + 300,
        "sub": "synthetic-person", "nonce": param(&upstream, "nonce").expect("a nonce"),
    });
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(String::from("op-1"));
    let id_token = jsonwebtoken::encode(&header, &claims, &two.patients.encoding).expect("signs");
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "synthetic-upstream-token", "token_type": "Bearer",
            "expires_in": 300, "id_token": id_token
        })))
        .mount(&smart.provider.server)
        .await;
    let callback = format!(
        "/callback?code=synthetic-upstream-code&state={}",
        param(&upstream, "state").expect("a state")
    );
    let (status, headers, _) = smart.get(&callback, Some(&cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let back = location(&headers);
    assert_eq!(
        REDIRECT,
        format!("{}{}", back.origin().ascii_serialization(), back.path())
    );
    assert_eq!(Some(String::from("server_error")), param(&back, "error"));
    assert!(param(&back, "code").is_none());
    two.stop().await;
}

#[test]
fn a_provider_table_is_checked_at_load() {
    let keys = Keys::new();
    let assertion = crate::support::upstream_assertion(keys.dir.path());
    let entry = |name: &str, issuer: &str| {
        format!(
            "[[ferrosmart.upstream]]\nname = {name:?}\n{ASSURANCE}\
             [ferrosmart.upstream.oidc]\nissuer = {issuer:?}\nclient_id = \"ferrosmart\"\n{assertion}"
        )
    };
    let base = format!("[ferrosmart]\nissuer = {ISSUER:?}\n");
    let refused = [
        format!(
            "{base}{}{}",
            entry("idp", "https://one.example.org"),
            entry("idp", "https://two.example.org")
        ),
        format!(
            "{base}{}{}",
            entry("one", "https://idp.example.org"),
            entry("two", "https://idp.example.org")
        ),
        format!("{base}{}", entry("not a name", "https://idp.example.org")),
        format!("{base}[[ferrosmart.upstream]]\nname = \"idp\"\n"),
        format!(
            "{base}[[ferrosmart.upstream]]\nname = \"idp\"\n[ferrosmart.upstream.oidc]\n\
             issuer = \"https://idp.example.org\"\nclient_id = \"ferrosmart\"\n{assertion}\
             [ferrosmart.upstream.saml]\nentity_id = \"https://idp.example.org/saml\"\n"
        ),
    ];
    for text in refused {
        assert!(config(&text, &keys).resolve().is_err(), "{text}");
    }
    let admitted = format!(
        "{base}{}{}",
        entry("one", "https://one.example.org"),
        entry("two", "https://two.example.org")
    );
    let settings = config(&admitted, &keys).resolve().expect("two providers");
    assert_eq!(
        vec!["one", "two"],
        settings
            .upstreams
            .iter()
            .map(|upstream| upstream.name.as_str())
            .collect::<Vec<_>>()
    );
}

/// Logs in at the `patients` provider for `online_access` and returns the
/// token response.
async fn online_at_patients(two: &Two) -> Value {
    let smart = &two.smart;
    let scope = "openid fhirUser user/Observation.rs online_access";
    let (_, headers, _) = smart.get(&authorize_path(&[("scope", scope)]), None).await;
    let cookie = set_cookie(&headers);
    let upstream = choose(smart, &cookie, "patients").await;
    answered(smart, &two.patients, &upstream, &cookie).await;
    let (_, _, page) = smart.get("/consent", Some(&cookie)).await;
    let (_, headers, _) = smart
        .post(
            "/consent",
            &[
                ("form_token", form_token(&page).as_str()),
                ("decision", "approve"),
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
    let (status, _, body) = smart.post("/token", &exchange, None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    serde_json::from_str(&body).expect("JSON")
}

#[tokio::test]
async fn a_back_channel_logout_ends_only_the_sessions_of_its_own_provider() {
    let two = Two::start().await;
    let body = online_at_patients(&two).await;
    let token = body["refresh_token"].as_str().expect("a refresh token");
    let smart = &two.smart;
    // NOTE: Back-Channel Logout 1.0 §2.6, the token's iss names the provider; the
    // same sub at the other provider is another person.
    let staff = smart.provider.logout_token(&json!({}));
    let (status, _, _) = smart
        .post("/backchannel-logout", &[("logout_token", &staff)], None)
        .await;
    assert_eq!(
        StatusCode::OK,
        status,
        "a logout that ends nothing succeeds"
    );
    let (status, renewed) = refresh(smart, token).await;
    assert_eq!(
        StatusCode::OK,
        status,
        "the patients login lives on: {renewed}"
    );
    let next = renewed["refresh_token"].as_str().expect("rotated");
    let patients = two.patients.logout_token(&json!({}));
    let (status, _, _) = smart
        .post("/backchannel-logout", &[("logout_token", &patients)], None)
        .await;
    assert_eq!(StatusCode::OK, status, "the logout succeeds");
    let (status, refused) = refresh(smart, next).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{refused}");
    two.stop().await;
}
