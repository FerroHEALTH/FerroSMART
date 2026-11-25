// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The EUDI Wallet login through the whole stack (#689): the signed request
//! object, the wallet's encrypted answer at the response URI, the browser
//! bringing the response code back, the `fhirUser` the PID's administrative
//! number finds, and the `110122` Login record of each outcome.

mod api;
pub(crate) mod kit;
mod list;
mod mdoc;
mod patient_index;
mod refusals;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

use super::*;
use kit::{Credential, Holder, Pki, now};

/// The scope every case asks: identity alone, so the login goes on to the
/// consent page.
const SCOPE: &str = "openid fhirUser";

/// The system of the Dutch citizen service number the lookup searches.
const BSN: &str = "http://fhir.nl/fhir/NamingSystem/bsn";

/// Writes `text` to `dir/name` and returns the path as TOML text.
fn written(dir: &std::path::Path, name: &str, text: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, text).expect("written");
    format!("{:?}", path.display().to_string())
}

/// FerroSMART over the EUDI Wallet, with the certificates of the case, the
/// status list server and the FHIR server the `fhirUser` lookup searches.
struct Wallet {
    /// The server.
    smart: Smart,
    /// The certificates.
    pki: Pki,
    /// The holder's key.
    holder: Holder,
    /// The status list server.
    status: MockServer,
    /// The FHIR server.
    fhir: MockServer,
    /// The patient index, when the case configures one.
    pix: Option<MockServer>,
}

/// A request the wallet fetched.
struct Begun {
    /// The browser's cookie.
    cookie: String,
    /// The URL that invoked the wallet.
    invocation: Url,
    /// The request object's protected header.
    header: Value,
    /// The request object's claims.
    object: Value,
}

impl Begun {
    /// Returns the claim `name` of the request object as text.
    fn text(&self, name: &str) -> String {
        self.object
            .get(name)
            .and_then(Value::as_str)
            .expect("a text claim")
            .to_owned()
    }

    /// Returns the request's ephemeral encryption key.
    fn jwk(&self) -> Value {
        self.object
            .pointer("/client_metadata/jwks/keys/0")
            .expect("a key")
            .clone()
    }
}

/// Returns the value of the first attribute `name` in `page` whose value
/// starts with `starts`, its entities read.
fn attribute(page: &str, name: &str, starts: &str) -> String {
    let marker = format!("{name}=\"{starts}");
    let (_, rest) = page.split_once(&marker).expect("the attribute");
    let (rest, _) = rest.split_once('"').expect("a closing quote");
    format!("{starts}{rest}")
        .replace("&#38;", "&")
        .replace("&#34;", "\"")
        .replace("&#39;", "'")
}

/// Returns the header and claims of the compact JWS `token`.
fn read_jws(token: &str) -> (Value, Value) {
    let mut parts = token.split('.');
    let mut segment = || {
        let bytes = URL_SAFE_NO_PAD
            .decode(parts.next().expect("a segment"))
            .expect("base64url");
        serde_json::from_slice::<Value>(&bytes).expect("JSON")
    };
    (segment(), segment())
}

impl Wallet {
    /// Starts FerroSMART with one wallet entry whose `[ferrosmart.upstream.openid4vp]`
    /// table carries the anchor file and `extra` too.
    async fn start_with(extra: &str) -> Self {
        let extra = extra.to_owned();
        Self::start_built(move |pki, dir| {
            format!(
                "issuer_anchor_files = [{}]\n{extra}",
                written(dir, "pid-root.pem", &pki.pid_root.pem)
            )
        })
        .await
    }

    /// Starts FerroSMART with one wallet entry whose `[ferrosmart.upstream.openid4vp]`
    /// table ends with what `table` writes for the case's certificates in its
    /// folder.
    async fn start_built(table: impl FnOnce(&Pki, &std::path::Path) -> String) -> Self {
        Self::start_at(table, "").await
    }

    /// Starts FerroSMART as [`Wallet::start_built`] does, the FHIR server's
    /// `[[ferrosmart.resource]]` table ending with `resource_extra`.
    async fn start_at(
        table: impl FnOnce(&Pki, &std::path::Path) -> String,
        resource_extra: &str,
    ) -> Self {
        let pki = Pki::new();
        let provider = Provider::start().await;
        let status = MockServer::start().await;
        let fhir = MockServer::start().await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/fhir/Patient"))
            .and(matchers::query_param(
                "identifier",
                format!("{BSN}|999990019"),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resourceType": "Bundle",
                "type": "searchset",
                "entry": [{"resource": {"resourceType": "Patient", "id": "p-1"}}],
            })))
            .mount(&fhir)
            .await;
        let keys = Keys::new();
        let dir = keys.dir.path();
        let database = Database::create().await;
        let base = format!("{}/fhir", fhir.uri());
        let resource = format!(
            "[[ferrosmart.resource]]\nbase = {base:?}\n\
             [[ferrosmart.resource.fhir_user_lookup]]\nresource_type = \"Patient\"\n\
             claim = \"personal_administrative_number\"\nsystem = {BSN:?}\n{resource_extra}"
        );
        let text = format!(
            "[ferrosmart]\nissuer = {ISSUER:?}\n[ferrosmart.database]\nurl = {database:?}\n\
             {resource}\
             [[ferrosmart.upstream]]\nname = \"wallet\"\nlabel = \"EUDI Wallet\"\n\
             [ferrosmart.upstream.openid4vp]\naccess_certificate_file = {access}\n\
             access_key_file = {access_key}\nregistration_certificate_file = {registration}\n\
             {table}\
             [[client]]\nclient_id = \"app\"\nclient_name = \"Synthetic App\"\ntoken_endpoint_auth_method = \"none\"\n\
             redirect_uris = [{REDIRECT:?}]\ngrant_types = [\"authorization_code\"]\n\
             {listing}scope = [\"openid\", \"fhirUser\"]\n",
            database = secrecy::ExposeSecret::expose_secret(&database.url),
            access = written(dir, "access.pem", &pki.access.pem),
            access_key = written(dir, "access-key.pem", &pki.access.key.serialize_pem()),
            registration = written(dir, "registration.jwt", "eyJhbGciOiJFUzI1NiJ9.e30.c2ln\n"),
            table = table(&pki, dir),
            listing = crate::support::resources_of(&resource),
        );
        let settings = config(&text, &keys).resolve().expect("resolves");
        let store = Store::connect(&settings.database_url, 2)
            .await
            .expect("connects");
        store.migrate().await.expect("migrates");
        let providers = crate::support::providers(&settings).await;
        let audit = audit(&settings);
        let state = AppState::new(settings.clone(), store.clone(), audit).with_login(providers);
        let clients = crate::support::clients(&text);
        crate::support::apply(&state, &clients).await;
        Self {
            smart: Smart {
                app: router(Arc::new(state)),
                provider,
                store,
                database,
                _keys: keys,
                settings,
                clients,
            },
            pki,
            holder: Holder::new(),
            status,
            fhir,
            pix: None,
        }
    }

    /// Starts FerroSMART with one wallet entry.
    async fn start() -> Self {
        Self::start_with("").await
    }

    /// Returns the FHIR base the app asks for.
    fn base(&self) -> String {
        format!("{}/fhir", self.fhir.uri())
    }

    /// Begins a login and fetches the request object the wallet is sent to.
    async fn begin(&self) -> Begun {
        let path = authorize_path(&[("scope", SCOPE), ("aud", &self.base())]);
        let (status, headers, page) = self.smart.get(&path, None).await;
        assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
        let cookie = set_cookie(&headers);
        let to_page = location(&headers);
        assert_eq!(
            "/wallet",
            to_page.path(),
            "the wallet page offers both lanes"
        );
        let (status, _, page) = self.smart.get("/wallet", Some(&cookie)).await;
        assert_eq!(StatusCode::OK, status, "{page}");
        let invocation =
            Url::parse(&attribute(&page, "href", "eu-eaap:")).expect("the wallet link");
        let request_uri =
            Url::parse(&param(&invocation, "request_uri").expect("a request_uri")).expect("a URL");
        let (status, headers, token) = self.smart.get(request_uri.path(), None).await;
        assert_eq!(StatusCode::OK, status, "{token}");
        assert_eq!(
            Some("application/oauth-authz-req+jwt"),
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            "RFC 9101 §10.2"
        );
        let (header, object) = read_jws(&token);
        Begun {
            cookie,
            invocation,
            header,
            object,
        }
    }

    /// Returns the holder's presentation of `credential` for `begun`.
    fn presentation(&self, credential: &Credential, begun: &Begun) -> String {
        credential.present(
            &self.pki.issuer,
            &self.holder,
            &begun.text("client_id"),
            &begun.text("nonce"),
            now(),
        )
    }

    /// Posts the form `pairs` to the response URI, as the wallet does.
    async fn post(&self, pairs: &[(&str, &str)]) -> (StatusCode, Value) {
        let (status, _, body) = self.smart.post("/wallet/response", pairs, None).await;
        (status, serde_json::from_str(&body).unwrap_or(Value::Null))
    }

    /// Posts the encrypted answer carrying `presentation` to `begun`.
    async fn answer(&self, begun: &Begun, presentation: &str) -> (StatusCode, Value) {
        let payload = json!({"vp_token": {"pid": [presentation]}, "state": begun.text("state")});
        let sealed = kit::sealed(&payload, &begun.jwk());
        self.post(&[("response", &sealed)]).await
    }

    /// Follows the `redirect_uri` of the response URI's answer `body` in the
    /// browser of `cookie`.
    async fn come_back(
        &self,
        body: &Value,
        cookie: Option<&str>,
    ) -> (StatusCode, http::HeaderMap, String) {
        let back =
            Url::parse(body["redirect_uri"].as_str().expect("a redirect_uri")).expect("a URL");
        assert_eq!("/wallet/complete", back.path(), "the way back");
        let path = format!("{}?{}", back.path(), back.query().unwrap_or_default());
        self.smart.get(&path, cookie).await
    }

    async fn stop(self) {
        self.smart.stop().await;
    }
}

/// Returns the `110122` Login records of `store`, oldest first.
async fn logins(store: &Store) -> Vec<String> {
    records(store)
        .await
        .iter()
        .filter(|record| record.pointer("/subtype/0/code") == Some(&json!("110122")))
        .map(Value::to_string)
        .collect()
}

#[tokio::test]
async fn a_pid_presented_from_the_wallet_logs_the_person_in_and_finds_their_fhir_user() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let presentation = wallet.presentation(&Credential::pid(), &begun);
    let (status, body) = wallet.answer(&begun, &presentation).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let (status, headers, page) = wallet.come_back(&body, Some(&begun.cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    assert_eq!("/consent", location(&headers).path());
    let pending = wallet
        .smart
        .store
        .pending(&begun.cookie)
        .await
        .expect("reads")
        .expect("the request");
    assert_eq!(
        Some(ferrosmart::upstream::pairwise(kit::PID, "NL:999990019")),
        pending.subject,
        "pairwise over the issuing country and the identifier"
    );
    assert_eq!(
        Some("Patient/p-1"),
        pending.fhir_user.as_deref(),
        "the administrative number found the person's Patient"
    );
    assert_eq!(
        Some(ferrohealth_smart::assurance::AssuranceLevel::High),
        pending.acr,
        "a PID login is at level high"
    );
    assert_eq!(Some("Eva Jansen"), pending.display_name.as_deref());
    let recorded = logins(&wallet.smart.store).await;
    let login = recorded.last().expect("the login is recorded");
    assert!(login.contains("\"outcome\":\"0\""), "{login}");
    assert!(
        !login.contains("999990019"),
        "no identifier in the record: {login}"
    );
    wallet.stop().await;
}

#[tokio::test]
async fn the_request_object_follows_haip_and_the_eu_profile() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    assert_eq!("eu-eaap", begun.invocation.scheme(), "{}", begun.invocation);
    assert_eq!(
        Some("post".to_owned()),
        param(&begun.invocation, "request_uri_method")
    );
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &wallet.pki.access.der);
    let client_id = format!("x509_hash:{}", URL_SAFE_NO_PAD.encode(digest));
    assert_eq!(
        Some(client_id.clone()),
        param(&begun.invocation, "client_id")
    );
    // NOTE: OpenID4VP 1.0 §5, RFC 9101 §10.2, ETSI TS 119 472-2 §6.4.2.
    assert_eq!("oauth-authz-req+jwt", begun.header["typ"]);
    assert_eq!("ES256", begun.header["alg"]);
    assert!(begun.header["iat"].is_i64(), "iat in the protected header");
    assert_eq!(
        json!([STANDARD.encode(&wallet.pki.access.der)]),
        begun.header["x5c"],
        "the access certificate, the anchor left out"
    );
    let object = &begun.object;
    assert_eq!(json!(client_id), object["client_id"]);
    assert_eq!("https://self-issued.me/v2", object["aud"]);
    assert_eq!("vp_token", object["response_type"]);
    assert_eq!("direct_post.jwt", object["response_mode"]);
    assert_eq!(format!("{ISSUER}/wallet/response"), object["response_uri"]);
    assert!(object.get("redirect_uri").is_none());
    let metadata = &object["client_metadata"];
    assert_eq!(
        json!(["A128GCM", "A256GCM"]),
        metadata["encrypted_response_enc_values_supported"]
    );
    let jwk = begun.jwk();
    assert_eq!(
        ("ECDH-ES", "enc", "P-256"),
        (
            jwk["alg"].as_str().expect("alg"),
            jwk["use"].as_str().expect("use"),
            jwk["crv"].as_str().expect("crv"),
        )
    );
    assert_eq!(
        object["state"], jwk["kid"],
        "the key is named by the request"
    );
    assert!(jwk.get("d").is_none());
    assert_eq!(
        json!([{"format": "registration_cert", "data": URL_SAFE_NO_PAD.encode("eyJhbGciOiJFUzI1NiJ9.e30.c2ln")}]),
        object["verifier_info"]
    );
    let query = &object["dcql_query"]["credentials"][0];
    assert_eq!("dc+sd-jwt", query["format"]);
    assert_eq!(json!([kit::PID]), query["meta"]["vct_values"]);
    assert_eq!("aki", query["trusted_authorities"][0]["type"]);
    assert!(
        query["claims"]
            .as_array()
            .expect("claims")
            .contains(&json!({"path": ["personal_administrative_number"]}))
    );
    wallet.stop().await;
}

#[tokio::test]
async fn the_request_object_is_served_again_and_echoes_a_posted_wallet_nonce() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let request_uri = Url::parse(&param(&begun.invocation, "request_uri").expect("a request_uri"))
        .expect("a URL");
    // NOTE: OpenID4VP 1.0 §5.10, the request object is not single-use.
    let (status, _, again) = wallet.smart.get(request_uri.path(), None).await;
    assert_eq!(StatusCode::OK, status);
    assert_eq!(begun.object["nonce"], read_jws(&again).1["nonce"]);
    let (status, _, posted) = wallet
        .smart
        .post(
            request_uri.path(),
            &[("wallet_nonce", "w-nonce-1"), ("wallet_metadata", "{}")],
            None,
        )
        .await;
    assert_eq!(StatusCode::OK, status, "{posted}");
    assert_eq!("w-nonce-1", read_jws(&posted).1["wallet_nonce"]);
    let (status, _, _) = wallet
        .smart
        .get("/wallet/request/unknown-state", None)
        .await;
    assert_eq!(StatusCode::NOT_FOUND, status);
    wallet.stop().await;
}

#[tokio::test]
async fn a_credential_with_a_valid_status_is_accepted() {
    let wallet = Wallet::start().await;
    let uri = format!("{}/status/1", wallet.status.uri());
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/status/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/statuslist+jwt")
                .set_body_string(kit::status_list(&wallet.pki.issuer, &uri, 64, &[3])),
        )
        .mount(&wallet.status)
        .await;
    let begun = wallet.begin().await;
    let mut credential = Credential::pid();
    credential.status = Some(json!({"status_list": {"idx": 7, "uri": uri}}));
    let (status, body) = wallet
        .answer(&begun, &wallet.presentation(&credential, &begun))
        .await;
    assert_eq!(StatusCode::OK, status, "{body}");
    wallet.stop().await;
}

#[tokio::test]
async fn an_answer_brought_back_in_another_browser_is_refused() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let (status, body) = wallet
        .answer(&begun, &wallet.presentation(&Credential::pid(), &begun))
        .await;
    assert_eq!(StatusCode::OK, status, "{body}");
    // NOTE: HAIP 1.0 §5.1, the redirect back must arrive in the session that began it.
    let (status, headers, _) = wallet.come_back(&body, Some("another-browser")).await;
    assert_ne!(StatusCode::SEE_OTHER, status);
    assert!(headers.get(header::LOCATION).is_none());
    let pending = wallet
        .smart
        .store
        .pending(&begun.cookie)
        .await
        .expect("reads")
        .expect("the request");
    assert_eq!(None, pending.subject, "no one logged in");
    let (status, _, _) = wallet.come_back(&body, Some(&begun.cookie)).await;
    assert_ne!(StatusCode::SEE_OTHER, status, "the code was taken once");
    wallet.stop().await;
}

#[tokio::test]
async fn a_declined_presentation_sends_the_app_access_denied() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let payload = json!({"error": "access_denied", "state": begun.text("state")});
    let sealed = kit::sealed(&payload, &begun.jwk());
    let (status, body) = wallet.post(&[("response", &sealed)]).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let (status, headers, page) = wallet.come_back(&body, Some(&begun.cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    let back = location(&headers);
    assert!(back.as_str().starts_with(REDIRECT), "{back}");
    assert_eq!(Some("access_denied".to_owned()), param(&back, "error"));
    assert_eq!(
        Some("synthetic-state".to_owned()),
        param(&back, "state"),
        "the app's own state"
    );
    let recorded = logins(&wallet.smart.store).await;
    assert!(
        recorded.last().expect("recorded").contains("declined"),
        "{recorded:?}"
    );
    wallet.stop().await;
}

#[tokio::test]
async fn an_error_posted_against_the_public_state_blocks_no_presentation() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    // NOTE: OpenID4VP 1.0 §8.3.1, an error may come in the clear, by anyone holding the state.
    let (status, forged) = wallet
        .post(&[("error", "access_denied"), ("state", &begun.text("state"))])
        .await;
    assert_eq!(StatusCode::OK, status, "{forged}");
    let (status, headers, _) = wallet.come_back(&forged, None).await;
    assert_ne!(StatusCode::SEE_OTHER, status, "no browser, no request ends");
    assert!(
        headers.get(header::LOCATION).is_none(),
        "nothing redirected"
    );
    let presentation = wallet.presentation(&Credential::pid(), &begun);
    let (status, body) = wallet.answer(&begun, &presentation).await;
    assert_eq!(
        StatusCode::OK,
        status,
        "the nonce is still the person's: {body}"
    );
    let (status, headers, page) = wallet.come_back(&body, Some(&begun.cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    assert_eq!("/consent", location(&headers).path());
    wallet.stop().await;
}

#[tokio::test]
async fn a_declined_answer_naming_another_state_ends_nothing() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let path = "/wallet/complete?error=access_denied&state=another-state";
    let (status, headers, _) = wallet.smart.get(path, Some(&begun.cookie)).await;
    assert_ne!(StatusCode::SEE_OTHER, status);
    assert!(
        headers.get(header::LOCATION).is_none(),
        "nothing redirected"
    );
    let pending = wallet
        .smart
        .store
        .pending(&begun.cookie)
        .await
        .expect("reads");
    assert!(pending.is_some(), "the request stays");
    wallet.stop().await;
}

#[tokio::test]
async fn the_registration_lists_what_the_registrar_records() {
    let wallet = Wallet::start().await;
    let text = format!(
        "[ferrosmart]\nissuer = {ISSUER:?}\n[[ferrosmart.upstream]]\nname = \"wallet\"\n\
         [ferrosmart.upstream.openid4vp]\n"
    );
    let section = config(&text, &Keys::new());
    let registration =
        ferrosmart::upstream::registration::Registration::of(&section.ferrosmart, "wallet")
            .expect("a registration");
    assert_eq!(
        Some(format!("{ISSUER}/wallet/response").as_str()),
        registration.get("response URI")
    );
    assert_eq!(
        Some(format!("{ISSUER}/wallet/complete").as_str()),
        registration.get("redirect URI")
    );
    assert_eq!(Some(kit::PID), registration.get("credential types"));
    let subject =
        ferrosmart::upstream::registration::subject(&section.ferrosmart, "wallet", "NL:999990019")
            .expect("a subject");
    assert_eq!(
        ferrosmart::upstream::pairwise(kit::PID, "NL:999990019"),
        subject
    );
    wallet.stop().await;
}

#[tokio::test]
async fn a_wallet_entry_takes_no_assurance_levels_and_asks_for_its_identifier() {
    let keys = Keys::new();
    let entry = |extra: &str| {
        format!(
            "[ferrosmart]\nissuer = {ISSUER:?}\n[ferrosmart.database]\nurl = {:?}\n\
             [[ferrosmart.upstream]]\nname = \"wallet\"\n[ferrosmart.upstream.openid4vp]\n{extra}",
            crate::support::UNREACHED_DATABASE
        )
    };
    let claims = entry("claims = [\"family_name\", \"issuing_country\"]\n");
    let refused = config(&claims, &keys).resolve().expect_err("refused");
    assert!(
        refused.to_string().contains("identifier_claim"),
        "{refused}"
    );
    let levels = format!(
        "{}[ferrosmart.upstream.assurance]\nlevels = {{ \"x\" = \"high\" }}\n",
        entry("")
    );
    let refused = config(&levels, &keys).resolve().expect_err("refused");
    assert!(refused.to_string().contains("level high"), "{refused}");
}

/// A JPEG portrait as the PID Rulebook 1.6 §4.1.1 encodes it.
const PORTRAIT: &str = "data:image/jpeg;base64,/9j/4AAQSkZJRg==";

// NOTE: Implementing Regulation (EU) 2024/2977 Art 3a(3); Regulation (EU) 2016/679 Art 5(1)(c).
#[tokio::test]
async fn a_wallet_entry_never_asks_for_the_portrait() {
    let keys = Keys::new();
    let entry = |extra: &str| {
        format!(
            "[ferrosmart]\nissuer = {ISSUER:?}\n[ferrosmart.database]\nurl = {:?}\n\
             [[ferrosmart.upstream]]\nname = \"wallet\"\n[ferrosmart.upstream.openid4vp]\n{extra}",
            crate::support::UNREACHED_DATABASE
        )
    };
    for table in [
        "claims = [\"picture\", \"personal_administrative_number\", \"issuing_country\"]\n",
        "mdoc_claims = [\"portrait\", \"personal_administrative_number\", \"issuing_country\"]\n",
    ] {
        let refused = config(&entry(table), &keys).resolve().expect_err("refused");
        let message = refused.to_string();
        assert!(
            message.contains("portrait") && message.contains("2024/2977 Art 3a(3)"),
            "{table}: {message}"
        );
    }
}

#[tokio::test]
async fn the_portrait_is_never_asked_for_kept_or_forwarded() {
    let wallet = Wallet::start().await;
    let begun = wallet.begin().await;
    let query = begun.object["dcql_query"].to_string();
    assert!(
        !query.contains("picture") && !query.contains("portrait"),
        "never asked for: {query}"
    );
    let mut credential = Credential::pid();
    credential
        .claims
        .push((String::from("picture"), json!(PORTRAIT)));
    let presentation = wallet.presentation(&credential, &begun);
    let (status, body) = wallet.answer(&begun, &presentation).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let (status, headers, page) = wallet.come_back(&body, Some(&begun.cookie)).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    assert_eq!("/consent", location(&headers).path());
    let pending = wallet
        .smart
        .store
        .pending(&begun.cookie)
        .await
        .expect("reads")
        .expect("the request");
    let kept = serde_json::to_string(&pending.person_claims).expect("JSON");
    assert!(kept.contains("Jansen"), "the names are kept: {kept}");
    assert!(
        !kept.contains("picture") && !kept.contains(PORTRAIT),
        "never kept: {kept}"
    );
    let recorded = serde_json::to_string(&records(&wallet.smart.store).await).expect("JSON");
    assert!(!recorded.contains(PORTRAIT), "never recorded: {recorded}");

    let (status, _, page) = wallet.smart.get("/consent", Some(&begun.cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(!page.contains(PORTRAIT), "never drawn: {page}");
    let token = page
        .split("name=\"form_token\" value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("a form token")
        .to_owned();
    let (status, headers, _) = wallet
        .smart
        .post(
            "/consent",
            &[
                ("form_token", &token),
                ("decision", "approve"),
                ("scope", "openid"),
                ("scope", "fhirUser"),
            ],
            Some(&begun.cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    let code = param(&location(&headers), "code").expect("a code");
    let exchange = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
        ("client_id", "app"),
    ];
    let (status, _, body) = wallet.smart.post("/token", &exchange, None).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let tokens: Value = serde_json::from_str(&body).expect("JSON");
    for name in ["id_token", "access_token"] {
        let token = tokens[name].as_str().expect("a token");
        let claims: Value = jsonwebtoken::dangerous::insecure_decode_claims(token).expect("claims");
        assert!(
            claims.get("picture").is_none() && !claims.to_string().contains(PORTRAIT),
            "never forwarded in the {name}: {claims}"
        );
    }
    wallet.stop().await;
}
