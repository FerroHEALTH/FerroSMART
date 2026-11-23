// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The SAML 2.0 login through the whole stack (#688): a test identity
//! provider in the case, FerroSMART's `[ferrosmart.saml]` service provider,
//! the assertion consumer service by HTTP-POST and by HTTP-Artifact over
//! mutual TLS, the replay record in PostgreSQL and the `110122` Login
//! record of each outcome.

use std::io::Read as _;
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ferrosmart::saml::keys::SigningKey;
use sqlx::Connection as _;

use super::*;
use crate::saml::kit::{self, Assertion, Pem};

/// The identity provider's single sign-on location.
const SSO: &str = "https://idp.example.org/sso";
/// The persistent name identifier format (saml-core-2.0-os §8.3.7).
const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
/// The SAML login's binding cookie.
const SAML_COOKIE: &str = ferrosmart::authorize::choose::SAML_COOKIE;
/// The scope every case asks for: no patient context, so the login goes on
/// to the consent page.
const SCOPE: &str = "openid fhirUser user/Observation.rs";

/// Returns a time `seconds` from now, as a SAML instant.
fn instant(seconds: i64) -> String {
    jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(seconds))
        .expect("in range")
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

/// Writes the test provider's metadata: its signing certificate, its
/// single sign-on service under both request bindings, and an artifact
/// resolution service at `ars` when it has one.
fn idp_metadata(certificate: &[u8], ars: Option<&str>) -> String {
    let ars = ars.map_or_else(String::new, |location| {
        format!(
            "<md:ArtifactResolutionService index=\"1\" Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\" Location=\"{location}\"/>"
        )
    });
    format!(
        concat!(
            "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ",
            "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"{idp}\">",
            "<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" ",
            "WantAuthnRequestsSigned=\"true\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data>",
            "<ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>",
            "</md:KeyDescriptor>{ars}",
            "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"{sso}\"/>",
            "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"{sso}\"/>",
            "</md:IDPSSODescriptor></md:EntityDescriptor>"
        ),
        idp = kit::IDP,
        certificate = STANDARD.encode(certificate),
        ars = ars,
        sso = SSO,
    )
}

/// How the provider of a case is set up.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// It answers by HTTP-POST, asked by HTTP-Redirect.
    Post,
    /// It is asked by HTTP-POST.
    PostRequest,
    /// It answers by HTTP-Artifact, resolved over mutual TLS.
    Artifact,
}

/// FerroSMART over one SAML provider, with the provider's key and, for an
/// artifact case, its resolution service.
struct Saml {
    /// The server.
    smart: Smart,
    /// The key the provider signs with.
    idp: SigningKey,
    /// The artifact resolution service.
    ars: Option<Ars>,
}

/// Writes `text` to `dir/name` and returns the path as TOML text.
fn written(dir: &std::path::Path, name: &str, text: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, text).expect("written");
    format!("{:?}", path.display().to_string())
}

impl Saml {
    async fn start(shape: Shape) -> Self {
        Self::start_beside(shape, "").await
    }

    /// Starts FerroSMART over the SAML provider of `shape`, with the
    /// further `[[ferrosmart.upstream]]` entries `beside`.
    async fn start_beside(shape: Shape, beside: &str) -> Self {
        Self::start_full(shape, beside, "substantial", "").await
    }

    /// Starts the server of [`Saml::start_beside`] whose provider's class
    /// stands for the eIDAS level `level` and whose app's table carries
    /// `client` too.
    async fn start_full(shape: Shape, beside: &str, level: &str, client: &str) -> Self {
        let provider = Provider::start().await;
        let keys = Keys::new();
        let dir = keys.dir.path();
        let database = Database::create().await;
        let idp = kit::rsa_pem();
        let sp = kit::p256_pem();
        let decryption = kit::rsa_pem();
        let ars = match shape {
            Shape::Artifact => Some(Ars::start().await),
            Shape::Post | Shape::PostRequest => None,
        };
        let metadata = written(
            dir,
            "idp-metadata.xml",
            &idp_metadata(&idp.der, ars.as_ref().map(|ars| ars.location.as_str())),
        );
        let tls = ars.as_ref().map_or_else(String::new, |ars| {
            format!(
                "[ferrosmart.saml.tls]\nclient_identity_file = {}\ntrust_roots_file = {}\n",
                written(dir, "tls-identity.pem", &ars.client_identity),
                written(dir, "tls-roots.pem", &ars.ca_pem),
            )
        });
        let (request_binding, response_binding) = match shape {
            Shape::Post => ("redirect", "post"),
            Shape::PostRequest => ("post", "post"),
            Shape::Artifact => ("redirect", "artifact"),
        };
        let text = format!(
            "[ferrosmart]\nissuer = {ISSUER:?}\n[ferrosmart.database]\nurl = {database:?}\n\
             [ferrosmart.saml]\nentity_id = {sp_entity:?}\nsigning_key_file = {sp_key}\n\
             signing_certificate_file = {sp_certificate}\n\
             [[ferrosmart.saml.decryption]]\nkey_file = {decryption_key}\ncertificate_file = {decryption_certificate}\n\
             {tls}\
             [[ferrosmart.upstream]]\nname = \"national\"\nlabel = \"National login\"\n\
             [ferrosmart.upstream.saml]\nentity_id = {idp_entity:?}\nmetadata_file = {metadata}\n\
             request_binding = {request_binding:?}\nresponse_binding = {response_binding:?}\n\
             name_id_format = {PERSISTENT:?}\nauthn_contexts = [{strong:?}]\n\
             fhir_user_claim = \"fhir_user\"\nrole_claims = [\"roles\"]\n\
             [ferrosmart.upstream.saml.claims]\nname = \"displayName\"\nroles = \"role\"\nfhir_user = \"fhirUser\"\n\
             [ferrosmart.upstream.assurance]\nlevels = {{ {strong:?} = {level:?} }}\n\
             {beside}\
             [[ferrosmart.role]]\nname = \"clinician\"\nscopes = [\"user/Observation.rs\"]\n\
             [[client]]\nclient_id = \"app\"\nclient_name = \"Synthetic App\"\ntoken_endpoint_auth_method = \"none\"\n\
             redirect_uris = [{REDIRECT:?}]\ngrant_types = [\"authorization_code\"]\n\
             scope = [\"openid\", \"fhirUser\", \"user/Observation.rs\"]\n{client}",
            database = secrecy::ExposeSecret::expose_secret(&database.url),
            sp_entity = kit::SP,
            sp_key = written(dir, "sp-key.pem", &sp.key),
            sp_certificate = written(dir, "sp-certificate.pem", &sp.certificate),
            decryption_key = written(dir, "decryption-key.pem", &decryption.key),
            decryption_certificate =
                written(dir, "decryption-certificate.pem", &decryption.certificate),
            idp_entity = kit::IDP,
            strong = kit::STRONG,
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
                provider,
                store,
                database,
                _keys: keys,
                settings,
                clients,
            },
            idp: signing_key(&idp),
            ars,
        }
    }

    async fn stop(self) {
        self.smart.stop().await;
    }

    /// Posts `pairs` to the assertion consumer service with the SAML
    /// binding cookie `binding`, if any.
    async fn acs_post(
        &self,
        pairs: &[(&str, &str)],
        binding: Option<&str>,
    ) -> (StatusCode, http::HeaderMap, String) {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        let mut request = Request::post("/saml/acs")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(binding) = binding {
            request = request.header(header::COOKIE, format!("{SAML_COOKIE}={binding}"));
        }
        self.smart
            .send(request.body(Body::from(body)).expect("a request"))
            .await
    }

    /// Returns `assertion` signed by the provider, in a response to the
    /// request `request_id`, as the `SAMLResponse` form value.
    fn answer(&self, assertion: &Assertion) -> String {
        let signed = kit::sign(&assertion.xml(), &self.idp);
        kit::posted(&kit::response_with(
            "_response1",
            &assertion.in_response_to,
            "Success",
            &signed,
        ))
    }
}

/// Returns the signing key of the PEM pair `pem`.
fn signing_key(pem: &Pem) -> SigningKey {
    SigningKey::from_pem(pem.key.as_bytes(), pem.certificate.as_bytes()).expect("a signing key")
}

/// Returns an assertion for the request `request_id`, valid now, for a
/// clinician whose `fhirUser` the provider carries.
fn assertion(request_id: &str) -> Assertion {
    Assertion {
        in_response_to: request_id.to_owned(),
        confirm_until: instant(300),
        not_before: instant(-60),
        not_on_or_after: instant(300),
        attributes: String::from(concat!(
            "<saml:Attribute Name=\"displayName\"><saml:AttributeValue>Synthetic Clinician</saml:AttributeValue></saml:Attribute>",
            "<saml:Attribute Name=\"role\"><saml:AttributeValue>clinician</saml:AttributeValue></saml:Attribute>",
            "<saml:Attribute Name=\"fhirUser\"><saml:AttributeValue>Practitioner/synthetic-1</saml:AttributeValue></saml:Attribute>"
        )),
        ..Assertion::default()
    }
}

/// A login begun at the authorization endpoint.
struct Begun {
    /// The request's cookie.
    cookie: String,
    /// The SAML login's binding cookie.
    binding: String,
    /// The `AuthnRequest` FerroSMART sent, inflated.
    request: String,
    /// The request's `ID`.
    request_id: String,
    /// The `RelayState`.
    relay_state: String,
}

/// Returns the value of the cookie `name` among the `Set-Cookie` headers.
fn set_cookie_named(headers: &http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| {
            let (found, rest) = value.split_once('=')?;
            (found == name).then(|| rest.split(';').next().unwrap_or_default().to_owned())
        })
}

/// Returns the `ID` attribute of the root of `xml`.
fn root_id(xml: &str) -> String {
    roxmltree::Document::parse(xml)
        .expect("well formed")
        .root_element()
        .attribute("ID")
        .expect("an ID")
        .to_owned()
}

/// Returns the `AuthnRequest` the HTTP-Redirect URL `to` carries,
/// inflated (saml-bindings-2.0-os §3.4.4.1).
fn inflated(to: &Url) -> String {
    let deflated = STANDARD
        .decode(param(to, "SAMLRequest").expect("a request"))
        .expect("base64");
    let mut request = String::new();
    flate2::read::DeflateDecoder::new(deflated.as_slice())
        .read_to_string(&mut request)
        .expect("DEFLATE");
    request
}

/// Begins a login at the authorization endpoint and reads the request the
/// browser is redirected to the provider with.
async fn begin(smart: &Smart) -> Begun {
    let (status, headers, page) = smart.get(&authorize_path(&[("scope", SCOPE)]), None).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    let to = location(&headers);
    assert_eq!(
        SSO,
        format!("{}{}", to.origin().ascii_serialization(), to.path()),
        "the browser goes to the single sign-on location"
    );
    // NOTE: saml-bindings-2.0-os §3.4.4.1, a signed redirect carries SigAlg and Signature.
    assert!(
        param(&to, "SigAlg").is_some() && param(&to, "Signature").is_some(),
        "{to}"
    );
    let request = inflated(&to);
    let relay_state = param(&to, "RelayState").expect("a RelayState");
    assert!(relay_state.len() <= 80, "saml-bindings-2.0-os §3.4.3");
    Begun {
        cookie: set_cookie_named(&headers, COOKIE).expect("the request's cookie"),
        binding: set_cookie_named(&headers, SAML_COOKIE).expect("the binding cookie"),
        request_id: root_id(&request),
        request,
        relay_state,
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
async fn a_saml_login_by_post_reaches_the_consent_page_and_is_recorded() {
    let saml = Saml::start(Shape::Post).await;
    let begun = begin(&saml.smart).await;
    // NOTE: saml-core-2.0-os §3.3.2.2.1, the provider's minimum as the accepted classes.
    assert!(
        begun.request.contains("Comparison=\"exact\"") && begun.request.contains(kit::STRONG),
        "{}",
        begun.request
    );
    assert!(
        begun
            .request
            .contains("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"")
    );
    let response = saml.answer(&assertion(&begun.request_id));
    let (status, headers, page) = saml
        .acs_post(
            &[
                ("SAMLResponse", &response),
                ("RelayState", &begun.relay_state),
            ],
            Some(&begun.binding),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    assert_eq!("/consent", location(&headers).path());
    assert_eq!(
        Some(String::new()),
        set_cookie_named(&headers, SAML_COOKIE),
        "the binding cookie is cleared"
    );
    let pending = saml
        .smart
        .store
        .pending(&begun.cookie)
        .await
        .expect("reads")
        .expect("the request");
    assert_eq!(
        Some("Practitioner/synthetic-1"),
        pending.fhir_user.as_deref(),
        "the fhirUser claim the attribute maps to"
    );
    assert_eq!(vec![String::from("clinician")], pending.roles);
    assert_eq!(Some("Synthetic Clinician"), pending.display_name.as_deref());
    assert_eq!(
        Some(ferrohealth_smart::assurance::AssuranceLevel::Substantial),
        pending.acr,
        "the level the class maps to"
    );
    let recorded = logins(&saml.smart.store).await;
    let login = recorded.last().expect("the login is recorded");
    assert!(login.contains("\"outcome\":\"0\""), "{login}");
    assert!(
        !login.contains("person-17"),
        "no upstream identifier: {login}"
    );
    saml.stop().await;
}

#[tokio::test]
async fn a_login_older_than_max_age_is_asked_again_with_force_authn() {
    let saml = Saml::start(Shape::Post).await;
    let (status, headers, page) = saml
        .smart
        .get(
            &authorize_path(&[("scope", SCOPE), ("max_age", "60")]),
            None,
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    let cookie = set_cookie_named(&headers, COOKIE).expect("the request's cookie");
    let binding = set_cookie_named(&headers, SAML_COOKIE).expect("the binding cookie");
    let to = location(&headers);
    let relay_state = param(&to, "RelayState").expect("a RelayState");
    let request_id = root_id(&inflated(&to));
    // NOTE: OpenID Connect Core 1.0 §3.1.2.1, past max_age the login is begun again;
    // the test assertion's AuthnInstant lies a day back.
    let response = saml.answer(&assertion(&request_id));
    let (status, headers, page) = saml
        .acs_post(
            &[("SAMLResponse", &response), ("RelayState", &relay_state)],
            Some(&binding),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    let again = location(&headers);
    assert!(again.as_str().starts_with(SSO), "{again}");
    assert!(
        inflated(&again).contains("ForceAuthn=\"true\""),
        "saml-core-2.0-os §3.4.1"
    );
    let bindings: Vec<&str> = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter(|value| value.starts_with(SAML_COOKIE))
        .collect();
    assert_eq!(
        vec![format!("{SAML_COOKIE}={cookie}")],
        bindings
            .iter()
            .filter_map(|value| value.split(';').next())
            .collect::<Vec<_>>(),
        "the browser stays bound to the request, and the binding is not cleared"
    );
    saml.stop().await;
}

#[tokio::test]
async fn a_replayed_assertion_is_refused_and_recorded() {
    let saml = Saml::start(Shape::Post).await;
    let first = begin(&saml.smart).await;
    let response = saml.answer(&assertion(&first.request_id));
    let (status, headers, _) = saml
        .acs_post(
            &[
                ("SAMLResponse", &response),
                ("RelayState", &first.relay_state),
            ],
            Some(&first.binding),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    assert_eq!("/consent", location(&headers).path());
    // NOTE: saml-profiles-2.0-os §4.1.4.5, the same assertion ID answering a second
    // request is a replay, whatever else it says.
    let second = begin(&saml.smart).await;
    let replayed = saml.answer(&assertion(&second.request_id));
    let (status, headers, page) = saml
        .acs_post(
            &[
                ("SAMLResponse", &replayed),
                ("RelayState", &second.relay_state),
            ],
            Some(&second.binding),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    let back = location(&headers);
    assert!(back.as_str().starts_with(REDIRECT), "{back}");
    assert_eq!(Some("server_error"), param(&back, "error").as_deref());
    let recorded = logins(&saml.smart.store).await;
    let refusal = recorded.last().expect("the refusal is recorded");
    assert!(refusal.contains("already used"), "{refusal}");
    let replays = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM seen_saml_assertion")
        .fetch_one(
            &mut sqlx::PgConnection::connect(secrecy::ExposeSecret::expose_secret(
                &saml.smart.database.url,
            ))
            .await
            .expect("connects"),
        )
        .await
        .expect("counts");
    assert_eq!(1, replays, "the assertion ID is kept once");
    saml.stop().await;
}

#[tokio::test]
async fn a_class_below_the_minimum_is_refused_by_name() {
    let saml = Saml::start(Shape::Post).await;
    let begun = begin(&saml.smart).await;
    let weak = Assertion {
        class: String::from(kit::WEAK),
        ..assertion(&begun.request_id)
    };
    let response = saml.answer(&weak);
    let (status, headers, _) = saml
        .acs_post(
            &[
                ("SAMLResponse", &response),
                ("RelayState", &begun.relay_state),
            ],
            Some(&begun.binding),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    assert_eq!(
        Some("server_error"),
        param(&location(&headers), "error").as_deref()
    );
    let recorded = logins(&saml.smart.store).await;
    let refusal = recorded.last().expect("the refusal is recorded");
    assert!(
        refusal.contains("below the provider") && refusal.contains("\"outcome\":\"4\""),
        "{refusal}"
    );
    saml.stop().await;
}

// NOTE: docs/architecture.md §13.28, the class's eIDAS level against the level the
// client's default_acr_values ask for (OpenID Connect Dynamic Client Registration 1.0 §2).
#[tokio::test]
async fn a_class_is_held_to_its_eidas_level_and_the_client_s_default_acr_values() {
    for (level, minimum, error) in [
        ("high", "", None),
        (
            "substantial",
            "default_acr_values = [\"http://eidas.europa.eu/LoA/high\"]",
            Some("unmet_authentication_requirements"),
        ),
    ] {
        let saml = Saml::start_full(Shape::Post, "", level, minimum).await;
        let begun = begin(&saml.smart).await;
        let response = saml.answer(&assertion(&begun.request_id));
        let (status, headers, page) = saml
            .acs_post(
                &[
                    ("SAMLResponse", &response),
                    ("RelayState", &begun.relay_state),
                ],
                Some(&begun.binding),
            )
            .await;
        assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
        let back = location(&headers);
        match error {
            None => {
                assert_eq!("/consent", back.path());
                let pending = saml
                    .smart
                    .store
                    .pending(&begun.cookie)
                    .await
                    .expect("reads")
                    .expect("the request");
                assert_eq!(
                    Some(ferrohealth_smart::assurance::AssuranceLevel::High),
                    pending.acr
                );
            }
            Some(error) => {
                assert_eq!(Some(String::from(error)), param(&back, "error"));
                let recorded = logins(&saml.smart.store).await;
                let login = recorded.last().expect("the refusal is recorded");
                assert!(login.contains("\"outcome\":\"4\""), "{login}");
            }
        }
        saml.stop().await;
    }
}

#[tokio::test]
async fn a_provider_s_status_other_than_success_is_access_denied() {
    let saml = Saml::start(Shape::Post).await;
    let begun = begin(&saml.smart).await;
    let response = kit::posted(&kit::response_with(
        "_response1",
        &begun.request_id,
        "Responder",
        "",
    ));
    let (status, headers, _) = saml
        .acs_post(
            &[
                ("SAMLResponse", &response),
                ("RelayState", &begun.relay_state),
            ],
            Some(&begun.binding),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    assert_eq!(
        Some("access_denied"),
        param(&location(&headers), "error").as_deref()
    );
    saml.stop().await;
}

#[tokio::test]
async fn a_response_in_another_browser_or_without_relay_state_is_refused_and_leaves_the_request() {
    let saml = Saml::start(Shape::Post).await;
    let begun = begin(&saml.smart).await;
    let response = saml.answer(&assertion(&begun.request_id));
    let (status, _, _) = saml
        .acs_post(
            &[
                ("SAMLResponse", &response),
                ("RelayState", &begun.relay_state),
            ],
            None,
        )
        .await;
    assert_eq!(StatusCode::FORBIDDEN, status, "RFC 9700 §4.7");
    // NOTE: saml-profiles-2.0-os §4.1.5, an unsolicited response answers no request.
    let (status, headers, _) = saml
        .acs_post(&[("SAMLResponse", &response)], Some(&begun.binding))
        .await;
    assert_ne!(StatusCode::SEE_OTHER, status, "{headers:?}");
    let (status, headers, page) = saml
        .acs_post(
            &[
                ("SAMLResponse", &response),
                ("RelayState", &begun.relay_state),
            ],
            Some(&begun.binding),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    assert_eq!("/consent", location(&headers).path());
    saml.stop().await;
}

#[tokio::test]
async fn a_posted_request_is_a_page_whose_form_carries_it_to_the_provider() {
    let saml = Saml::start(Shape::PostRequest).await;
    let (status, headers, page) = saml
        .smart
        .get(&authorize_path(&[("scope", SCOPE)]), None)
        .await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(
        page.contains(&format!("action=\"{SSO}\""))
            && page.contains("name=\"SAMLRequest\"")
            && page.contains("name=\"RelayState\""),
        "{page}"
    );
    let policy = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(policy.contains("https://idp.example.org"), "{policy}");
    assert!(set_cookie_named(&headers, SAML_COOKIE).is_some());
    saml.stop().await;
}

#[tokio::test]
async fn the_service_provider_metadata_names_the_assertion_consumer_service() {
    let saml = Saml::start(Shape::Post).await;
    let (status, headers, body) = saml.smart.get("/saml/metadata", None).await;
    assert_eq!(StatusCode::OK, status);
    assert_eq!(
        Some("application/samlmetadata+xml"),
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
    );
    let document = roxmltree::Document::parse(&body).expect("well formed");
    let root = document.root_element();
    assert_eq!(Some(kit::SP), root.attribute("entityID"));
    let acs: Vec<&str> = document
        .descendants()
        .filter(|node| node.tag_name().name() == "AssertionConsumerService")
        .filter_map(|node| node.attribute("Location"))
        .collect();
    assert_eq!(vec![kit::ACS, kit::ACS], acs);
    assert!(body.contains(PERSISTENT), "{body}");
    assert!(body.contains("use=\"encryption\""), "{body}");
    saml.stop().await;
}

#[tokio::test]
async fn the_chooser_lists_a_saml_provider_beside_an_openid_connect_one() {
    let held = tempfile::tempdir().expect("a directory");
    let assertion = crate::support::upstream_assertion(held.path());
    let oidc = Provider::start().await;
    let beside = format!(
        "[[ferrosmart.upstream]]\nname = \"staff\"\nlabel = \"Hospital staff\"\n\
         [ferrosmart.upstream.oidc]\nissuer = {:?}\nclient_id = {UPSTREAM_CLIENT:?}\n{assertion}{ASSURANCE}",
        oidc.server.uri()
    );
    let saml = Saml::start_beside(Shape::Post, &beside).await;
    let (status, headers, _) = saml
        .smart
        .get(&authorize_path(&[("scope", SCOPE)]), None)
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    assert_eq!(format!("{ISSUER}/login"), location(&headers).as_str());
    let cookie = set_cookie(&headers);
    let (status, headers, page) = saml.smart.get("/login", Some(&cookie)).await;
    assert_eq!(StatusCode::OK, status, "{page}");
    assert!(
        page.contains("National login") && page.contains("Hospital staff"),
        "{page}"
    );
    let policy = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(
        policy.contains("https://idp.example.org") && policy.contains(&oidc.server.uri()),
        "{policy}"
    );
    let (status, headers, _) = saml
        .smart
        .post(
            "/login",
            &[("form_token", &form_token(&page)), ("provider", "national")],
            Some(&cookie),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    assert!(location(&headers).as_str().starts_with(SSO));
    assert!(set_cookie_named(&headers, SAML_COOKIE).is_some());
    saml.stop().await;
}

#[tokio::test]
async fn an_artifact_is_resolved_over_mutual_tls_and_completes_the_login() {
    let saml = Saml::start(Shape::Artifact).await;
    let begun = begin(&saml.smart).await;
    assert!(
        begun
            .request
            .contains("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\"")
    );
    let ars = saml.ars.as_ref().expect("the resolution service");
    let signed = kit::sign(&assertion(&begun.request_id).xml(), &saml.idp);
    ars.answer_with(&kit::response_with(
        "_response1",
        &begun.request_id,
        "Success",
        &signed,
    ));
    let artifact = artifact();
    let path = format!(
        "/saml/acs?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("SAMLart", artifact.as_str()),
                ("RelayState", &begun.relay_state)
            ])
            .finish()
    );
    let request = Request::get(path)
        .header(header::COOKIE, format!("{SAML_COOKIE}={}", begun.binding))
        .body(Body::empty())
        .expect("a request");
    let (status, headers, page) = saml.smart.send(request).await;
    assert_eq!(StatusCode::SEE_OTHER, status, "{page}");
    assert_eq!("/consent", location(&headers).path());
    let seen = ars.seen();
    let resolved = seen.first().expect("the artifact was resolved");
    // NOTE: saml-profiles-2.0-os §4.1.4.4, the resolution is mutually authenticated.
    assert!(
        resolved.certificate,
        "FerroSMART presented its client certificate"
    );
    assert!(resolved.soap_action, "saml-bindings-2.0-os §3.2.3.1");
    assert!(resolved.body.contains(&artifact), "{}", resolved.body);
    saml.stop().await;
}

#[tokio::test]
async fn a_posted_response_to_a_provider_asked_for_an_artifact_is_refused() {
    let saml = Saml::start(Shape::Artifact).await;
    let begun = begin(&saml.smart).await;
    let response = saml.answer(&assertion(&begun.request_id));
    let (status, headers, _) = saml
        .acs_post(
            &[
                ("SAMLResponse", &response),
                ("RelayState", &begun.relay_state),
            ],
            Some(&begun.binding),
        )
        .await;
    assert_eq!(StatusCode::SEE_OTHER, status);
    assert_eq!(
        Some("server_error"),
        param(&location(&headers), "error").as_deref()
    );
    let recorded = logins(&saml.smart.store).await;
    assert!(
        recorded
            .last()
            .is_some_and(|refusal| refusal.contains("binding")),
        "{recorded:?}"
    );
    saml.stop().await;
}

/// Returns a type 0x0004 artifact of the test provider for its resolution
/// endpoint 1 (saml-bindings-2.0-os §3.6.4.2).
fn artifact() -> String {
    let mut bytes = vec![0_u8, 4, 0, 1];
    bytes.extend(
        aws_lc_rs::digest::digest(
            &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
            kit::IDP.as_bytes(),
        )
        .as_ref(),
    );
    let mut handle = [0_u8; 20];
    aws_lc_rs::rand::fill(&mut handle).expect("random");
    bytes.extend(handle);
    STANDARD.encode(bytes)
}

#[test]
fn a_saml_provider_without_its_service_provider_or_complete_table_is_refused_at_load() {
    let keys = Keys::new();
    let dir = keys.dir.path();
    let metadata = written(dir, "metadata.xml", "<md:EntityDescriptor/>");
    let entry = |extra: &str| {
        format!(
            "[ferrosmart]\nissuer = {ISSUER:?}\n[[ferrosmart.upstream]]\nname = \"national\"\n\
             [ferrosmart.upstream.assurance]\nlevels = {{ {:?} = \"substantial\" }}\n\
             [ferrosmart.upstream.saml]\nentity_id = {:?}\nmetadata_file = {metadata}\n{extra}",
            kit::STRONG,
            kit::IDP
        )
    };
    let refused = config(&entry(""), &keys).resolve().expect_err("refused");
    assert!(refused.to_string().contains("ferrosmart.saml"), "{refused}");
    let sp = kit::p256_pem();
    let service_provider = format!(
        "[ferrosmart.saml]\nsigning_key_file = {}\nsigning_certificate_file = {}\n",
        written(dir, "sp-key.pem", &sp.key),
        written(dir, "sp-certificate.pem", &sp.certificate)
    );
    let complete = format!("{}{service_provider}", entry(""));
    config(&complete, &keys)
        .resolve()
        .expect("a complete entry resolves");
    for (case, broken) in [
        (
            "an artifact binding needs a TLS client identity",
            "response_binding = \"artifact\"\n",
        ),
        (
            "a fhirUser claim names a mapped claim",
            "fhir_user_claim = \"fhir_user\"\n",
        ),
        (
            "a role claim names a mapped claim",
            "role_claims = [\"roles\"]\n",
        ),
        (
            "the metadata comes from one place",
            "metadata_url = \"https://idp.example.org/metadata\"\n",
        ),
    ] {
        let text = format!("{}{service_provider}", entry(broken));
        assert!(config(&text, &keys).resolve().is_err(), "{case}");
    }
    let http = format!(
        "[ferrosmart]\nissuer = {ISSUER:?}\n{service_provider}[[ferrosmart.upstream]]\nname = \"national\"\n\
         [ferrosmart.upstream.saml]\nentity_id = {:?}\nmetadata_url = \"http://idp.example.org/metadata\"\n",
        kit::IDP
    );
    assert!(
        config(&http, &keys).resolve().is_err(),
        "the metadata URL is https"
    );
}

/// One resolution request the artifact resolution service answered.
#[derive(Debug, Clone)]
struct Resolved {
    /// Whether the client presented a certificate in the handshake.
    certificate: bool,
    /// Whether the request carried the SAML `SOAPAction` header.
    soap_action: bool,
    /// The SOAP request.
    body: String,
}

/// The test provider's artifact resolution service: TLS on loopback that
/// requires a client certificate chaining to a fresh authority, answering
/// each `ArtifactResolve` with an `ArtifactResponse` carrying the response
/// a case sets.
struct Ars {
    /// Its location, `https://localhost:<port>/ars`.
    location: String,
    /// The authority every certificate chains to, PEM.
    ca_pem: String,
    /// FerroSMART's client certificate and key, one PEM.
    client_identity: String,
    /// The response the next resolution carries.
    response: Arc<Mutex<String>>,
    /// Every request it answered.
    seen: Arc<Mutex<Vec<Resolved>>>,
}

impl Ars {
    /// Starts the service.
    async fn start() -> Self {
        use rcgen::{
            BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        };
        let ca_key = KeyPair::generate().expect("a key pair");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("parameters");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        validity(&mut ca_params);
        let ca = ca_params.self_signed(&ca_key).expect("the authority signs");
        let issuer = Issuer::new(ca_params, ca_key);
        let server_key = KeyPair::generate().expect("a key pair");
        let mut server_params =
            CertificateParams::new(vec![String::from("localhost")]).expect("parameters");
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        validity(&mut server_params);
        let server = server_params
            .signed_by(&server_key, &issuer)
            .expect("the server certificate signs");
        let client_key = KeyPair::generate().expect("a key pair");
        let mut client_params =
            CertificateParams::new(vec![String::from("smart.example.org")]).expect("parameters");
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        validity(&mut client_params);
        let client = client_params
            .signed_by(&client_key, &issuer)
            .expect("the client certificate signs");
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(ca.der().clone())
            .expect("the authority is a root");
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::clone(&provider),
        )
        .build()
        .expect("a client verifier");
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()),
        );
        let tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("the protocol versions")
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![server.der().clone()], key)
            .expect("the server certificate");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let port = listener.local_addr().expect("an address").port();
        let response = Arc::new(Mutex::new(String::new()));
        let seen = Arc::new(Mutex::new(Vec::new()));
        drop(tokio::spawn(serve(
            listener,
            acceptor,
            Arc::clone(&response),
            Arc::clone(&seen),
        )));
        Self {
            location: format!("https://localhost:{port}/ars"),
            ca_pem: ca.pem(),
            client_identity: format!("{}{}", client.pem(), client_key.serialize_pem()),
            response,
            seen,
        }
    }

    /// Sets the `samlp:Response` the next resolution carries.
    fn answer_with(&self, response: &str) {
        response.clone_into(&mut self.response.lock().expect("not poisoned"));
    }

    /// Returns every request it answered.
    fn seen(&self) -> Vec<Resolved> {
        self.seen.lock().expect("not poisoned").clone()
    }
}

/// Sets the validity of a test certificate: from yesterday for thirty days.
fn validity(params: &mut rcgen::CertificateParams) {
    let today = jiff::Zoned::now().date();
    let ymd = |date: jiff::civil::Date| {
        rcgen::date_time_ymd(
            i32::from(date.year()),
            u8::try_from(date.month()).expect("a month"),
            u8::try_from(date.day()).expect("a day"),
        )
    };
    params.not_before = ymd(today.yesterday().expect("a date"));
    params.not_after = ymd(today
        .checked_add(jiff::Span::new().days(30))
        .expect("a date"));
}

/// Answers every connection that completes the handshake on `listener`.
async fn serve(
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    response: Arc<Mutex<String>>,
    seen: Arc<Mutex<Vec<Resolved>>>,
) {
    use tokio::io::AsyncWriteExt as _;
    while let Ok((tcp, _peer)) = listener.accept().await {
        let acceptor = acceptor.clone();
        let response = Arc::clone(&response);
        let seen = Arc::clone(&seen);
        drop(tokio::spawn(async move {
            let Ok(mut stream) = acceptor.accept(tcp).await else {
                return;
            };
            let certificate = stream
                .get_ref()
                .1
                .peer_certificates()
                .is_some_and(|chain| !chain.is_empty());
            let Some((head, body)) = read_request(&mut stream).await else {
                return;
            };
            let soap_action = head.lines().any(|line| {
                line.split_once(':').is_some_and(|(name, value)| {
                    name.eq_ignore_ascii_case("soapaction")
                        && value.trim() == ferrosmart::saml::artifact::SOAP_ACTION
                })
            });
            let resolve_id = roxmltree::Document::parse(&body)
                .ok()
                .and_then(|document| {
                    document
                        .descendants()
                        .find(|node| node.tag_name().name() == "ArtifactResolve")
                        .and_then(|node| node.attribute("ID").map(str::to_owned))
                })
                .unwrap_or_default();
            seen.lock().expect("not poisoned").push(Resolved {
                certificate,
                soap_action,
                body,
            });
            let inner = response.lock().expect("not poisoned").clone();
            let artifact_response = format!(
                concat!(
                    "<soap11:Envelope xmlns:soap11=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap11:Body>",
                    "<samlp:ArtifactResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ",
                    "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_ar1\" Version=\"2.0\" ",
                    "IssueInstant=\"{issued}\" InResponseTo=\"{irt}\"><saml:Issuer>{idp}</saml:Issuer>",
                    "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>",
                    "</samlp:Status>{inner}</samlp:ArtifactResponse></soap11:Body></soap11:Envelope>"
                ),
                issued = instant(-1),
                irt = resolve_id,
                idp = kit::IDP,
                inner = inner,
            );
            let answer = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/xml\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{artifact_response}",
                artifact_response.len()
            );
            if stream.write_all(answer.as_bytes()).await.is_ok() {
                drop(stream.shutdown().await);
            }
        }));
    }
}

/// Returns the head and the body of the one HTTP/1.1 request on `stream`.
async fn read_request(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Option<(String, String)> {
    use tokio::io::AsyncReadExt as _;
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(chunk.get(..read)?);
        let text = String::from_utf8_lossy(&buffer).into_owned();
        if let Some(end) = text.find("\r\n\r\n") {
            let head = text.get(..end)?.to_owned();
            let length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            let start = end + 4;
            if buffer.len() >= start + length {
                let body = buffer.get(start..start + length)?;
                return Some((head, String::from_utf8_lossy(body).into_owned()));
            }
        }
    }
}
