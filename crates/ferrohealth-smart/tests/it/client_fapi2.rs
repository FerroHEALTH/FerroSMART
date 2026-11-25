// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The key ring a client signs with and the JWK Set it publishes, the FAPI
//! 2.0 Security Profile on a client grant (build-time and metadata rules),
//! and RFC 9396 `authorization_details` sent and read back.

use std::error::Error as StdError;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use ferrohealth_smart::client::ClientCredentials;
use ferrohealth_smart::client::Endpoint;
use ferrohealth_smart::client::TokenError;
use ferrohealth_smart::client::assertion::AssertionKey;
use ferrohealth_smart::client::authorization_details::AuthorizationDetails;
use ferrohealth_smart::client::binding::IssuedToken;
use ferrohealth_smart::client::cache::TokenSource;
use ferrohealth_smart::client::dpop::DpopKey;
use ferrohealth_smart::client::fapi2::AliasHost;
use ferrohealth_smart::client::fapi2::Fapi2;
use ferrohealth_smart::client::fapi2::Fapi2Error;
use ferrohealth_smart::client::fapi2::SecurityProfile;
use ferrohealth_smart::client::keys::KeyRing;
use ferrohealth_smart::client::keys::KeyRingError;
use ferrohealth_smart::config::ConfigError;
use ferrohealth_smart::config::credentials::OauthSection;
use ferrohealth_smart::jws::algorithm::Algorithm;
use secrecy::SecretString;
use serde_json::Value;
use serde_json::json;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::Request;
use wiremock::ResponseTemplate;
use wiremock::matchers::method;
use wiremock::matchers::path;

use crate::support::ec_key;
use crate::support::temp_file;

type TestResult = Result<(), Box<dyn StdError>>;

/// The token endpoint path every stub serves.
const TOKEN_PATH: &str = "/token";

/// The RFC 9396 §2 Figure 3 request, a combined one.
const DETAILS: &str = r#"[{"type": "account_information", "actions": ["list_accounts"], "locations": ["https://example.com/accounts"]}, {"type": "payment_initiation", "actions": ["initiate"], "locations": ["https://example.com/payments"], "instructedAmount": {"currency": "EUR", "amount": "123.50"}}]"#;

/// Returns an assertion key on `alg`.
fn assertion_key(kid: &str, alg: Algorithm) -> AssertionKey {
    AssertionKey::from_pem(&ec_key(kid, alg).pem, Some(alg), None).expect("the key reads")
}

/// Returns a `DPoP` key on the curve of `alg`.
fn dpop_key(alg: Algorithm) -> Arc<DpopKey> {
    Arc::new(DpopKey::from_pem(&ec_key("dpop", alg).pem).expect("the key reads"))
}

/// Returns a FAPI 2.0 grant at `issuer`: `private_key_jwt` with ES256, the
/// issuer as `aud`, `DPoP`-bound, asking for a scope.
fn fapi2(issuer: &str) -> ClientCredentials {
    let mut grant = ClientCredentials::with_private_key_jwt(
        Endpoint::Issuer(issuer.to_owned()),
        String::from("gateway"),
        assertion_key("client", Algorithm::Es256),
    )
    .with_dpop(dpop_key(Algorithm::Es256));
    grant.scope = Some(String::from("system/Patient.r"));
    grant.profile = SecurityProfile::Fapi2(Fapi2::new());
    grant.timeout = Duration::from_secs(5);
    grant
}

/// Returns the metadata of `server` as an issuer that admits the grant
/// [`fapi2`] builds.
fn metadata(server: &MockServer) -> Value {
    json!({
        "issuer": server.uri(),
        "token_endpoint": format!("{}{TOKEN_PATH}", server.uri()),
        "token_endpoint_auth_methods_supported": ["private_key_jwt", "tls_client_auth"],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256", "PS256"],
        "grant_types_supported": ["client_credentials"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "authorization_details_types_supported": ["account_information", "payment_initiation"],
        "tls_client_certificate_bound_access_tokens": true
    })
}

/// Mounts `document` as the RFC 8414 metadata of `server`, answered as
/// `media_type`.
async fn serve_metadata(server: &MockServer, document: &Value, media_type: &str) {
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(document.to_string(), media_type))
        .mount(server)
        .await;
}

/// Mounts the token endpoint of `server`, answering `response`.
async fn serve_token(server: &MockServer, response: Value) {
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .mount(server)
        .await;
}

/// Returns the form parameter `name` of `request`.
fn param(request: &Request, name: &str) -> Option<String> {
    url::form_urlencoded::parse(&request.body)
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// Returns the claims of the JWT `token`, unverified.
fn claims(token: &str) -> Result<Value, Box<dyn StdError>> {
    use base64::Engine as _;
    let payload = token.split('.').nth(1).ok_or("a JWS")?;
    Ok(serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload)?,
    )?)
}

#[test]
fn the_ring_publishes_the_current_previous_and_next_keys_and_signs_with_one() -> TestResult {
    let current = assertion_key("current", Algorithm::Es256);
    let previous = assertion_key("previous", Algorithm::Es384);
    let next = assertion_key("next", Algorithm::Es256);
    let ring = KeyRing::new(current.clone())
        .with_previous_for(previous.clone(), Duration::from_secs(60))?
        .with_next(next.clone())?;
    let kids = |set: &Value| -> Vec<String> {
        set["keys"]
            .as_array()
            .map(|keys| {
                keys.iter()
                    .filter_map(|key| key["kid"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    // NOTE: RFC 7638 §3, each kid is the key's SHA-256 thumbprint by default.
    assert_eq!(
        vec![current.kid(), previous.kid(), next.kid()],
        kids(&ring.published())
    );
    assert_eq!(current.kid(), ring.current().kid());
    let later = Instant::now() + Duration::from_secs(120);
    assert_eq!(
        vec![current.kid(), next.kid()],
        kids(&ring.published_at(later))
    );
    assert!(ring.retiring().is_some(), "the retired key is still known");
    let kept = KeyRing::new(current.clone()).with_previous_until_removed(previous.clone())?;
    assert_eq!(2, kids(&kept.published_at(later)).len(), "until removed");
    assert!(matches!(
        KeyRing::new(current.clone()).with_previous_until_removed(current.clone()),
        Err(KeyRingError::SameKey { .. })
    ));
    assert!(matches!(
        KeyRing::new(current.clone())
            .with_previous_until_removed(previous.clone())?
            .with_next(previous),
        Err(KeyRingError::NextReused { .. })
    ));
    assert!(matches!(
        KeyRing::new(current.clone()).with_next(current),
        Err(KeyRingError::NextReused { .. })
    ));
    Ok(())
}

#[test]
fn a_fapi2_grant_that_breaks_a_build_rule_is_refused() -> TestResult {
    let issuer = "https://as.example.org";
    let refused = |grant: &ClientCredentials| match grant.validate() {
        Err(TokenError::Fapi2 { source }) => Some(source),
        _ => None,
    };
    assert!(fapi2(issuer).validate().is_ok());
    let mut grant = fapi2(issuer);
    grant.endpoint = Endpoint::Token("https://as.example.org/token".parse()?);
    assert_eq!(Some(Fapi2Error::NoIssuer), refused(&grant));
    let mut grant = ClientCredentials::new(
        Endpoint::Issuer(issuer.to_owned()),
        String::from("gateway"),
        SecretString::from("synthetic-secret"),
    )
    .with_dpop(dpop_key(Algorithm::Es256));
    grant.scope = Some(String::from("s"));
    grant.profile = SecurityProfile::Fapi2(Fapi2::new());
    assert_eq!(Some(Fapi2Error::ClientAuthentication), refused(&grant));
    let mut grant = fapi2(issuer);
    grant.assertion_keys = Some(Arc::new(KeyRing::new(assertion_key("c", Algorithm::Es384))));
    assert!(matches!(
        refused(&grant),
        Some(Fapi2Error::Algorithm {
            role: "assertion",
            algorithm: Algorithm::Es384
        })
    ));
    let mut grant = fapi2(issuer);
    grant.assertion_keys = Some(Arc::new(
        KeyRing::new(assertion_key("c", Algorithm::Es256))
            .with_previous_until_removed(assertion_key("p", Algorithm::Es384))?,
    ));
    assert!(matches!(
        refused(&grant),
        Some(Fapi2Error::Algorithm {
            role: "previous assertion",
            ..
        })
    ));
    let grant = fapi2(issuer).with_dpop(dpop_key(Algorithm::Es384));
    assert!(matches!(
        refused(&grant),
        Some(Fapi2Error::Algorithm { role: "DPoP", .. })
    ));
    let mut grant = fapi2(issuer);
    grant.token_binding = None;
    assert_eq!(Some(Fapi2Error::Unbound), refused(&grant));
    let mut grant = fapi2(issuer);
    grant.scope = None;
    assert_eq!(Some(Fapi2Error::Unrequested), refused(&grant));
    grant.authorization_details = Some(AuthorizationDetails::parse(DETAILS)?);
    assert!(grant.validate().is_ok(), "details alone are a request");
    let mut grant = fapi2(issuer);
    grant.profile =
        SecurityProfile::Fapi2(Fapi2::new().with_alias_host(AliasHost::parse("mtls.example.org")?));
    assert_eq!(Some(Fapi2Error::AliasHostsUnused), refused(&grant));
    Ok(())
}

#[tokio::test]
async fn a_fapi2_grant_discovers_its_endpoint_and_sends_the_issuer_as_aud() -> TestResult {
    let server = MockServer::start().await;
    serve_metadata(
        &server,
        &metadata(&server),
        "application/json; charset=utf-8",
    )
    .await;
    // NOTE: RFC 9396 §7, Figure 15: the details granted come back with the token.
    serve_token(
        &server,
        json!({
            "access_token": "2YotnFZFEjr1zCsicMWpAA", "token_type": "DPoP", "expires_in": 300,
            "authorization_details": [{"type": "payment_initiation", "actions": ["initiate"],
                "locations": ["https://example.com/payments"]}]
        }),
    )
    .await;
    let mut grant = fapi2(&server.uri());
    grant.authorization_details = Some(AuthorizationDetails::parse(DETAILS)?);
    let source = TokenSource::new(grant)?;
    let token = source.token().await.map_err(|error| error.to_string())?;
    let issued: &IssuedToken = token.as_ref().as_ref();
    let granted = issued.authorization_details().ok_or("details granted")?;
    assert_eq!(
        vec!["payment_initiation"],
        granted
            .types()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
    let requests = server.received_requests().await.unwrap_or_default();
    let request = requests
        .iter()
        .find(|request| request.url.path() == TOKEN_PATH)
        .ok_or("a token request")?;
    assert_eq!(
        Some(DETAILS.to_owned()),
        param(request, "authorization_details")
    );
    let assertion = param(request, "client_assertion").ok_or("an assertion")?;
    // NOTE: FAPI 2.0 §5.3.3.1, the issuer as aud, a string and never an array.
    assert_eq!(json!(server.uri()), claims(&assertion)?["aud"]);
    // NOTE: RFC 10070 §4, a client authentication JWT is explicitly typed.
    assert_eq!(
        Some(String::from("client-authentication+jwt")),
        crate::support::header(&assertion).typ
    );
    assert!(request.headers.contains_key("dpop"));
    Ok(())
}

#[tokio::test]
async fn metadata_that_does_not_admit_the_fapi2_grant_is_refused_before_a_token_request()
-> TestResult {
    type Edit = fn(&mut Value, &str);
    let cases: [(Edit, Fapi2Error); 6] = [
        (
            |document, _| {
                document["token_endpoint"] = json!("https://elsewhere.example.org/token");
            },
            Fapi2Error::Endpoint {
                member: "token_endpoint",
            },
        ),
        (
            |document, _| {
                document["token_endpoint_auth_methods_supported"] = json!(["tls_client_auth"]);
            },
            Fapi2Error::AuthenticationMethod {
                method: "private_key_jwt",
            },
        ),
        (
            |document, _| {
                document["token_endpoint_auth_signing_alg_values_supported"] = json!(["PS256"]);
            },
            Fapi2Error::SigningAlgorithm {
                algorithm: Algorithm::Es256,
            },
        ),
        (
            |document, _| {
                document["grant_types_supported"] = json!(["authorization_code"]);
            },
            Fapi2Error::GrantType {
                grant_type: "client_credentials",
            },
        ),
        (
            |document, _| {
                document["dpop_signing_alg_values_supported"] = json!(["PS256"]);
            },
            Fapi2Error::ProofAlgorithm {
                algorithm: Algorithm::Es256,
            },
        ),
        (
            |document, _| {
                if let Some(members) = document.as_object_mut() {
                    members.remove("grant_types_supported");
                }
            },
            Fapi2Error::GrantType {
                grant_type: "client_credentials",
            },
        ),
    ];
    for (edit, expected) in cases {
        let server = MockServer::start().await;
        let mut document = metadata(&server);
        edit(&mut document, &server.uri());
        serve_metadata(&server, &document, "application/json").await;
        let outcome = TokenSource::new(fapi2(&server.uri()))?.token().await;
        assert!(
            matches!(outcome.as_ref().map_err(AsRef::as_ref), Err(TokenError::Fapi2 { source }) if *source == expected),
            "{expected:?}: {outcome:?}"
        );
        let sent = server.received_requests().await.unwrap_or_default();
        assert!(sent.iter().all(|request| request.url.path() != TOKEN_PATH));
    }
    let server = MockServer::start().await;
    serve_metadata(&server, &metadata(&server), "text/plain").await;
    let outcome = TokenSource::new(fapi2(&server.uri()))?.token().await;
    assert!(matches!(
        outcome.as_ref().map_err(AsRef::as_ref),
        Err(TokenError::Fapi2 {
            source: Fapi2Error::MediaType
        })
    ));
    Ok(())
}

#[tokio::test]
async fn an_authorization_details_type_the_metadata_does_not_list_is_never_sent() -> TestResult {
    let server = MockServer::start().await;
    let mut document = metadata(&server);
    document["authorization_details_types_supported"] = json!(["account_information"]);
    serve_metadata(&server, &document, "application/json").await;
    let mut grant = fapi2(&server.uri());
    grant.authorization_details = Some(AuthorizationDetails::parse(DETAILS)?);
    let outcome = TokenSource::new(grant)?.token().await;
    assert!(matches!(
        outcome.as_ref().map_err(AsRef::as_ref),
        Err(TokenError::AuthorizationDetailsType { kind }) if kind == "payment_initiation"
    ));
    Ok(())
}

#[tokio::test]
async fn a_token_response_that_states_no_granted_details_is_refused() -> TestResult {
    for (response, why) in [
        (
            json!({"access_token": "t", "token_type": "Bearer"}),
            "none granted",
        ),
        (
            json!({"access_token": "t", "token_type": "Bearer", "authorization_details": [{"actions": ["x"]}]}),
            "granted without a type",
        ),
    ] {
        let server = MockServer::start().await;
        serve_token(&server, response).await;
        let mut grant = ClientCredentials::new(
            Endpoint::Token(format!("{}{TOKEN_PATH}", server.uri()).parse()?),
            String::from("gateway"),
            SecretString::from("synthetic-secret"),
        );
        grant.authorization_details = Some(AuthorizationDetails::parse(DETAILS)?);
        let outcome = TokenSource::new(grant)?.token().await;
        assert!(
            matches!(
                outcome.as_ref().map_err(AsRef::as_ref),
                Err(TokenError::AuthorizationDetails | TokenError::GrantedDetails { .. })
            ),
            "{why}: {outcome:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_mutual_tls_alias_on_an_unnamed_host_is_refused() -> TestResult {
    let server = MockServer::start().await;
    let identity = {
        let key = rcgen::KeyPair::generate()?;
        let certificate = rcgen::CertificateParams::new(vec![String::from("gateway.example.org")])?
            .self_signed(&key)?;
        format!("{}{}", certificate.pem(), key.serialize_pem())
    };
    let grant = |hosts: &[&str]| -> Result<ClientCredentials, Box<dyn StdError>> {
        let mut grant = ClientCredentials::with_presented_tls(
            Endpoint::Issuer(server.uri()),
            String::from("gateway"),
            crate::tls::presented_identity("", &identity).map_err(|error| error.to_string())?,
            false,
        )
        .with_certificate_binding();
        grant.scope = Some(String::from("s"));
        let mut profile = Fapi2::new();
        for host in hosts {
            profile = profile.with_alias_host(AliasHost::parse(host)?);
        }
        grant.profile = SecurityProfile::Fapi2(profile);
        grant.timeout = Duration::from_secs(5);
        Ok(grant)
    };
    let mut document = metadata(&server);
    document["mtls_endpoint_aliases"] = json!({"token_endpoint": "https://mtls.example.org/token"});
    serve_metadata(&server, &document, "application/json").await;
    let outcome = TokenSource::new(grant(&[])?)?.token().await;
    assert!(matches!(
        outcome.as_ref().map_err(AsRef::as_ref),
        Err(TokenError::Fapi2 {
            source: Fapi2Error::Endpoint {
                member: "mtls_endpoint_aliases.token_endpoint"
            }
        })
    ));
    Ok(())
}

#[test]
fn the_oauth_table_names_a_fapi2_grant_its_key_ring_and_its_details() -> TestResult {
    let current = temp_file("current.pem", &ec_key("c", Algorithm::Es256).pem);
    let previous = temp_file("previous.pem", &ec_key("p", Algorithm::Es256).pem);
    let next = temp_file("next.pem", &ec_key("n", Algorithm::Es256).pem);
    let dpop = temp_file("dpop.pem", &ec_key("d", Algorithm::Es256).pem);
    let table = format!(
        r#"issuer = "https://as.example.org"
client_id = "gateway"
client_auth = "private_key_jwt"
private_key_file = {current:?}
assertion_alg = "ES256"
previous_private_key_file = {previous:?}
next_private_key_file = {next:?}
dpop_key_file = {dpop:?}
security_profile = "fapi2"
authorization_details = '{DETAILS}'
"#,
        current = current.display().to_string(),
        previous = previous.display().to_string(),
        next = next.display().to_string(),
        dpop = dpop.display().to_string(),
    );
    let section: OauthSection = toml::from_str(&table)?;
    let grant = section.resolve()?;
    assert!(matches!(grant.profile, SecurityProfile::Fapi2(_)));
    let ring = grant.assertion_keys.as_deref().ok_or("a ring")?;
    assert!(ring.retiring().is_some() && ring.next().is_some());
    assert_eq!(3, ring.published()["keys"].as_array().map_or(0, Vec::len));
    assert!(grant.authorization_details.is_some());
    let unbound: OauthSection = toml::from_str(&table.replace(
        &format!("dpop_key_file = {:?}\n", dpop.display().to_string()),
        "",
    ))?;
    assert!(matches!(
        unbound.resolve(),
        Err(ConfigError::Grant { source }) if matches!(*source, TokenError::Fapi2 { source: Fapi2Error::Unbound })
    ));
    let aliased: OauthSection = toml::from_str(
        "token_endpoint = \"https://as.example.org/token\"\nclient_id = \"g\"\nclient_secret = \"s\"\nmtls_alias_hosts = [\"mtls.example.org\"]\n",
    )?;
    assert!(aliased.resolve().is_err());
    assert!(
        aliased
            .problems("t")
            .iter()
            .any(|problem| problem.contains("mtls_alias_hosts"))
    );
    Ok(())
}

/// FAPI 2.0 Security Profile §5.4.1: the actor key of a mutual-TLS client
/// is held to the profile's algorithms as a client assertion key is, and a
/// conforming one loads beside the client certificate.
#[test]
fn a_mutual_tls_fapi2_grant_holds_its_actor_key_to_the_profile_s_algorithms() -> TestResult {
    let pair = rcgen::KeyPair::generate()?;
    let certificate = rcgen::CertificateParams::new(vec![String::from("gateway.example.org")])?
        .self_signed(&pair)?;
    let identity_file = temp_file(
        "fapi2-client.pem",
        format!("{}{}", certificate.pem(), pair.serialize_pem()).as_bytes(),
    );
    let table = |alg: Algorithm, name: &str| -> Result<OauthSection, toml::de::Error> {
        let actor = temp_file("fapi2-actor.pem", &ec_key("a", alg).pem);
        toml::from_str(&format!(
            "issuer = \"https://as.example.org\"\nclient_id = \"gateway\"\nclient_auth = \"tls_client_auth\"\n\
             tls.client_identity_file = {:?}\ncertificate_bound = true\n\
             private_key_file = {:?}\nassertion_alg = \"{name}\"\nsecurity_profile = \"fapi2\"\nscope = \"system/*.rs\"\n",
            identity_file.display().to_string(),
            actor.display().to_string(),
        ))
    };
    let grant = table(Algorithm::Es256, "ES256")?.resolve_with_tls(&crate::tls::PemTls)?;
    assert!(grant.assertion_keys.is_some(), "the actor key is read");
    assert!(matches!(
        table(Algorithm::Es384, "ES384")?.resolve_with_tls(&crate::tls::PemTls),
        Err(ConfigError::Grant { source }) if matches!(
            *source,
            TokenError::Fapi2 { source: Fapi2Error::Algorithm { role: "assertion", .. } }
        )
    ));
    Ok(())
}
