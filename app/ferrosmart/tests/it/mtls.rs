// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! Mutual-TLS client authentication (RFC 8705 §2): a `tls_client_auth`
//! client by the subject of the connection's certificate, a
//! `self_signed_tls_client_auth` client by the certificate its JWK Set
//! registers.

use std::sync::Arc;

use axum::body::Body;
use base64::Engine as _;
use ferrohealth_server::tls::PeerCertificates;
use ferrosmart::store::grant::Access;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt as _;
use rustls::pki_types::CertificateDer;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use crate::introspection::{Answer, Server};
use crate::support::from_client;

/// A self-signed certificate with the subject `O=Example, CN=<common>` and
/// the `dNSName` `dns`, in DER form, and the JWK of its key carrying it in
/// `x5c` (RFC 7517 §4.7).
fn certificate(common: &str, dns: &str) -> (Vec<u8>, Value) {
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("a key");
    let mut params = rcgen::CertificateParams::new(vec![dns.to_owned()]).expect("params");
    let mut name = rcgen::DistinguishedName::new();
    name.push(rcgen::DnType::OrganizationName, "Example");
    name.push(rcgen::DnType::CommonName, common);
    params.distinguished_name = name;
    let der = params
        .self_signed(&pair)
        .expect("a certificate")
        .der()
        .to_vec();
    let point = pair.public_key_raw();
    let url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let jwk = json!({
        "kty": "EC", "crv": "P-256", "kid": "mtls",
        "x": url.encode(point.get(1..33).expect("an uncompressed point")),
        "y": url.encode(point.get(33..65).expect("an uncompressed point")),
        "x5c": [base64::engine::general_purpose::STANDARD.encode(&der)],
    });
    (der, jwk)
}

/// The client tables of the case: a PKI client matched by its `dNSName`,
/// one by its subject DN, and a self-signed one that registers `registered`.
fn clients(registered: &Value) -> String {
    let set = crate::support::inline(&json!({ "keys": [registered] }));
    format!(
        "[[client]]\nclient_id = \"pki\"\ntoken_endpoint_auth_method = \"tls_client_auth\"\n\
         tls_client_auth_san_dns = \"mtls.example.org\"\n\
         redirect_uris = [\"https://pki.example.org/callback\"]\n\
         grant_types = [\"authorization_code\", \"refresh_token\"]\n\
         [[client]]\nclient_id = \"named\"\ntoken_endpoint_auth_method = \"tls_client_auth\"\n\
         tls_client_auth_subject_dn = \"cn=mtls client, O=Example\"\n\
         redirect_uris = [\"https://named.example.org/callback\"]\n\
         grant_types = [\"authorization_code\", \"refresh_token\"]\n\
         [[client]]\nclient_id = \"self\"\ntoken_endpoint_auth_method = \"self_signed_tls_client_auth\"\n\
         jwks = {set}\n\
         redirect_uris = [\"https://self.example.org/callback\"]\n\
         grant_types = [\"authorization_code\", \"refresh_token\"]\n"
    )
}

/// Posts `form` to `path` over a connection that presented `certificate`.
async fn post(
    server: &Server,
    path: &str,
    form: &[(&str, &str)],
    certificate: Option<&[u8]>,
) -> Answer {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form)
        .finish();
    let mut request = Request::post(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .expect("a request");
    if let Some(der) = certificate {
        let chain: Arc<[CertificateDer<'static>]> =
            Arc::from(vec![CertificateDer::from(der.to_vec())]);
        request.extensions_mut().insert(PeerCertificates(chain));
    }
    let response = server
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
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Refreshes a fresh grant of `client` over a connection that presented
/// `certificate`.
async fn refresh(server: &Server, client: &str, certificate: Option<&[u8]>) -> Answer {
    let grant = server
        .grant(
            client,
            Some(Access::Offline),
            None,
            &json!({"patient": "123"}),
        )
        .await;
    let token = server.refresh(&grant, 3600).await;
    post(
        server,
        "/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &token),
            ("client_id", client),
        ],
        certificate,
    )
    .await
}

// NOTE: RFC 8705 §2.1 and §2.1.2, a PKI client authenticates by the one subject
// it registers, a dNSName or an RFC 4514 subject DN; §2, any other is invalid_client.
#[tokio::test]
async fn a_pki_client_authenticates_by_its_certificate_s_subject() {
    let (own, jwk) = certificate("mtls client", "mtls.example.org");
    let (other, _) = certificate("someone else", "other.example.org");
    let server = Server::start_with(&clients(&jwk)).await;
    for client in ["pki", "named"] {
        let (status, _, body) = refresh(&server, client, Some(&own)).await;
        assert_eq!(StatusCode::OK, status, "{client}: {body}");
        for presented in [None, Some(other.as_slice())] {
            let (status, _, body) = refresh(&server, client, presented).await;
            assert_eq!(StatusCode::BAD_REQUEST, status, "{client}: {body}");
            assert_eq!(json!("invalid_client"), body["error"], "{client}");
        }
    }
    server.stop().await;
}

// NOTE: RFC 8705 §2.2, a self-signed client authenticates by a certificate its JWK
// Set registers in x5c, and by no other.
#[tokio::test]
async fn a_self_signed_client_authenticates_by_the_certificate_it_registers() {
    let (own, jwk) = certificate("mtls client", "mtls.example.org");
    let (other, _) = certificate("mtls client", "mtls.example.org");
    let server = Server::start_with(&clients(&jwk)).await;
    let (status, _, body) = refresh(&server, "self", Some(&own)).await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let (status, _, body) = refresh(&server, "self", Some(&other)).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{body}");
    assert_eq!(json!("invalid_client"), body["error"]);
    server.stop().await;
}

// NOTE: RFC 7009 §2.1, the revocation endpoint authenticates the client as the
// token endpoint does, its certificate included (RFC 8705 §2).
#[tokio::test]
async fn a_mutual_tls_client_revokes_over_its_certificate() {
    let (own, jwk) = certificate("mtls client", "mtls.example.org");
    let server = Server::start_with(&clients(&jwk)).await;
    let grant = server
        .grant(
            "pki",
            Some(Access::Offline),
            None,
            &json!({"patient": "123"}),
        )
        .await;
    let token = server.refresh(&grant, 3600).await;
    let form = [("token", token.as_str()), ("client_id", "pki")];
    let (status, _, body) = post(&server, "/revoke", &form, None).await;
    assert_eq!(StatusCode::BAD_REQUEST, status, "{body}");
    let (status, _, _) = post(&server, "/revoke", &form, Some(&own)).await;
    assert_eq!(StatusCode::OK, status);
    server.stop().await;
}

// NOTE: RFC 8705 §2.1.2, a tls_client_auth client names exactly one subject, and
// no other method names one.
#[test]
fn a_registration_naming_no_subject_or_two_is_refused() {
    use ferrosmart::clients::{
        AuthMethod, ClientMetadata, GrantType, Material, TlsSubjectFields, resolve,
    };
    let section = |method, fields| ClientMetadata {
        client_id: String::from("pki"),
        auth_method: method,
        redirect_uris: vec![String::from("https://pki.example.org/callback")],
        grant_types: vec![GrantType::AuthorizationCode],
        tls_client_auth: fields,
        ..ClientMetadata::default()
    };
    let material = || Material {
        jwks: None,
        secret_hash: None,
    };
    let one = TlsSubjectFields {
        san_dns: String::from("mtls.example.org"),
        ..TlsSubjectFields::default()
    };
    let two = TlsSubjectFields {
        san_uri: String::from("https://mtls.example.org"),
        ..one.clone()
    };
    let bad_ip = TlsSubjectFields {
        san_ip: String::from("not an address"),
        ..TlsSubjectFields::default()
    };
    assert!(resolve(&section(AuthMethod::TlsClientAuth, one.clone()), material()).is_ok());
    for fields in [TlsSubjectFields::default(), two, bad_ip] {
        assert!(resolve(&section(AuthMethod::TlsClientAuth, fields), material()).is_err());
    }
    assert!(resolve(&section(AuthMethod::ClientSecretBasic, one), material()).is_err());
}

// NOTE: RFC 8705 §2.1.1 and §2.2.1, the metadata lists the two methods once the
// listener asks the client for its certificate (§3.3).
#[tokio::test]
async fn the_metadata_lists_mutual_tls_once_the_listener_asks_for_a_certificate() {
    let server = Server::start().await;
    let mut settings = server.settings().clone();
    let methods = |settings: &ferrosmart::config::settings::Settings| {
        let document = ferrosmart::discovery::metadata_document(&ferrosmart::discovery::metadata(
            settings, true,
        ));
        [
            "token_endpoint_auth_methods_supported",
            "introspection_endpoint_auth_methods_supported",
            "revocation_endpoint_auth_methods_supported",
        ]
        .map(|member| document[member].clone())
    };
    for listed in methods(&settings) {
        assert!(
            !listed
                .as_array()
                .expect("a list")
                .contains(&json!("tls_client_auth")),
            "{listed}"
        );
    }
    settings.server.tls = Some(
        toml::from_str("certificate_file = \"tls.crt\"\nkey_file = \"tls.key\"\nclient_auth = \"optional\"\nclient_ca_file = \"ca.crt\"\n")
            .expect("a TLS section"),
    );
    for listed in methods(&settings) {
        let listed = listed.as_array().expect("a list").clone();
        assert!(listed.contains(&json!("tls_client_auth")), "{listed:?}");
        assert!(
            listed.contains(&json!("self_signed_tls_client_auth")),
            "{listed:?}"
        );
    }
    server.stop().await;
}
