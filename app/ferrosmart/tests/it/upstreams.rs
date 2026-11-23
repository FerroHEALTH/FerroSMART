// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! `GET /admin/upstreams` (#830): each provider's documents, read or
//! failed, its certificates' expiry and the clients that name it, against
//! a `wiremock` OpenID Provider and a SAML provider read from a file.

use std::time::Duration;

use http::{Method, StatusCode};
use serde_json::{Value, json};
use wiremock::{Mock, ResponseTemplate, matchers};

use crate::authorize::Provider;
use crate::introspection::{ISSUER, Server};
use crate::saml::kit;
use crate::support::ASSURANCE;

/// Returns the TOML string of `path`.
fn toml_path(path: &std::path::Path) -> String {
    format!("{:?}", path.display().to_string())
}

/// Writes `text` to `dir/name` and returns its TOML string.
fn written(dir: &std::path::Path, name: &str, text: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, text).expect("written");
    toml_path(&path)
}

/// Returns the configuration of an OpenID Provider `idp` at `issuer` and a
/// SAML provider `national` whose metadata is the file `metadata`, read
/// again every second, with FerroSMART's service provider in `dir`, and a
/// client `clinic` that names `national`.
fn providers(dir: &std::path::Path, issuer: &str, metadata: &str) -> String {
    let sp = kit::p256_pem();
    let decryption = kit::rsa_pem();
    format!(
        "[[ferrosmart.upstream]]\nname = \"idp\"\n[ferrosmart.upstream.oidc]\nissuer = {issuer:?}\n\
         client_id = \"ferrosmart\"\n[ferrosmart.upstream.oidc.client_secret_basic]\nsecret = \"synthetic\"\n\
         {ASSURANCE}\
         [ferrosmart.saml]\nentity_id = {sp_entity:?}\nsigning_key_file = {sp_key}\n\
         signing_certificate_file = {sp_certificate}\n\
         [[ferrosmart.saml.decryption]]\nkey_file = {decryption_key}\ncertificate_file = {decryption_certificate}\n\
         [[ferrosmart.upstream]]\nname = \"national\"\nlabel = \"National login\"\n\
         [ferrosmart.upstream.saml]\nentity_id = {idp_entity:?}\nmetadata_file = {metadata}\n\
         metadata_refresh = \"1s\"\nauthn_contexts = [{strong:?}]\n\
         [ferrosmart.upstream.assurance]\nlevels = {{ {strong:?} = \"substantial\" }}\n\
         [[client]]\nclient_id = \"clinic\"\ntoken_endpoint_auth_method = \"none\"\n\
         redirect_uris = [\"https://clinic.example.org/callback\"]\ngrant_types = [\"authorization_code\"]\n\
         upstreams = [\"national\"]\nscope = [\"openid\"]\n",
        sp_entity = kit::SP,
        sp_key = written(dir, "sp-key.pem", &sp.key),
        sp_certificate = written(dir, "sp-certificate.pem", &sp.certificate),
        decryption_key = written(dir, "decryption-key.pem", &decryption.key),
        decryption_certificate =
            written(dir, "decryption-certificate.pem", &decryption.certificate),
        idp_entity = kit::IDP,
        strong = kit::STRONG,
    )
}

/// Returns the entry of the provider `name` in `body`.
fn entry<'a>(body: &'a Value, name: &str) -> &'a Value {
    body["upstreams"]
        .as_array()
        .and_then(|entries| entries.iter().find(|entry| entry["name"] == name))
        .expect("the provider's entry")
}

/// Returns the document `kind` of `entry`.
fn document<'a>(entry: &'a Value, kind: &str) -> &'a Value {
    entry["documents"]
        .as_array()
        .and_then(|documents| {
            documents
                .iter()
                .find(|document| document["document"] == kind)
        })
        .expect("the document")
}

#[tokio::test]
async fn each_provider_is_reported_with_its_documents_and_a_failed_read_as_failed() {
    let provider = Provider::start().await;
    let dir = tempfile::tempdir().expect("a directory");
    let idp = kit::rsa_pem();
    let metadata_path = dir.path().join("idp-metadata.xml");
    std::fs::write(&metadata_path, kit::metadata(&[&idp.der], "")).expect("written");
    let extra = providers(
        dir.path(),
        &provider.server.uri(),
        &toml_path(&metadata_path),
    );
    let server = Server::start_with(&extra).await;
    let admin = server.token("admin", "system/admin", ISSUER).await;

    let (status, _, _) = server
        .call(Method::GET, "/admin/upstreams", None, None)
        .await;
    assert_eq!(StatusCode::UNAUTHORIZED, status);

    let (status, _, body) = server
        .call(Method::GET, "/admin/upstreams", None, Some(&admin))
        .await;
    assert_eq!(StatusCode::OK, status, "{body}");
    let names: Vec<&Value> = body["upstreams"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|entry| &entry["name"])
        .collect();
    assert_eq!(
        vec![&json!("idp"), &json!("national")],
        names,
        "configuration order"
    );
    let oidc = entry(&body, "idp");
    assert_eq!(json!("oidc"), oidc["protocol"]);
    assert_eq!(json!(provider.server.uri()), oidc["issuer"]);
    assert_eq!(json!([]), oidc["clients"]);
    assert_eq!(json!(true), document(oidc, "openid_configuration")["ok"]);
    assert_eq!(json!(true), document(oidc, "jwks")["ok"]);
    let saml = entry(&body, "national");
    assert_eq!(json!("saml"), saml["protocol"]);
    assert_eq!(json!(kit::IDP), saml["issuer"]);
    assert_eq!(json!(["clinic"]), saml["clients"]);
    let metadata = document(saml, "saml_metadata");
    assert_eq!(json!(true), metadata["ok"]);
    assert_eq!(metadata["read_at"], metadata["last_good_read_at"]);
    assert_eq!(
        1,
        metadata["certificates_expire_at"]
            .as_array()
            .map_or(0, Vec::len),
        "the signing certificate's notAfter: {metadata}"
    );
    assert!(
        !body.to_string().contains("synthetic"),
        "no configured secret is answered"
    );

    Mock::given(matchers::method("GET"))
        .and(matchers::path("/jwks"))
        .respond_with(ResponseTemplate::new(500))
        .with_priority(1)
        .mount(&provider.server)
        .await;
    std::fs::write(&metadata_path, "<md:EntityDescriptor/>").expect("written");
    let mut failed = Value::Null;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let (_, _, body) = server
            .call(Method::GET, "/admin/upstreams", None, Some(&admin))
            .await;
        if document(entry(&body, "national"), "saml_metadata")["ok"] == json!(false) {
            failed = body;
            break;
        }
    }
    assert!(
        failed.is_object(),
        "the metadata was read again within ten seconds"
    );
    let key_set = document(entry(&failed, "idp"), "jwks");
    assert_eq!(json!(false), key_set["ok"]);
    assert!(
        key_set["error"]
            .as_str()
            .is_some_and(|error| error.contains("500")),
        "{key_set}"
    );
    let metadata = document(entry(&failed, "national"), "saml_metadata");
    assert!(metadata["error"].is_string(), "{metadata}");
    assert!(
        metadata["last_good_read_at"].as_str() < metadata["read_at"].as_str(),
        "the copy in use is the last good one: {metadata}"
    );
    assert_eq!(
        1,
        metadata["certificates_expire_at"]
            .as_array()
            .map_or(0, Vec::len),
        "the copy in use still names its certificate"
    );
    server.stop().await;
}
