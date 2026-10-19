// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The SMART discovery document, `.well-known/smart-configuration`, built
//! from the authorization server's metadata.
//!
//! "FHIR endpoints requiring authorization SHALL serve a JSON document at
//! the location formed by appending `/.well-known/smart-configuration` to
//! their base URL" (SMART App Launch 2.2.0, Conformance, §Using Well-Known).
//! The product mounts the route and serves the value this module builds,
//! which "SHALL be JSON, regardless of `Accept` headers". The document is
//! the product's own assertion about itself, so a value the specification
//! does not define for a member is dropped rather than copied from the
//! issuer.

use std::collections::BTreeMap;

use serde_json::Map;
use serde_json::Value;

use crate::metadata::ServerMetadata;

/// The path of the SMART discovery document under a FHIR base.
pub const SMART_CONFIGURATION: &str = "/.well-known/smart-configuration";

/// The capabilities this resource server enforces whatever the deployment
/// adds: v1 scope syntax, and `patient/` and `user/` scopes (SMART App
/// Launch 2.2.0, Conformance, §Capability Sets).
const ENFORCED: [&str; 3] = ["permission-v1", "permission-patient", "permission-user"];

/// The grant types the document may name (SMART App Launch 2.2.0,
/// Conformance, §Metadata).
const GRANT_TYPES: [&str; 2] = ["authorization_code", "client_credentials"];

/// The client authentication methods the document may name.
const AUTH_METHODS: [&str; 3] = [
    "client_secret_post",
    "client_secret_basic",
    "private_key_jwt",
];

/// The capabilities a SMART on openEHR platform advertises.
///
/// `master04 §Capabilities`: the EHR launch context conveyed by the `ehrId`
/// claim, the openEHR resource scopes, and the base64 JSON launch parameter.
pub const OPENEHR_CAPABILITIES: [&str; 3] = [
    "context-openehr-ehr",
    "openehr-permission-v1",
    "launch-base64-json",
];

/// The key of the openEHR REST API in the `services` map, required of a
/// SMART on openEHR platform (`master04 §Services`).
pub const OPENEHR_REST_SERVICE: &str = "org.openehr.rest";

/// The key of the FHIR API in the `services` map, recommended
/// (`master04 §Services`).
pub const FHIR_REST_SERVICE: &str = "org.fhir.rest";

/// What the product adds to the discovery document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SmartOptions {
    /// The scopes the product serves, which "the server SHALL support";
    /// omitted when empty.
    pub scopes_supported: Vec<String>,
    /// The capabilities the product adds to the enforced ones (`launch-ehr`,
    /// `context-ehr-patient`, `sso-openid-connect`).
    pub capabilities: Vec<String>,
    /// Whether the product supplies an evaluator for granular scopes, which
    /// is what `permission-v2` promises.
    pub granular: bool,
    /// The `services` map of a SMART on openEHR platform, each key a
    /// reverse domain name and each value the service's metadata with its
    /// `baseUrl` (`master04 §Services`); omitted when empty.
    pub services: BTreeMap<String, Value>,
}

impl SmartOptions {
    /// Returns these options as a SMART on openEHR platform's, with the
    /// openEHR REST API at `openehr_base_url`, the FHIR API at
    /// `fhir_base_url` when the product serves one, and the openEHR
    /// capabilities added.
    #[must_use]
    pub fn with_openehr(mut self, openehr_base_url: &str, fhir_base_url: Option<&str>) -> Self {
        self.services.insert(
            String::from(OPENEHR_REST_SERVICE),
            serde_json::json!({ "baseUrl": openehr_base_url }),
        );
        if let Some(fhir) = fhir_base_url {
            self.services.insert(
                String::from(FHIR_REST_SERVICE),
                serde_json::json!({ "baseUrl": fhir }),
            );
        }
        for capability in OPENEHR_CAPABILITIES {
            if !self.capabilities.iter().any(|added| added == capability) {
                self.capabilities.push(String::from(capability));
            }
        }
        self
    }
}

/// Returns the discovery document of `metadata` under `options`.
///
/// `grant_types_supported` and `token_endpoint_auth_methods_supported` keep
/// only the options the page defines, each when the issuer advertises it;
/// `code_challenge_methods_supported` carries `S256` and never `plain`:
/// "The `S256` method SHALL be included in this list, and the `plain`
/// method SHALL NOT be included" (SMART App Launch 2.2.0, Conformance,
/// §Metadata). The client types and the standalone launch are derived from
/// what the issuer supports.
pub(super) fn document(metadata: &ServerMetadata, options: &SmartOptions) -> Value {
    let mut document = Map::new();
    let mut put = |name: &str, value: Option<Value>| {
        if let Some(value) = value {
            document.insert(String::from(name), value);
        }
    };
    let text = |value: &Option<String>| value.clone().map(Value::String);
    let list = |items: &[String]| Value::from(items.iter().map(String::as_str).collect::<Vec<_>>());
    let keep = |advertised: &[String], allowed: &[&str]| -> Vec<String> {
        allowed
            .iter()
            .filter(|option| advertised.iter().any(|value| value == *option))
            .map(|option| (*option).to_owned())
            .collect()
    };
    let grant_types = keep(&metadata.grant_types(), &GRANT_TYPES);
    let auth_methods = keep(&metadata.token_endpoint_auth_methods(), &AUTH_METHODS);
    put("issuer", Some(Value::String(metadata.issuer.clone())));
    put("jwks_uri", text(&metadata.jwks_uri));
    put(
        "authorization_endpoint",
        text(&metadata.authorization_endpoint),
    );
    put("token_endpoint", text(&metadata.token_endpoint));
    put(
        "token_endpoint_auth_methods_supported",
        Some(list(&auth_methods)),
    );
    put("grant_types_supported", Some(list(&grant_types)));
    put(
        "registration_endpoint",
        text(&metadata.registration_endpoint),
    );
    if !options.scopes_supported.is_empty() {
        put("scopes_supported", Some(list(&options.scopes_supported)));
    }
    if !options.services.is_empty() {
        put(
            "services",
            Some(Value::Object(
                options
                    .services
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            )),
        );
    }
    put(
        "response_types_supported",
        metadata.response_types_supported.as_deref().map(list),
    );
    put(
        "introspection_endpoint",
        text(&metadata.introspection_endpoint),
    );
    put("revocation_endpoint", text(&metadata.revocation_endpoint));
    let mut challenge: Vec<&str> = vec!["S256"];
    for method in metadata.code_challenge_methods_supported.iter().flatten() {
        if method != "plain" && !challenge.contains(&method.as_str()) {
            challenge.push(method);
        }
    }
    put(
        "code_challenge_methods_supported",
        Some(Value::from(challenge)),
    );
    put(
        "capabilities",
        Some(Value::from(capabilities(
            metadata,
            options,
            &grant_types,
            &auth_methods,
        ))),
    );
    Value::Object(document)
}

/// Returns the capabilities of the document: the enforced ones, the client
/// types and the standalone launch the issuer supports, and the product's.
fn capabilities<'a>(
    metadata: &'a ServerMetadata,
    options: &'a SmartOptions,
    grant_types: &[String],
    auth_methods: &[String],
) -> Vec<&'a str> {
    let mut capabilities: Vec<&str> = ENFORCED.to_vec();
    if options.granular {
        capabilities.push("permission-v2");
    }
    let symmetric = auth_methods
        .iter()
        .any(|method| method == "client_secret_basic" || method == "client_secret_post");
    if symmetric {
        capabilities.push("client-confidential-symmetric");
    }
    if auth_methods
        .iter()
        .any(|method| method == "private_key_jwt")
    {
        capabilities.push("client-confidential-asymmetric");
    }
    if metadata
        .token_endpoint_auth_methods()
        .iter()
        .any(|method| method == "none")
    {
        capabilities.push("client-public");
    }
    if grant_types
        .iter()
        .any(|grant| grant == "authorization_code")
    {
        capabilities.push("launch-standalone");
    }
    for added in &options.capabilities {
        if !capabilities.contains(&added.as_str()) {
            capabilities.push(added);
        }
    }
    capabilities
}

#[cfg(test)]
mod tests {
    use super::{SmartOptions, document};
    use crate::metadata::ServerMetadata;

    #[test]
    fn the_document_keeps_only_the_defined_options_and_adds_the_products() {
        let metadata = ServerMetadata {
            issuer: String::from("https://as.example.org"),
            token_endpoint: Some(String::from("https://as.example.org/token")),
            grant_types_supported: Some(vec![
                String::from("authorization_code"),
                String::from("client_credentials"),
                String::from("urn:ietf:params:oauth:grant-type:token-exchange"),
            ]),
            token_endpoint_auth_methods_supported: Some(vec![
                String::from("private_key_jwt"),
                String::from("tls_client_auth"),
            ]),
            code_challenge_methods_supported: Some(vec![String::from("plain")]),
            scopes_supported: Some(vec![String::from("issuer-scope")]),
            ..ServerMetadata::default()
        };
        let options = SmartOptions {
            scopes_supported: vec![String::from("system/Condition.rs")],
            capabilities: vec![String::from("launch-ehr"), String::from("permission-v1")],
            granular: true,
            ..SmartOptions::default()
        };
        let document = document(&metadata, &options);
        assert_eq!(
            serde_json::json!(["S256"]),
            document["code_challenge_methods_supported"]
        );
        assert_eq!(
            serde_json::json!(["authorization_code", "client_credentials"]),
            document["grant_types_supported"]
        );
        assert_eq!(
            serde_json::json!(["private_key_jwt"]),
            document["token_endpoint_auth_methods_supported"]
        );
        assert_eq!(
            serde_json::json!(["system/Condition.rs"]),
            document["scopes_supported"]
        );
        assert_eq!(
            serde_json::json!([
                "permission-v1",
                "permission-patient",
                "permission-user",
                "permission-v2",
                "client-confidential-asymmetric",
                "launch-standalone",
                "launch-ehr"
            ]),
            document["capabilities"]
        );
        assert!(document.get("jwks_uri").is_none());
    }

    #[test]
    fn the_defaults_of_rfc_8414_stand_in_for_omitted_members() {
        let metadata = ServerMetadata {
            issuer: String::from("https://as.example.org"),
            ..ServerMetadata::default()
        };
        let document = document(&metadata, &SmartOptions::default());
        assert_eq!(
            serde_json::json!(["authorization_code"]),
            document["grant_types_supported"]
        );
        assert_eq!(
            serde_json::json!(["client_secret_basic"]),
            document["token_endpoint_auth_methods_supported"]
        );
        assert_eq!(
            serde_json::json!([
                "permission-v1",
                "permission-patient",
                "permission-user",
                "client-confidential-symmetric",
                "launch-standalone"
            ]),
            document["capabilities"]
        );
        assert!(document.get("scopes_supported").is_none());
    }
}
