// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The JSON documents of `/admin/clients`.
//!
//! The document is RFC 7591 §2 client metadata, so the admin API, `ferrosmart
//! client apply` and an app's own registration read one shape. `resources`,
//! `launch_uri`, `upstreams` and `first_party` are FerroSMART's
//! own. The server issues a symmetric client's `client_secret` and keeps
//! only its hash (RFC 7591 §3.2.1); no document or answer carries the hash.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::clients::{
    AuthMethod, Client, ClientKeys, ClientKind, ClientMetadata, GrantType, Material,
};
use crate::store::admin::Registered;

/// A client as an administrator sends it: a JSON object alone, never the
/// positional array serde would also read a struct from.
///
/// `POST /admin/clients` and `PUT /admin/clients/{client_id}` take it, and
/// `ferrosmart client apply` reads it from a file.
#[derive(Debug, Clone, Default)]
pub struct ClientDocument(Fields);

impl<'de> Deserialize<'de> for ClientDocument {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(ObjectOnly).map(Self)
    }
}

/// The visitor that reads a [`ClientDocument`] from an object and refuses
/// every other JSON value.
struct ObjectOnly;

impl<'de> serde::de::Visitor<'de> for ObjectOnly {
    type Value = Fields;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a client document object")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<Fields, A::Error> {
        Fields::deserialize(serde::de::value::MapAccessDeserializer::new(map))
    }
}

impl ClientDocument {
    /// Returns the `client_id` the document names; empty when it names none.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.0.client_id
    }

    /// Returns the document a registration request's object `body` holds,
    /// its members the document does not read ignored (RFC 7591 §2), and
    /// the `client_secret` it carries, if any (RFC 7592 §2.2).
    ///
    /// # Errors
    /// Returns the [`serde_json::Error`] of a body that is no object or a
    /// member of the wrong type.
    pub fn from_registration(
        body: Value,
    ) -> Result<(Self, Option<secrecy::SecretString>), serde_json::Error> {
        let Value::Object(mut members) = body else {
            return Err(serde::de::Error::custom("a client metadata object"));
        };
        members.retain(|name, _| MEMBERS.contains(&name.as_str()));
        let secret = members
            .remove("client_secret")
            .map(|secret| match secret {
                Value::String(secret) => Ok(secrecy::SecretString::from(secret)),
                _ => Err(serde::de::Error::custom("client_secret is a string")),
            })
            .transpose()?;
        let fields: Fields = serde_json::from_value(Value::Object(members))?;
        Ok((Self(fields), secret))
    }

    /// Returns the first member an app may not set for itself: the ones
    /// FerroSMART keeps for an administrator (`docs/architecture.md` §13.27).
    #[must_use]
    pub fn administrators_only(&self) -> Option<&'static str> {
        let fields = &self.0;
        [
            ("resources", !fields.resources.is_empty()),
            ("launch_uri", !fields.launch_uri.is_empty()),
            ("upstreams", !fields.upstreams.is_empty()),
            ("first_party", fields.first_party),
        ]
        .into_iter()
        .find_map(|(member, set)| set.then_some(member))
    }

    /// Returns the scope the document asks for, space-separated.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.0.scope
    }

    /// Returns the document with `client_id` set, which the registration
    /// endpoint assigns when an administrator names none.
    #[must_use]
    pub fn named(mut self, client_id: String) -> Self {
        self.0.client_id = client_id;
        self
    }

    /// Returns the document with `client_id`, `scope` and `resources` set,
    /// as the registration of an app that registers itself assigns them.
    #[must_use]
    pub fn assigned(mut self, client_id: String, scope: String, resources: Vec<String>) -> Self {
        self.0.client_id = client_id;
        self.0.scope = scope;
        self.0.resources = resources;
        self
    }
}

/// The members of a [`ClientDocument`].
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is an RFC 7591 client metadata boolean of its own"
)]
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Fields {
    /// The `client_id`; on an update absent or the path's.
    pub client_id: String,
    /// The name shown to the person who approves the client.
    pub client_name: String,
    /// How the client authenticates at the token endpoint.
    pub token_endpoint_auth_method: AuthMethod,
    /// The URL of the client's JWK Set; exclusive with `jwks`.
    pub jwks_uri: String,
    /// The client's JWK Set by value; exclusive with `jwks_uri`.
    pub jwks: Option<Value>,
    /// The client's complete redirect URIs.
    pub redirect_uris: Vec<String>,
    /// The URIs the end-session endpoint may send the browser back to.
    pub post_logout_redirect_uris: Vec<String>,
    /// The providers a person may log in at for the client, by name.
    pub upstreams: Vec<String>,
    /// The `acr` values a request without `acr_values` asks for.
    pub default_acr_values: Vec<String>,
    /// The resource servers the client's tokens may name in `aud`.
    pub resources: Vec<String>,
    /// The scope ceiling, space-separated.
    pub scope: String,
    /// The grant types.
    pub grant_types: Vec<GrantType>,
    /// The app's launch URL; empty for none.
    pub launch_uri: String,
    /// The app's home page (RFC 7591 §2); empty for none.
    pub client_uri: String,
    /// The app's logo (RFC 7591 §2); empty for none.
    pub logo_uri: String,
    /// The app's privacy policy (RFC 7591 §2); empty for none.
    pub policy_uri: String,
    /// The app's terms of service (RFC 7591 §2); empty for none.
    pub tos_uri: String,
    /// Whether the app is the controller's own or acts for it.
    pub first_party: bool,
    /// Whether the client starts an authorization request only by pushing
    /// it (RFC 9126 §6).
    pub require_pushed_authorization_requests: bool,
    /// Whether the client sends a `DPoP` proof with every token request
    /// (RFC 9449 §5.2).
    pub dpop_bound_access_tokens: bool,
    /// Whether the client's tokens are bound to its mutual-TLS certificate
    /// (RFC 8705 §3.4).
    pub tls_client_certificate_bound_access_tokens: bool,
}

impl Default for Fields {
    fn default() -> Self {
        Self {
            client_id: String::new(),
            client_name: String::new(),
            // NOTE: RFC 7591 §2, an omitted token_endpoint_auth_method is
            // client_secret_basic and omitted grant_types are authorization_code.
            token_endpoint_auth_method: AuthMethod::ClientSecretBasic,
            jwks_uri: String::new(),
            jwks: None,
            redirect_uris: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            upstreams: Vec::new(),
            default_acr_values: Vec::new(),
            resources: Vec::new(),
            scope: String::new(),
            grant_types: vec![GrantType::AuthorizationCode],
            launch_uri: String::new(),
            client_uri: String::new(),
            logo_uri: String::new(),
            policy_uri: String::new(),
            tos_uri: String::new(),
            first_party: false,
            require_pushed_authorization_requests: false,
            dpop_bound_access_tokens: false,
            tls_client_certificate_bound_access_tokens: false,
        }
    }
}

/// The members a [`ClientDocument`] reads; a registration request's other
/// members are ignored (RFC 7591 §2).
const MEMBERS: [&str; 22] = [
    "client_id",
    "client_name",
    "token_endpoint_auth_method",
    "jwks_uri",
    "jwks",
    "redirect_uris",
    "post_logout_redirect_uris",
    "upstreams",
    "default_acr_values",
    "resources",
    "scope",
    "grant_types",
    "launch_uri",
    "client_uri",
    "logo_uri",
    "policy_uri",
    "tos_uri",
    "first_party",
    "require_pushed_authorization_requests",
    "dpop_bound_access_tokens",
    "tls_client_certificate_bound_access_tokens",
    "client_secret",
];

impl ClientDocument {
    /// Returns the registration this document makes of `client_id`, over
    /// the client `stored` when the request changes one.
    #[must_use]
    pub fn registration(
        self,
        client_id: &str,
        stored: Option<&Client>,
    ) -> (ClientMetadata, Material) {
        self.0.registration(client_id, stored)
    }
}

impl Fields {
    /// Returns the registration [`ClientDocument::registration`] makes.
    fn registration(self, client_id: &str, stored: Option<&Client>) -> (ClientMetadata, Material) {
        let kept_hash = stored
            .filter(|client| {
                self.token_endpoint_auth_method.kind() == ClientKind::ConfidentialSymmetric
                    && client.kind() == ClientKind::ConfidentialSymmetric
            })
            .and_then(|client| client.secret_hash.clone());
        let section = ClientMetadata {
            client_id: client_id.to_owned(),
            name: self.client_name,
            auth_method: self.token_endpoint_auth_method,
            jwks_uri: self.jwks_uri,
            redirect_uris: self.redirect_uris,
            post_logout_redirect_uris: self.post_logout_redirect_uris,
            upstreams: self.upstreams,
            default_acr_values: self.default_acr_values,
            resources: self.resources,
            scopes: self.scope.split_whitespace().map(str::to_owned).collect(),
            grant_types: self.grant_types,
            launch_uri: self.launch_uri,
            client_uri: self.client_uri,
            logo_uri: self.logo_uri,
            policy_uri: self.policy_uri,
            tos_uri: self.tos_uri,
            first_party: self.first_party,
            require_pushed_authorization_requests: self.require_pushed_authorization_requests,
            dpop_bound_access_tokens: self.dpop_bound_access_tokens,
            tls_client_certificate_bound_access_tokens: self
                .tls_client_certificate_bound_access_tokens,
        };
        let material = Material {
            jwks: self.jwks,
            secret_hash: kept_hash,
        };
        (section, material)
    }
}

/// A registered client as the API answers with it.
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is an RFC 7591 client metadata boolean of its own"
)]
#[derive(Debug, Serialize)]
pub struct ClientView<'a> {
    /// The `client_id`.
    client_id: &'a str,
    /// Its `client_name`.
    client_name: &'a str,
    /// How it authenticates at the token endpoint.
    token_endpoint_auth_method: AuthMethod,
    /// Its JWK Set URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    jwks_uri: Option<&'a str>,
    /// Its JWK Set by value.
    #[serde(skip_serializing_if = "Option::is_none")]
    jwks: Option<&'a Value>,
    /// Its redirect URIs.
    redirect_uris: &'a [String],
    /// Its post-logout redirect URIs.
    post_logout_redirect_uris: &'a [String],
    /// The providers its people log in at, every one when empty.
    upstreams: &'a [String],
    /// The `acr` values a request without `acr_values` asks for.
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    default_acr_values: &'a [String],
    /// The resource servers its tokens may name in `aud`.
    resources: &'a [String],
    /// Its scope ceiling, space-separated.
    scope: String,
    /// Its grant types.
    grant_types: &'a [GrantType],
    /// Its normalized launch URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    launch_uri: Option<&'a str>,
    /// Its home page.
    #[serde(skip_serializing_if = "Option::is_none")]
    client_uri: Option<&'a str>,
    /// Its logo.
    #[serde(skip_serializing_if = "Option::is_none")]
    logo_uri: Option<&'a str>,
    /// Its privacy policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_uri: Option<&'a str>,
    /// Its terms of service.
    #[serde(skip_serializing_if = "Option::is_none")]
    tos_uri: Option<&'a str>,
    /// Whether the app is the controller's own or acts for it.
    first_party: bool,
    /// Whether it starts an authorization request only by pushing it.
    require_pushed_authorization_requests: bool,
    /// Whether it sends a `DPoP` proof with every token request.
    dpop_bound_access_tokens: bool,
    /// Whether its tokens are bound to its mutual-TLS certificate.
    tls_client_certificate_bound_access_tokens: bool,
    /// `admin`, or `self` for an app that registered itself (RFC 7591 §5).
    registered_by: &'static str,
    /// When it was disabled, an RFC 3339 instant; absent while enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    disabled_at: Option<String>,
}

/// Returns `seconds` since the epoch as an RFC 3339 instant.
#[expect(
    clippy::expect_used,
    reason = "every instant the registry holds is the clock's or a parsed RFC 3339 instant, both within jiff's range"
)]
pub(super) fn instant(seconds: i64) -> String {
    jiff::Timestamp::from_second(seconds)
        .expect("the instant should be one the server wrote")
        .to_string()
}

impl<'a> From<&'a Registered> for ClientView<'a> {
    fn from(registered: &'a Registered) -> Self {
        let client = &registered.client;
        let (jwks_uri, jwks) = match &client.keys {
            Some(ClientKeys::Uri(url)) => (Some(url.as_str()), None),
            Some(ClientKeys::Set(set)) => (None, Some(set)),
            None => (None, None),
        };
        Self {
            client_id: &client.client_id,
            client_name: &client.name,
            token_endpoint_auth_method: client.auth_method,
            jwks_uri,
            jwks,
            redirect_uris: &client.redirect_uris,
            post_logout_redirect_uris: &client.post_logout_redirect_uris,
            upstreams: &client.upstreams,
            default_acr_values: &client.default_acr_values,
            resources: &client.resources,
            scope: client.scopes.join(" "),
            grant_types: &client.grant_types,
            launch_uri: client.launch_uri.as_deref(),
            client_uri: client.about.home.as_ref().map(Url::as_str),
            logo_uri: client.about.logo.as_ref().map(Url::as_str),
            policy_uri: client.about.policy.as_ref().map(Url::as_str),
            tos_uri: client.about.terms.as_ref().map(Url::as_str),
            first_party: client.first_party(),
            require_pushed_authorization_requests: client.require_pushed_authorization_requests,
            dpop_bound_access_tokens: client.dpop_bound_access_tokens,
            tls_client_certificate_bound_access_tokens: client
                .tls_client_certificate_bound_access_tokens,
            registered_by: registered.by.as_str(),
            disabled_at: registered.disabled_at.map(instant),
        }
    }
}
