// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The JSON documents of `/admin/clients`.
//!
//! The client an administrator sends carries what a `[[ferrosmart.client]]`
//! table does, with the JWK Set and the secret hash by value; the client
//! the API answers with never carries the secret hash.
//!
//! No specification governs the documents: our own design, with the RFC
//! 7591 §2 member names wherever the registry has one.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::clients::{
    ApprovalSection, Client, ClientKeys, ClientKind, ClientSection, GrantType, Material, SecretHash,
};
use crate::store::admin::Registered;

/// A client as an administrator sends it to `POST /admin/clients` or
/// `PUT /admin/clients/{client_id}`: a JSON object alone, never the
/// positional array serde would also read a struct from.
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
}

/// The members of a [`ClientDocument`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Fields {
    /// The `client_id`; on an update absent or the path's.
    pub client_id: String,
    /// The name shown to the person who approves the client.
    pub name: String,
    /// How the client authenticates.
    pub kind: ClientKind,
    /// The URL of the client's JWK Set; exclusive with `jwks`.
    pub jwks_uri: String,
    /// The client's JWK Set by value; exclusive with `jwks_uri`.
    pub jwks: Option<Value>,
    /// The Argon2id PHC hash of a confidential symmetric client's secret;
    /// on an update of such a client, absent keeps the stored one.
    pub secret_hash: Option<SecretHash>,
    /// The client's complete redirect URIs.
    pub redirect_uris: Vec<String>,
    /// The URIs the end-session endpoint may send the browser back to.
    pub post_logout_redirect_uris: Vec<String>,
    /// The providers a person may log in at for the client, by name.
    pub upstreams: Vec<String>,
    /// The eIDAS level a person's login for the client reaches.
    pub assurance_minimum: Option<ferrohealth_smart::assurance::AssuranceLevel>,
    /// The resource servers the client's tokens may name in `aud`.
    pub resources: Vec<String>,
    /// The scope ceiling.
    pub scopes: Vec<String>,
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
    /// The organisation's approval of the client for its staff.
    pub organisation_approval: Option<ApprovalDocument>,
}

/// The organisation approval a [`ClientDocument`] gives.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApprovalDocument {
    /// The approved scopes.
    pub scopes: Vec<String>,
    /// The administrator who approved, as the controller names them.
    pub approved_by: String,
    /// When, an RFC 3339 instant; absent keeps the stored approval's time
    /// when its scopes, approver and mark are the same, and takes the time
    /// of the request otherwise.
    pub approved_at: Option<String>,
    /// Whether the app is the organisation's own.
    pub first_party: bool,
}

impl ClientDocument {
    /// Returns the registration this document makes of `client_id`, over
    /// the client `stored` when the request changes one, at `now` in
    /// seconds since the epoch.
    #[must_use]
    pub fn registration(
        self,
        client_id: &str,
        stored: Option<&Client>,
        now: i64,
    ) -> (ClientSection, Material) {
        self.0.registration(client_id, stored, now)
    }
}

impl Fields {
    /// Returns the registration [`ClientDocument::registration`] makes.
    fn registration(
        self,
        client_id: &str,
        stored: Option<&Client>,
        now: i64,
    ) -> (ClientSection, Material) {
        let kept_hash = stored
            .filter(|client| {
                self.kind == ClientKind::ConfidentialSymmetric
                    && client.kind == ClientKind::ConfidentialSymmetric
            })
            .and_then(|client| client.secret_hash.clone());
        let approval = self.organisation_approval.map(|approval| {
            let same = stored
                .and_then(|client| client.approval.as_ref())
                .filter(|kept| {
                    kept.scopes == approval.scopes
                        && kept.approved_by == approval.approved_by
                        && kept.first_party == approval.first_party
                })
                .map(|kept| kept.approved_at);
            let approved_at = approval
                .approved_at
                .unwrap_or_else(|| instant(same.unwrap_or(now)));
            ApprovalSection {
                scopes: approval.scopes,
                approved_by: approval.approved_by,
                approved_at,
                first_party: approval.first_party,
            }
        });
        let section = ClientSection {
            client_id: client_id.to_owned(),
            name: self.name,
            kind: self.kind,
            jwks_uri: self.jwks_uri,
            jwks_file: None,
            secret_hash_file: None,
            redirect_uris: self.redirect_uris,
            post_logout_redirect_uris: self.post_logout_redirect_uris,
            upstreams: self.upstreams,
            assurance_minimum: self.assurance_minimum,
            resources: self.resources,
            scopes: self.scopes,
            grant_types: self.grant_types,
            launch_uri: self.launch_uri,
            client_uri: self.client_uri,
            logo_uri: self.logo_uri,
            policy_uri: self.policy_uri,
            tos_uri: self.tos_uri,
            organisation_approval: approval,
        };
        let material = Material {
            jwks: self.jwks,
            secret_hash: self.secret_hash.or(kept_hash),
        };
        (section, material)
    }
}

/// A registered client as the API answers with it.
#[derive(Debug, Serialize)]
pub struct ClientView<'a> {
    /// The `client_id`.
    client_id: &'a str,
    /// The name.
    name: &'a str,
    /// How it authenticates.
    kind: ClientKind,
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
    /// The eIDAS level its people's logins reach.
    #[serde(skip_serializing_if = "Option::is_none")]
    assurance_minimum: Option<ferrohealth_smart::assurance::AssuranceLevel>,
    /// The resource servers its tokens may name in `aud`.
    resources: &'a [String],
    /// Its scope ceiling.
    scopes: &'a [String],
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
    /// Its organisation approval.
    #[serde(skip_serializing_if = "Option::is_none")]
    organisation_approval: Option<ApprovalView<'a>>,
    /// `config` while its table writes it at start, `admin` once the API
    /// created or changed it.
    source: &'static str,
    /// When it was disabled, an RFC 3339 instant; absent while enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    disabled_at: Option<String>,
}

/// An organisation approval as the API answers with it.
#[derive(Debug, Serialize)]
struct ApprovalView<'a> {
    /// The approved scopes.
    scopes: &'a [String],
    /// Who approved.
    approved_by: &'a str,
    /// When, an RFC 3339 instant.
    approved_at: String,
    /// Whether the app is the organisation's own.
    first_party: bool,
}

/// Returns `seconds` since the epoch as an RFC 3339 instant.
#[expect(
    clippy::expect_used,
    reason = "every instant the registry holds is the clock's or a parsed RFC 3339 instant, both within jiff's range"
)]
fn instant(seconds: i64) -> String {
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
            name: &client.name,
            kind: client.kind,
            jwks_uri,
            jwks,
            redirect_uris: &client.redirect_uris,
            post_logout_redirect_uris: &client.post_logout_redirect_uris,
            upstreams: &client.upstreams,
            assurance_minimum: client.assurance_minimum,
            resources: &client.resources,
            scopes: &client.scopes,
            grant_types: &client.grant_types,
            launch_uri: client.launch_uri.as_deref(),
            client_uri: client.about.home.as_ref().map(Url::as_str),
            logo_uri: client.about.logo.as_ref().map(Url::as_str),
            policy_uri: client.about.policy.as_ref().map(Url::as_str),
            tos_uri: client.about.terms.as_ref().map(Url::as_str),
            organisation_approval: client.approval.as_ref().map(|approval| ApprovalView {
                scopes: &approval.scopes,
                approved_by: &approval.approved_by,
                approved_at: instant(approval.approved_at),
                first_party: approval.first_party,
            }),
            source: registered.source.as_str(),
            disabled_at: registered.disabled_at.map(instant),
        }
    }
}
