// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The client registry: who may ask FerroSMART for a token, and how.
//!
//! SMART specifies no registration protocol ("SMART does not specify a
//! standards-based registration process", SMART App Launch 2.2.0, Register
//! App with EHR), so the registry is content: each `[[ferrosmart.client]]`
//! table names one client, checked here against what SMART requires of a
//! registration, and the store keeps them (`docs/architecture.md` §13.9).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

/// How a client authenticates at the token endpoint (SMART App Launch
/// 2.2.0, Conformance, Client Types).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    /// No client authentication (`client-public`).
    #[default]
    Public,
    /// A JWT assertion signed with a key of its registered JWK Set
    /// (`client-confidential-asymmetric`).
    ConfidentialAsymmetric,
    /// A client secret, sent by HTTP Basic or in the form
    /// (`client-confidential-symmetric`, SMART App Launch 2.2.0, Client
    /// Authentication: Symmetric; RFC 6749 §2.3.1).
    ConfidentialSymmetric,
}

impl ClientKind {
    /// Returns the kind as the store writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::ConfidentialAsymmetric => "confidential_asymmetric",
            Self::ConfidentialSymmetric => "confidential_symmetric",
        }
    }
}

/// A grant type a client may use at the token endpoint (RFC 6749 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    /// The authorization code grant (RFC 6749 §4.1).
    AuthorizationCode,
    /// The client credentials grant (RFC 6749 §4.4), SMART Backend Services.
    ClientCredentials,
    /// The refresh token grant (RFC 6749 §6).
    RefreshToken,
}

impl GrantType {
    /// Returns the `grant_type` value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::ClientCredentials => "client_credentials",
            Self::RefreshToken => "refresh_token",
        }
    }
}

/// One `[[ferrosmart.client]]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientSection {
    /// The `client_id` the client is assigned ("Upon registration, the
    /// client SHALL be assigned a `client_id`", SMART App Launch 2.2.0,
    /// Client Authentication: Asymmetric).
    pub client_id: String,
    /// The name shown to the person who approves the client.
    pub name: String,
    /// How the client authenticates.
    pub kind: ClientKind,
    /// The URL of the client's JWK Set; exclusive with `jwks_file`.
    pub jwks_uri: String,
    /// A file holding the client's JWK Set; exclusive with `jwks_uri`.
    pub jwks_file: Option<PathBuf>,
    /// A file holding the Argon2id PHC hash of a confidential symmetric
    /// client's secret; FerroSMART never holds the secret itself.
    pub secret_hash_file: Option<PathBuf>,
    /// The client's complete redirect URIs.
    pub redirect_uris: Vec<String>,
    /// The URIs the browser may be sent back to after a logout at the
    /// end-session endpoint, each matched exactly (OpenID Connect
    /// RP-Initiated Logout 1.0 §3.1, `post_logout_redirect_uris`).
    pub post_logout_redirect_uris: Vec<String>,
    /// The `[[ferrosmart.upstream]]` providers a person may log in at for
    /// the client, by name; every provider when empty. With more than one,
    /// the person chooses on a page.
    pub upstreams: Vec<String>,
    /// The eIDAS level a person's login for the client reaches, above the
    /// deployment's floor and the provider's minimum; none leaves those.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assurance_minimum: Option<ferrohealth_smart::assurance::AssuranceLevel>,
    /// The `[[ferrosmart.resource]]` bases the client's tokens may name in
    /// `aud`; none when empty, which leaves the client FerroSMART's own
    /// endpoints alone (`docs/architecture.md` §13.6 item 12).
    pub resources: Vec<String>,
    /// The scopes the client may be granted at most.
    pub scopes: Vec<String>,
    /// The grant types the client may use.
    pub grant_types: Vec<GrantType>,
    /// The app's launch URL, which an EHR's launch registration may name
    /// in place of the `client_id` (`docs/architecture.md` §13.17); empty
    /// for none.
    pub launch_uri: String,
    /// The app's home page (RFC 7591 §2 `client_uri`), linked from its name
    /// on the consent page; empty for none.
    pub client_uri: String,
    /// The app's logo (RFC 7591 §2 `logo_uri`), drawn on the consent page;
    /// empty for none.
    pub logo_uri: String,
    /// The app's privacy policy (RFC 7591 §2 `policy_uri`); empty for none.
    pub policy_uri: String,
    /// The app's terms of service (RFC 7591 §2 `tos_uri`); empty for none.
    pub tos_uri: String,
    /// The administrator's approval of the client for the whole
    /// organisation, under which a professional sees no consent page
    /// (`docs/architecture.md` §13.6 item 6).
    pub organisation_approval: Option<ApprovalSection>,
}

/// One `[ferrosmart.client.organisation_approval]` table: what an
/// administrator of the controller approved for every professional, who
/// and when.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSection {
    /// The approved scopes: `user/` and `patient/` scopes with the launch,
    /// OpenID, refresh and extension scopes that go with them, each within
    /// the client's ceiling. A `patient/` scope answers a professional's
    /// EHR launch, and for a `first_party` app any person's launch.
    pub scopes: Vec<String>,
    /// The administrator who approved, as the controller names them.
    pub approved_by: String,
    /// When they approved, an RFC 3339 instant.
    pub approved_at: String,
    /// Whether the app is the organisation's own (first party), which the
    /// approval may then cover `patient/` scopes for and a patient's own
    /// login too; the mark is set and cleared with the approval, by its
    /// approver at its time.
    #[serde(default)]
    pub first_party: bool,
}

/// A client's approval for the whole organisation, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// The approved scopes.
    pub scopes: Vec<String>,
    /// Who approved.
    pub approved_by: String,
    /// When, in seconds since the epoch.
    pub approved_at: i64,
    /// Whether the app is the organisation's own (first party).
    pub first_party: bool,
}

impl Approval {
    /// Returns whether the approval covers every scope of `offered`.
    #[must_use]
    pub fn covers(&self, offered: &[&str]) -> bool {
        offered
            .iter()
            .all(|wanted| self.scopes.iter().any(|approved| approved == wanted))
    }
}

/// Returns whether an organisation may approve `scope`, for its staff or,
/// for its `first_party` app, for its patients too.
///
/// A `user/` or `patient/` scope may be approved, with a launch, OpenID,
/// refresh or extension scope that goes with one. A `patient/` scope of an
/// app not the organisation's own answers only a professional's EHR launch.
/// A `system/` scope, which no person holds, never (`docs/architecture.md`
/// §13.6 item 6).
#[must_use]
pub fn approvable(scope: &str) -> bool {
    scope.starts_with("user/")
        || scope.starts_with("patient/")
        || crate::scopes::is_extension(scope)
        || matches!(
            scope,
            "openid"
                | "fhirUser"
                | "launch"
                | "launch/patient"
                | "launch/encounter"
                | "online_access"
                | "offline_access"
        )
}

/// A registered client, checked.
#[expect(
    clippy::struct_field_names,
    reason = "`client_id` is the parameter's name in RFC 6749 §2.2"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    /// The `client_id`.
    pub client_id: String,
    /// The name.
    pub name: String,
    /// How it authenticates.
    pub kind: ClientKind,
    /// Its JWK Set, by URL or by value.
    pub keys: Option<ClientKeys>,
    /// The Argon2id PHC hash of its secret, for a confidential symmetric
    /// client.
    pub secret_hash: Option<SecretHash>,
    /// Its redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Its post-logout redirect URIs.
    pub post_logout_redirect_uris: Vec<String>,
    /// The providers a person may log in at for it, every one when empty.
    pub upstreams: Vec<String>,
    /// The eIDAS level a person's login for it reaches, when it sets one.
    pub assurance_minimum: Option<ferrohealth_smart::assurance::AssuranceLevel>,
    /// The resource servers its tokens may name in `aud`.
    pub resources: Vec<String>,
    /// Its scope ceiling.
    pub scopes: Vec<String>,
    /// Its grant types, sorted and without repetition.
    pub grant_types: Vec<GrantType>,
    /// Its launch URL, normalized by [`normalized_launch_uri`].
    pub launch_uri: Option<String>,
    /// Its approval for the whole organisation, when an administrator
    /// gave one.
    pub approval: Option<Approval>,
    /// What the consent page shows about the app.
    pub about: About,
}

impl Client {
    /// Returns whether a redirect to `redirect_uri` assures this client's
    /// identity.
    ///
    /// Only then may a remembered consent or an organisation approval
    /// answer for the person with no page: always for a confidential
    /// client, which authenticates at the token endpoint, and for a public
    /// client only through a claimed `https` redirect URI (RFC 8252 §8.6,
    /// §7.2; RFC 6749 §10.2).
    #[must_use]
    pub fn assured_by(&self, redirect_uri: &str) -> bool {
        self.kind != ClientKind::Public || claimed_https(redirect_uri)
    }

    /// Returns whether the client's tokens may name `base` in `aud`: a base
    /// its `resources` list (RFC 8707 §2, `invalid_target` for any other).
    #[must_use]
    pub fn reaches(&self, base: &str) -> bool {
        self.resources.iter().any(|listed| listed == base)
    }
}

/// Returns whether `uri` is a claimed `https` redirect URI.
///
/// That is an `https` URL whose host is a name other than `localhost` or an
/// address that is not a loopback one (RFC 8252 §7.2). Any app on the
/// device can listen on a loopback redirect (§7.3).
#[must_use]
pub fn claimed_https(uri: &str) -> bool {
    Url::parse(uri).is_ok_and(|url| {
        url.scheme() == "https"
            && match url.host() {
                Some(url::Host::Domain(name)) => !name.eq_ignore_ascii_case("localhost"),
                Some(url::Host::Ipv4(address)) => !address.is_loopback(),
                Some(url::Host::Ipv6(address)) => !address.is_loopback(),
                None => false,
            }
    })
}

/// Returns a warning for each first-party public client with no claimed
/// `https` redirect URI.
///
/// No sign-in of such an app can assure its identity, so every one shows
/// the consent page (RFC 8252 §8.6).
#[must_use]
pub fn unassured_first_party(clients: &[Client]) -> Vec<String> {
    clients
        .iter()
        .filter(|client| {
            client.kind == ClientKind::Public
                && client
                    .approval
                    .as_ref()
                    .is_some_and(|approval| approval.first_party)
                && !client.redirect_uris.iter().any(|uri| claimed_https(uri))
        })
        .map(|client| {
            format!(
                "client {:?} is a first-party public app with no claimed https redirect URI, so every sign-in shows the consent page (RFC 8252 §8.6): register an https redirect the app claims, such as a Universal Link or an App Link",
                client.client_id
            )
        })
        .collect()
}

/// What a client registers about its app for the person who approves it
/// (RFC 7591 §2, client metadata), each an absolute `https` URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct About {
    /// `client_uri`, the app's home page.
    pub home: Option<Url>,
    /// `logo_uri`, the app's logo.
    pub logo: Option<Url>,
    /// `policy_uri`, the app's privacy policy.
    pub policy: Option<Url>,
    /// `tos_uri`, the app's terms of service.
    pub terms: Option<Url>,
}

/// The Argon2id PHC hash of a client secret, never rendered by `Debug`.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(from = "String")]
pub struct SecretHash(String);

impl SecretHash {
    /// Returns the PHC string.
    #[must_use]
    pub fn phc(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretHash {
    fn from(phc: String) -> Self {
        Self(phc)
    }
}

impl std::fmt::Debug for SecretHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretHash(..)")
    }
}

/// Where a confidential asymmetric client's public keys are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientKeys {
    /// The URL of its JWK Set, "strongly preferred" (SMART App Launch 2.2.0,
    /// Client Authentication: Asymmetric, Registering a client).
    Uri(Url),
    /// Its JWK Set by value, which the server "SHALL protect ... from
    /// corruption" (same section).
    Set(Value),
}

/// Why a client table was refused, naming the client and the key.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// A client has no `client_id`.
    #[error("a `[[ferrosmart.client]]` table has no `client_id`")]
    NoClientId,
    /// Two tables name one `client_id`.
    #[error("the client `{client_id}` is registered twice")]
    Repeated {
        /// The client.
        client_id: String,
    },
    /// A key the client's kind or grants need is missing, or one they
    /// forbid is set.
    #[error("the client `{client_id}`: {rule}")]
    Rule {
        /// The client.
        client_id: String,
        /// The rule broken.
        rule: &'static str,
    },
    /// The JWK Set URL is no `https` URL.
    #[error("the client `{client_id}`: `jwks_uri` is not an https URL")]
    JwksUri {
        /// The client.
        client_id: String,
    },
    /// The JWK Set file cannot be read or is no JSON.
    #[error("the client `{client_id}`: `jwks_file` cannot be read as JSON")]
    JwksFile {
        /// The client.
        client_id: String,
        /// Why.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// A JWK of the set breaks SMART's rule for a registered key.
    #[error("the client `{client_id}`: key {index} of its JWK Set {rule}")]
    Jwk {
        /// The client.
        client_id: String,
        /// The key's place in the set.
        index: usize,
        /// The rule broken.
        rule: &'static str,
    },
    /// A redirect URI is no absolute URL, or carries a fragment.
    #[error("the client `{client_id}`: a redirect URI is not an absolute URL without a fragment")]
    RedirectUri {
        /// The client.
        client_id: String,
    },
    /// A post-logout redirect URI is no absolute URL, or carries a
    /// fragment.
    #[error(
        "the client `{client_id}`: a post-logout redirect URI is not an absolute URL without a fragment"
    )]
    PostLogoutRedirectUri {
        /// The client.
        client_id: String,
    },
    /// The secret hash file cannot be read, or holds no Argon2id PHC string
    /// at the OWASP floor.
    #[error("the client `{client_id}`: `secret_hash_file` holds no usable Argon2id hash")]
    SecretHash {
        /// The client.
        client_id: String,
        /// Why.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The launch URL is no absolute `https` URL without a fragment.
    #[error(
        "the client `{client_id}`: `launch_uri` is not an absolute https URL without a fragment"
    )]
    LaunchUri {
        /// The client.
        client_id: String,
    },
    /// An RFC 7591 §2 URL of the app is no absolute `https` URL without a
    /// fragment.
    #[error("the client `{client_id}`: `{key}` is not an absolute https URL without a fragment")]
    AboutUri {
        /// The client.
        client_id: String,
        /// The key.
        key: &'static str,
    },
    /// Two clients register one launch URL, which a launch registration
    /// could then not tell apart.
    #[error("the clients `{first}` and `{second}` register the same `launch_uri`")]
    RepeatedLaunchUri {
        /// The client that registered it first.
        first: String,
        /// The client that registered it again.
        second: String,
    },
    /// A scope is outside the RFC 6749 §3.3 character set.
    #[error("the client `{client_id}`: a scope is outside the RFC 6749 §3.3 character set")]
    Scope {
        /// The client.
        client_id: String,
    },
}

/// Returns the clients `sections` register, each checked.
///
/// # Errors
/// Returns [`ClientError`] for the first table that breaks a rule.
pub fn resolve(sections: &[ClientSection]) -> Result<Vec<Client>, ClientError> {
    let mut seen = BTreeSet::new();
    let mut launch_uris: BTreeMap<String, String> = BTreeMap::new();
    let mut clients = Vec::with_capacity(sections.len());
    for section in sections {
        let client = resolve_one(section)?;
        if !seen.insert(client.client_id.clone()) {
            return Err(ClientError::Repeated {
                client_id: client.client_id,
            });
        }
        if let Some(uri) = &client.launch_uri
            && let Some(first) = launch_uris.insert(uri.clone(), client.client_id.clone())
        {
            return Err(ClientError::RepeatedLaunchUri {
                first,
                second: client.client_id,
            });
        }
        clients.push(client);
    }
    Ok(clients)
}

/// Returns the launch URL `uri` normalized for comparison.
///
/// The URL is an absolute `https` URL without user information or a
/// fragment; its scheme and host go to lower case, its default port is
/// dropped, its dot segments resolved and its percent-encodings normalized
/// in the path and the query (RFC 3986 §6.2.2). Any other value is `None`.
///
/// A launch registration names the app by this URL, as OpenID Connect
/// Dynamic Client Registration 1.0 §2 names a client's `initiate_login_uri`;
/// comparing the normalized forms exactly is our own design.
#[must_use]
pub fn normalized_launch_uri(uri: &str) -> Option<String> {
    let url = Url::parse(uri).ok()?;
    if url.scheme() != "https" || url.fragment().is_some() {
        return None;
    }
    let base = ferrohealth_smart::uri::normalized(uri)?;
    Some(match url.query() {
        Some(query) => format!(
            "{base}?{}",
            ferrohealth_smart::uri::normalize_percent(query)
        ),
        None => base,
    })
}

/// Returns the client `section` registers, checked, its JWK Set and secret
/// hash read from the files it names.
fn resolve_one(section: &ClientSection) -> Result<Client, ClientError> {
    if section.client_id.is_empty() {
        return Err(ClientError::NoClientId);
    }
    let rule = |rule| ClientError::Rule {
        client_id: section.client_id.clone(),
        rule,
    };
    if section.kind != ClientKind::ConfidentialSymmetric && section.secret_hash_file.is_some() {
        return Err(rule(
            "only a confidential symmetric client registers a `secret_hash_file`",
        ));
    }
    if section.kind != ClientKind::ConfidentialAsymmetric && section.jwks_file.is_some() {
        return Err(rule(
            "only a confidential asymmetric client registers a `jwks_file`",
        ));
    }
    let jwks = section
        .jwks_file
        .as_ref()
        .map(|path| read_jwks(&section.client_id, path))
        .transpose()?;
    let secret_hash = match (section.kind, &section.secret_hash_file) {
        (ClientKind::ConfidentialSymmetric, Some(path)) => {
            let phc = std::fs::read_to_string(path).map_err(|source| ClientError::SecretHash {
                client_id: section.client_id.clone(),
                source: Box::new(source),
            })?;
            Some(SecretHash(phc.trim().to_owned()))
        }
        _ => None,
    };
    resolve_with(section, Material { jwks, secret_hash })
}

/// What a client registers by value: its JWK Set and the Argon2id hash of
/// its secret, read from the files of its table or carried by the admin
/// API's document.
#[derive(Debug, Clone, Default)]
pub struct Material {
    /// Its JWK Set by value.
    pub jwks: Option<Value>,
    /// The Argon2id PHC hash of its secret.
    pub secret_hash: Option<SecretHash>,
}

/// Returns the client `section` and `material` register, checked as a
/// configured client is; the file keys of `section` are not read.
///
/// # Errors
/// Returns [`ClientError`] for the first rule the registration breaks.
pub fn resolve_with(section: &ClientSection, material: Material) -> Result<Client, ClientError> {
    if section.client_id.is_empty() {
        return Err(ClientError::NoClientId);
    }
    let id = || section.client_id.clone();
    let rule = |rule| ClientError::Rule {
        client_id: id(),
        rule,
    };
    let grant_types: Vec<GrantType> = section
        .grant_types
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if grant_types.is_empty() {
        return Err(rule("no `grant_types`"));
    }
    let jwks = !section.jwks_uri.is_empty() || material.jwks.is_some();
    if section.kind != ClientKind::ConfidentialSymmetric && material.secret_hash.is_some() {
        return Err(rule(
            "only a confidential symmetric client registers a secret hash",
        ));
    }
    let (keys, secret_hash) = match section.kind {
        ClientKind::Public => {
            if jwks {
                return Err(rule("a public client registers no JWK Set"));
            }
            // NOTE: SMART App Launch 2.2.0, Backend Services, the client
            // credentials grant authenticates with an asymmetric key.
            if grant_types.contains(&GrantType::ClientCredentials) {
                return Err(rule("a public client cannot use `client_credentials`"));
            }
            (None, None)
        }
        ClientKind::ConfidentialAsymmetric => (Some(keys(section, material.jwks)?), None),
        ClientKind::ConfidentialSymmetric => {
            if jwks {
                return Err(rule("a confidential symmetric client registers no JWK Set"));
            }
            // NOTE: SMART App Launch 2.2.0, Client Authentication: Symmetric, the
            // profile "SHALL NOT be used" for SMART Backend Services.
            if grant_types.contains(&GrantType::ClientCredentials) {
                return Err(rule(
                    "a confidential symmetric client cannot use `client_credentials`",
                ));
            }
            (None, Some(secret_hash(section, material.secret_hash)?))
        }
    };
    // NOTE: SMART App Launch 2.2.0, Backend Services, refresh tokens SHOULD NOT be
    // issued there; a refresh token continues an authorization code grant.
    if grant_types.contains(&GrantType::RefreshToken)
        && !grant_types.contains(&GrantType::AuthorizationCode)
    {
        return Err(rule("`refresh_token` needs `authorization_code`"));
    }
    if grant_types.contains(&GrantType::AuthorizationCode) && section.redirect_uris.is_empty() {
        return Err(rule("`authorization_code` needs `redirect_uris`"));
    }
    for uri in &section.redirect_uris {
        // NOTE: RFC 6749 §3.1.2, "The redirection endpoint URI MUST be an
        // absolute URI" and "MUST NOT include a fragment component".
        let absolute = Url::parse(uri).is_ok_and(|url| url.fragment().is_none());
        if !absolute {
            return Err(ClientError::RedirectUri { client_id: id() });
        }
    }
    check_post_logout(section, &grant_types)?;
    if !section
        .scopes
        .iter()
        .all(|scope| ferrohealth_smart::scope::is_scope_token(scope))
    {
        return Err(ClientError::Scope { client_id: id() });
    }
    let launch_uri = resolve_launch_uri(section, &grant_types)?;
    let approval = section
        .organisation_approval
        .as_ref()
        .map(|approval| resolve_approval(section, &grant_types, approval))
        .transpose()?;
    let about = resolve_about(section)?;
    Ok(Client {
        client_id: section.client_id.clone(),
        name: if section.name.is_empty() {
            section.client_id.clone()
        } else {
            section.name.clone()
        },
        kind: section.kind,
        keys,
        secret_hash,
        redirect_uris: section.redirect_uris.clone(),
        post_logout_redirect_uris: section.post_logout_redirect_uris.clone(),
        upstreams: section.upstreams.clone(),
        assurance_minimum: section.assurance_minimum,
        resources: section.resources.clone(),
        scopes: section.scopes.clone(),
        grant_types,
        launch_uri,
        approval,
        about,
    })
}

/// Returns what the client `section` registers about its app, each URL
/// checked.
///
/// The consent page links and draws these, so each is an absolute `https`
/// URL without a fragment; RFC 7591 §2 asks only for a URL, and the scheme
/// rule is our own design.
fn resolve_about(section: &ClientSection) -> Result<About, ClientError> {
    let url = |key: &'static str, value: &str| {
        if value.is_empty() {
            return Ok(None);
        }
        Url::parse(value)
            .ok()
            .filter(|url| url.scheme() == "https" && url.fragment().is_none())
            .map(Some)
            .ok_or_else(|| ClientError::AboutUri {
                client_id: section.client_id.clone(),
                key,
            })
    };
    Ok(About {
        home: url("client_uri", &section.client_uri)?,
        logo: url("logo_uri", &section.logo_uri)?,
        policy: url("policy_uri", &section.policy_uri)?,
        terms: url("tos_uri", &section.tos_uri)?,
    })
}

/// Returns the launch URL the client `section` registers, normalized; it
/// Checks the client's `post_logout_redirect_uris`: absolute, with no
/// fragment, and only beside the authorization code grant.
fn check_post_logout(
    section: &ClientSection,
    grant_types: &[GrantType],
) -> Result<(), ClientError> {
    // NOTE: RP-Initiated Logout 1.0 §3.1, a post-logout redirect follows a login of an
    // ID Token, so it needs the authorization code grant; absolute, no fragment.
    if !section.post_logout_redirect_uris.is_empty()
        && !grant_types.contains(&GrantType::AuthorizationCode)
    {
        return Err(ClientError::Rule {
            client_id: section.client_id.clone(),
            rule: "`post_logout_redirect_uris` needs `authorization_code`",
        });
    }
    for uri in &section.post_logout_redirect_uris {
        if !Url::parse(uri).is_ok_and(|url| url.fragment().is_none()) {
            return Err(ClientError::PostLogoutRedirectUri {
                client_id: section.client_id.clone(),
            });
        }
    }
    Ok(())
}

/// needs the authorization code grant an EHR launch continues in.
fn resolve_launch_uri(
    section: &ClientSection,
    grant_types: &[GrantType],
) -> Result<Option<String>, ClientError> {
    if section.launch_uri.is_empty() {
        return Ok(None);
    }
    if !grant_types.contains(&GrantType::AuthorizationCode) {
        return Err(ClientError::Rule {
            client_id: section.client_id.clone(),
            rule: "`launch_uri` needs `authorization_code`, the grant an EHR launch continues in",
        });
    }
    normalized_launch_uri(&section.launch_uri)
        .map(Some)
        .ok_or_else(|| ClientError::LaunchUri {
            client_id: section.client_id.clone(),
        })
}

/// Returns the organisation approval `approval` of the client `section`,
/// checked: a person's grant to approve, an approver and an instant, and
/// scopes an organisation may approve within the client's ceiling.
fn resolve_approval(
    section: &ClientSection,
    grant_types: &[GrantType],
    approval: &ApprovalSection,
) -> Result<Approval, ClientError> {
    let rule = |rule| ClientError::Rule {
        client_id: section.client_id.clone(),
        rule,
    };
    if !grant_types.contains(&GrantType::AuthorizationCode) {
        return Err(rule(
            "an `organisation_approval` needs `authorization_code`, the grant a person signs in to",
        ));
    }
    if approval.scopes.is_empty() {
        return Err(rule("the `organisation_approval` approves no scope"));
    }
    if approval.scopes.iter().any(|scope| !approvable(scope)) {
        return Err(rule(
            "the `organisation_approval` lists a scope no organisation approves: only `user/`, `patient/`, launch, OpenID, refresh and `__` extension scopes",
        ));
    }
    if !approval
        .scopes
        .iter()
        .all(|scope| crate::scopes::admits(&section.scopes, scope))
    {
        return Err(rule(
            "the `organisation_approval` lists a scope beyond the client's `scopes`",
        ));
    }
    if approval.approved_by.trim().is_empty() {
        return Err(rule("the `organisation_approval` names no `approved_by`"));
    }
    let approved_at = approval
        .approved_at
        .parse::<jiff::Timestamp>()
        .map_err(|_unparsed| {
            rule("the `organisation_approval`'s `approved_at` is no RFC 3339 instant")
        })?
        .as_second();
    Ok(Approval {
        scopes: approval.scopes.clone(),
        approved_by: approval.approved_by.clone(),
        approved_at,
        first_party: approval.first_party,
    })
}

/// Returns the JWK Set a confidential asymmetric client registers: by URL
/// or by value, exactly one ("FHIR authorization servers SHALL support
/// registration of client JWKs using both of the following techniques",
/// SMART App Launch 2.2.0, Client Authentication: Asymmetric, Registering a
/// client).
fn keys(section: &ClientSection, set: Option<Value>) -> Result<ClientKeys, ClientError> {
    let id = || section.client_id.clone();
    match (section.jwks_uri.is_empty(), set) {
        (false, None) => {
            // NOTE: SMART App Launch 2.2.0, Registering a client, the JWK Set URL
            // is a "TLS-protected endpoint"; a loopback host is the test exception.
            let url = Url::parse(&section.jwks_uri)
                .ok()
                .filter(|url| url.scheme() == "https" || is_loopback(url))
                .ok_or(ClientError::JwksUri { client_id: id() })?;
            Ok(ClientKeys::Uri(url))
        }
        (true, Some(set)) => {
            check_set(&section.client_id, &set)?;
            Ok(ClientKeys::Set(set))
        }
        _ => Err(ClientError::Rule {
            client_id: id(),
            rule: "a confidential asymmetric client registers exactly one of `jwks_uri` and a JWK Set by value",
        }),
    }
}

/// Returns the JWK Set the file `path` holds for `client_id`.
fn read_jwks(client_id: &str, path: &std::path::Path) -> Result<Value, ClientError> {
    let failed = |source: Box<dyn std::error::Error + Send + Sync>| ClientError::JwksFile {
        client_id: client_id.to_owned(),
        source,
    };
    let bytes = std::fs::read(path).map_err(|source| failed(Box::new(source)))?;
    serde_json::from_slice::<Value>(&bytes).map_err(|source| failed(Box::new(source)))
}

/// Returns the secret hash a confidential symmetric client registers,
/// checked as `ferrohealth-smart` checks a Basic user's hash: an Argon2id
/// PHC string at the OWASP Password Storage Cheat Sheet floor
/// (`docs/architecture.md` §13.9).
fn secret_hash(
    section: &ClientSection,
    hash: Option<SecretHash>,
) -> Result<SecretHash, ClientError> {
    let hash = hash.ok_or(ClientError::Rule {
        client_id: section.client_id.clone(),
        rule: "a confidential symmetric client registers a secret hash",
    })?;
    ferrohealth_smart::basic::PasswordStore::new()
        .with_user("client", secrecy::SecretString::from(hash.0.clone()))
        .map_err(|source| ClientError::SecretHash {
            client_id: section.client_id.clone(),
            source: Box::new(source),
        })?;
    Ok(hash)
}

/// The Argon2id memory cost of a hash [`hash_secret`] makes, in KiB: the
/// OWASP Password Storage Cheat Sheet floor.
pub const HASH_MEMORY_KIB: u32 = 19_456;

/// The Argon2id passes of a hash [`hash_secret`] makes.
pub const HASH_PASSES: u32 = 2;

/// Returns the Argon2id PHC hash of `secret` at [`HASH_MEMORY_KIB`] and
/// [`HASH_PASSES`], one lane, under a fresh 16-byte salt: the string a
/// confidential symmetric client's `secret_hash_file` holds.
///
/// # Errors
/// Returns [`HashError`] when no salt can be drawn or the hash fails.
pub fn hash_secret(secret: &str) -> Result<String, HashError> {
    use argon2::password_hash::PasswordHasher as _;
    let mut salt = [0_u8; 16];
    aws_lc_rs::rand::fill(&mut salt).map_err(|_unspecified| HashError::Salt)?;
    let params =
        argon2::Params::new(HASH_MEMORY_KIB, HASH_PASSES, 1, None).map_err(HashError::Params)?;
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_with_salt(secret.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(HashError::Hash)
}

/// Why a secret could not be hashed.
#[derive(Debug, thiserror::Error)]
pub enum HashError {
    /// No salt could be drawn.
    #[error("no salt could be drawn")]
    Salt,
    /// The parameters were refused.
    #[error("the Argon2id parameters were refused")]
    Params(#[source] argon2::Error),
    /// The hash failed.
    #[error("the secret could not be hashed")]
    Hash(#[source] argon2::password_hash::Error),
}

/// Returns whether `url` names a loopback host over plain `http`, which a
/// test's JWK Set server is. No specification governs the exception: our
/// own design, the one `ferrohealth_smart::metadata::issuer_url` makes.
fn is_loopback(url: &Url) -> bool {
    url.scheme() == "http" && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

/// Checks the JWK Set `set` of `client_id` against SMART's rule for a
/// registered key: "each JWK SHALL represent an asymmetric key by including
/// `kty` and `kid` properties, with content conveyed using 'bare key'
/// properties", `n` and `e` for RSA and `crv`, `x` and `y` for EC (SMART
/// App Launch 2.2.0, Client Authentication: Asymmetric, Registering a
/// client). A private member (`d`, RFC 7518 §6.2.2.1 and §6.3.2.1) is
/// refused: a public key set never carries one.
fn check_set(client_id: &str, set: &Value) -> Result<(), ClientError> {
    let keys = set
        .get("keys")
        .and_then(Value::as_array)
        .filter(|keys| !keys.is_empty())
        .ok_or(ClientError::Rule {
            client_id: client_id.to_owned(),
            rule: "its JWK Set has no `keys`",
        })?;
    for (index, key) in keys.iter().enumerate() {
        let fault = |rule| ClientError::Jwk {
            client_id: client_id.to_owned(),
            index,
            rule,
        };
        let text = |member: &str| key.get(member).and_then(Value::as_str);
        if text("kid").is_none_or(str::is_empty) {
            return Err(fault("has no `kid`"));
        }
        let bare = match text("kty") {
            Some("RSA") => ["n", "e"].iter().all(|member| text(member).is_some()),
            Some("EC") => ["crv", "x", "y"]
                .iter()
                .all(|member| text(member).is_some()),
            _ => return Err(fault("is no RSA or EC key")),
        };
        if !bare {
            return Err(fault("lacks a bare key member"));
        }
        if key.get("d").is_some() {
            return Err(fault("carries a private member"));
        }
    }
    Ok(())
}
