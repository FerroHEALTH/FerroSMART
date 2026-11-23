// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The client registry: who may ask FerroSMART for a token, and how.
//!
//! The store is the one place a client lives. RFC 6749 §2 leaves the means
//! of registration to the server, and SMART App Launch 2.2.0 (Register App
//! with EHR) asks only for what a registration holds, which this module
//! checks (`docs/architecture.md` §13.9).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

/// How a client authenticates at the token endpoint: its RFC 7591 §2
/// `token_endpoint_auth_method`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// No client authentication.
    #[default]
    None,
    /// The client secret by HTTP Basic (RFC 6749 §2.3.1).
    ClientSecretBasic,
    /// The client secret in the form (RFC 6749 §2.3.1).
    ClientSecretPost,
    /// A JWT assertion signed with a key of the client's JWK Set (RFC 7523
    /// §2.2).
    PrivateKeyJwt,
}

impl AuthMethod {
    /// Returns the method as RFC 7591 §2 and the store spell it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::PrivateKeyJwt => "private_key_jwt",
        }
    }

    /// Returns the method the store wrote as `text`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        [
            Self::None,
            Self::ClientSecretBasic,
            Self::ClientSecretPost,
            Self::PrivateKeyJwt,
        ]
        .into_iter()
        .find(|method| method.as_str() == text)
    }

    /// Returns the SMART client type the method makes.
    #[must_use]
    pub const fn kind(self) -> ClientKind {
        match self {
            Self::None => ClientKind::Public,
            Self::ClientSecretBasic | Self::ClientSecretPost => ClientKind::ConfidentialSymmetric,
            Self::PrivateKeyJwt => ClientKind::ConfidentialAsymmetric,
        }
    }
}

/// A SMART client type (SMART App Launch 2.2.0, Conformance, Client Types),
/// which the client's [`AuthMethod`] makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientKind {
    /// No client authentication (`client-public`).
    Public,
    /// A JWT assertion signed with a key of its JWK Set
    /// (`client-confidential-asymmetric`).
    ConfidentialAsymmetric,
    /// A client secret (`client-confidential-symmetric`).
    ConfidentialSymmetric,
}

impl ClientKind {
    /// Returns the type as the audit record names it.
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
    /// The token exchange of a patient's own token for their openEHR base
    /// (RFC 8693 §2.1; `docs/architecture.md` §13.29).
    #[serde(rename = "urn:ietf:params:oauth:grant-type:token-exchange")]
    TokenExchange,
}

impl GrantType {
    /// Returns the `grant_type` value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::ClientCredentials => "client_credentials",
            Self::RefreshToken => "refresh_token",
            Self::TokenExchange => crate::token::exchange::TOKEN_EXCHANGE,
        }
    }
}

/// What a registration of one client states, before it is checked.
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is an RFC 7591 client metadata boolean of its own"
)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientMetadata {
    /// The `client_id` the client is assigned ("Upon registration, the
    /// client SHALL be assigned a `client_id`", SMART App Launch 2.2.0,
    /// Client Authentication: Asymmetric).
    pub client_id: String,
    /// The `client_name` shown to the person who approves the client.
    pub name: String,
    /// Its `token_endpoint_auth_method`.
    pub auth_method: AuthMethod,
    /// The URL of the client's JWK Set; exclusive with a JWK Set by value.
    pub jwks_uri: String,
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
    /// The `acr` values a request that sends no `acr_values` asks for
    /// (OpenID Connect Dynamic Client Registration 1.0 §2).
    pub default_acr_values: Vec<String>,
    /// The `[[ferrosmart.resource]]` bases the client's tokens may name in
    /// `aud`; none when empty, which leaves the client FerroSMART's own
    /// endpoints alone (`docs/architecture.md` §13.6 item 12).
    pub resources: Vec<String>,
    /// Its `scope`, split: the scopes the client may be granted at most.
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
    /// Whether the app is the controller's own or acts for it, which only
    /// an administrator sets (`docs/architecture.md` §13.6 item 6).
    pub first_party: bool,
    /// Whether the client may start an authorization request only by
    /// pushing it (RFC 9126 §6).
    pub require_pushed_authorization_requests: bool,
    /// Whether the client sends a `DPoP` proof with every token request
    /// (RFC 9449 §5.2).
    pub dpop_bound_access_tokens: bool,
    /// Whether the client's tokens are bound to its mutual-TLS certificate
    /// (RFC 8705 §3.4).
    pub tls_client_certificate_bound_access_tokens: bool,
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
    /// Its `client_name`.
    pub name: String,
    /// Its `token_endpoint_auth_method`.
    pub auth_method: AuthMethod,
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
    /// The `acr` values a request without `acr_values` asks for.
    pub default_acr_values: Vec<String>,
    /// The resource servers its tokens may name in `aud`.
    pub resources: Vec<String>,
    /// Its scope ceiling.
    pub scopes: Vec<String>,
    /// Its grant types, sorted and without repetition.
    pub grant_types: Vec<GrantType>,
    /// Its launch URL, normalized by [`normalized_launch_uri`].
    pub launch_uri: Option<String>,
    /// Who registered it, which decides what its metadata may claim.
    pub registration: Registration,
    /// What the consent page shows about the app.
    pub about: About,
    /// Whether it may start an authorization request only by pushing it
    /// (RFC 9126 §6).
    pub require_pushed_authorization_requests: bool,
    /// Whether it sends a `DPoP` proof with every token request (RFC 9449
    /// §5.2).
    pub dpop_bound_access_tokens: bool,
    /// Whether its tokens are bound to its mutual-TLS certificate (RFC 8705
    /// §3.4).
    pub tls_client_certificate_bound_access_tokens: bool,
}

/// Who registered a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registration {
    /// An administrator, through the admin API or `ferrosmart client
    /// apply`; the registration is the organisation's administrative
    /// consent (OpenID Connect Core 1.0 §3.1.2.4).
    Administered {
        /// Whether the app is the controller's own or acts for it.
        first_party: bool,
    },
    /// The app itself (RFC 7591). RFC 7591 §5 has its metadata treated as
    /// self-asserted, so it is never first party.
    Dynamic,
}

impl Client {
    /// Returns its SMART client type.
    #[must_use]
    pub const fn kind(&self) -> ClientKind {
        self.auth_method.kind()
    }

    /// Returns the level its `default_acr_values` ask for, when it sets any.
    #[must_use]
    pub fn default_acr(&self) -> Option<ferrohealth_smart::assurance::AssuranceLevel> {
        self.default_acr_values
            .iter()
            .filter_map(|value| crate::assurance::of_uri(value))
            .min()
    }

    /// Returns whether the app is the controller's own or acts for it.
    #[must_use]
    pub const fn first_party(&self) -> bool {
        matches!(
            self.registration,
            Registration::Administered { first_party: true }
        )
    }

    /// Returns whether the app registered itself (RFC 7591).
    #[must_use]
    pub const fn registered_itself(&self) -> bool {
        matches!(self.registration, Registration::Dynamic)
    }

    /// Returns what the consent page may show about the app for a request
    /// that redirects to `redirect_uri`.
    ///
    /// RFC 7591 §5 has the server check that the URLs of a registration
    /// share the scheme and host of its redirect URIs, so an app that
    /// registered itself shows only those that share `redirect_uri`'s.
    #[must_use]
    pub fn shown_about(&self, redirect_uri: &str) -> About {
        if !self.registered_itself() {
            return self.about.clone();
        }
        let redirect = Url::parse(redirect_uri).ok();
        let same_site = |url: &Option<Url>| {
            url.clone().filter(|url| {
                redirect.as_ref().is_some_and(|redirect| {
                    redirect.scheme() == url.scheme() && redirect.host() == url.host()
                })
            })
        };
        About {
            home: same_site(&self.about.home),
            logo: same_site(&self.about.logo),
            policy: same_site(&self.about.policy),
            terms: same_site(&self.about.terms),
        }
    }

    /// Returns whether a redirect to `redirect_uri` assures this client's
    /// identity.
    ///
    /// Only then may a remembered consent or the registration
    /// answer for the person with no page: always for a confidential
    /// client, which authenticates at the token endpoint, and for a public
    /// client only through a claimed `https` redirect URI (RFC 8252 §8.6,
    /// §7.2; RFC 6749 §10.2).
    #[must_use]
    pub fn assured_by(&self, redirect_uri: &str) -> bool {
        self.kind() != ClientKind::Public || claimed_https(redirect_uri)
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

/// Returns a warning when `client` is a public app an administrator
/// registered with no claimed `https` redirect URI.
///
/// No sign-in of such an app can assure its identity, so every one shows
/// the consent page (RFC 8252 §8.6), the registration's consent unused.
#[must_use]
pub fn unassured_public(client: &Client) -> Option<String> {
    let unassured = client.kind() == ClientKind::Public
        && !client.registered_itself()
        && !client.redirect_uris.iter().any(|uri| claimed_https(uri));
    unassured.then(|| {
        format!(
            "client {:?} is a public app with no claimed https redirect URI, so every sign-in shows the consent page (RFC 8252 §8.6): register an https redirect the app claims, such as a Universal Link or an App Link",
            client.client_id
        )
    })
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

/// Why a registration was refused, naming the client and the member.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The registration has no `client_id`.
    #[error("the client document has no `client_id`")]
    NoClientId,
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
    /// The secret hash is no Argon2id PHC string at the OWASP floor.
    #[error("the client `{client_id}`: its secret hash is no usable Argon2id hash")]
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
    /// A scope is outside the RFC 6749 §3.3 character set.
    #[error("the client `{client_id}`: a scope is outside the RFC 6749 §3.3 character set")]
    Scope {
        /// The client.
        client_id: String,
    },
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

/// What a client registers by value: its JWK Set and the Argon2id hash of
/// its secret.
#[derive(Debug, Clone, Default)]
pub struct Material {
    /// Its JWK Set by value.
    pub jwks: Option<Value>,
    /// The Argon2id PHC hash of its secret.
    pub secret_hash: Option<SecretHash>,
}

/// Returns the client `section` and `material` register, checked.
///
/// # Errors
/// Returns [`ClientError`] for the first rule the registration breaks.
pub fn resolve(section: &ClientMetadata, material: Material) -> Result<Client, ClientError> {
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
    let kind = section.auth_method.kind();
    if kind != ClientKind::ConfidentialSymmetric && material.secret_hash.is_some() {
        return Err(rule(
            "only a confidential symmetric client registers a secret hash",
        ));
    }
    let (keys, secret_hash) = match kind {
        ClientKind::Public => {
            if jwks {
                return Err(rule("a public client registers no JWK Set"));
            }
            // NOTE: SMART App Launch 2.2.0, Backend Services, the client
            // credentials grant authenticates with an asymmetric key.
            if grant_types.contains(&GrantType::ClientCredentials) {
                return Err(rule("a public client cannot use `client_credentials`"));
            }
            // NOTE: RFC 8693 §2.1, the exchanging client authenticates.
            if grant_types.contains(&GrantType::TokenExchange) {
                return Err(rule("a public client cannot use the token exchange grant"));
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
    check_redirects(section, &grant_types)?;
    check_post_logout(section, &grant_types)?;
    if !section
        .scopes
        .iter()
        .all(|scope| ferrohealth_smart::scope::is_scope_token(scope))
    {
        return Err(ClientError::Scope { client_id: id() });
    }
    check_acr(section)?;
    let launch_uri = resolve_launch_uri(section, &grant_types)?;
    // NOTE: our own design, first party speaks of a person's sign-in, which only
    // the authorization code grant has.
    if section.first_party && !grant_types.contains(&GrantType::AuthorizationCode) {
        return Err(rule(
            "`first_party` needs `authorization_code`, the grant a person signs in to",
        ));
    }
    let about = resolve_about(section)?;
    Ok(Client {
        client_id: section.client_id.clone(),
        name: if section.name.is_empty() {
            section.client_id.clone()
        } else {
            section.name.clone()
        },
        auth_method: section.auth_method,
        keys,
        secret_hash,
        redirect_uris: section.redirect_uris.clone(),
        post_logout_redirect_uris: section.post_logout_redirect_uris.clone(),
        upstreams: section.upstreams.clone(),
        default_acr_values: section.default_acr_values.clone(),
        resources: section.resources.clone(),
        scopes: section.scopes.clone(),
        grant_types,
        launch_uri,
        registration: Registration::Administered {
            first_party: section.first_party,
        },
        about,
        require_pushed_authorization_requests: section.require_pushed_authorization_requests,
        dpop_bound_access_tokens: section.dpop_bound_access_tokens,
        tls_client_certificate_bound_access_tokens: section
            .tls_client_certificate_bound_access_tokens,
    })
}

/// Returns what the client `section` registers about its app, each URL
/// checked.
///
/// The consent page links and draws these, so each is an absolute `https`
/// URL without a fragment; RFC 7591 §2 asks only for a URL, and the scheme
/// rule is our own design.
fn resolve_about(section: &ClientMetadata) -> Result<About, ClientError> {
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

/// Checks the client's `redirect_uris`: at least one beside the
/// authorization code grant, each absolute with no fragment.
fn check_redirects(section: &ClientMetadata, grant_types: &[GrantType]) -> Result<(), ClientError> {
    if grant_types.contains(&GrantType::AuthorizationCode) && section.redirect_uris.is_empty() {
        return Err(ClientError::Rule {
            client_id: section.client_id.clone(),
            rule: "`authorization_code` needs `redirect_uris`",
        });
    }
    // NOTE: RFC 6749 §3.1.2, "The redirection endpoint URI MUST be an absolute
    // URI" and "MUST NOT include a fragment component".
    if section
        .redirect_uris
        .iter()
        .all(|uri| Url::parse(uri).is_ok_and(|url| url.fragment().is_none()))
    {
        return Ok(());
    }
    Err(ClientError::RedirectUri {
        client_id: section.client_id.clone(),
    })
}

/// Checks that each of the client's `default_acr_values` is an eIDAS level
/// FerroSMART knows (`docs/architecture.md` §13.28); OpenID Connect Dynamic
/// Client Registration 1.0 §2 leaves the values to the server.
fn check_acr(section: &ClientMetadata) -> Result<(), ClientError> {
    if section
        .default_acr_values
        .iter()
        .all(|value| crate::assurance::of_uri(value).is_some())
    {
        return Ok(());
    }
    Err(ClientError::Rule {
        client_id: section.client_id.clone(),
        rule: "`default_acr_values` names a value other than an eIDAS level",
    })
}

/// Checks the client's `post_logout_redirect_uris`: absolute, with no
/// fragment, and only beside the authorization code grant.
fn check_post_logout(
    section: &ClientMetadata,
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

/// Returns the launch URL the client `section` registers, normalized; it
/// needs the authorization code grant an EHR launch continues in.
fn resolve_launch_uri(
    section: &ClientMetadata,
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

/// Returns the JWK Set a confidential asymmetric client registers: by URL
/// or by value, exactly one ("FHIR authorization servers SHALL support
/// registration of client JWKs using both of the following techniques",
/// SMART App Launch 2.2.0, Client Authentication: Asymmetric, Registering a
/// client).
fn keys(section: &ClientMetadata, set: Option<Value>) -> Result<ClientKeys, ClientError> {
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

/// Returns the secret hash a confidential symmetric client registers,
/// checked as `ferrohealth-smart` checks a Basic user's hash: an Argon2id
/// PHC string at the OWASP Password Storage Cheat Sheet floor
/// (`docs/architecture.md` §13.9).
fn secret_hash(
    section: &ClientMetadata,
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

/// A client secret FerroSMART issued, answered once and kept only as its
/// hash (RFC 7591 §3.2.1).
#[derive(Debug)]
pub struct IssuedSecret {
    /// The secret, which the answer carries once.
    pub secret: secrecy::SecretString,
    /// Its Argon2id hash, which the store keeps.
    pub hash: SecretHash,
}

/// Returns a fresh client secret: 32 random bytes, base64url without
/// padding, with its Argon2id hash.
///
/// # Errors
/// Returns [`HashError`] when no random bytes or salt can be drawn or the
/// hash fails.
pub fn issue_secret() -> Result<IssuedSecret, HashError> {
    use base64::Engine as _;
    let mut bytes = [0_u8; 32];
    aws_lc_rs::rand::fill(&mut bytes).map_err(|_unspecified| HashError::Salt)?;
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let hash = SecretHash(hash_secret(&secret)?);
    Ok(IssuedSecret {
        secret: secrecy::SecretString::from(secret),
        hash,
    })
}

/// Returns the Argon2id PHC hash of `secret` at [`HASH_MEMORY_KIB`] and
/// [`HASH_PASSES`], one lane, under a fresh 16-byte salt.
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
    /// No random bytes could be drawn.
    #[error("no random bytes could be drawn")]
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
