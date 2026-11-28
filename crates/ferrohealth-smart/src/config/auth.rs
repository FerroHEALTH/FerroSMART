// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The resolution of the `[auth]` section: every rule checked, every
//! secret read, every issuer's settings built from its own table.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ferrohealth_config::tls::TlsClientSection;
use ferrohealth_secret::secret_url::SecretUrl;

use crate::basic::PasswordStore;
use crate::client::Tls;
use crate::config::AuthMode;
use crate::config::AuthSection;
use crate::config::BasicSection;
use crate::config::ConfigError;
use crate::config::IssuerEntry;
use crate::config::Resolved;
use crate::config::TlsBuilder;
use crate::config::build_tls;
use crate::config::issuer::check_entry;
use crate::config::read::secret;
use crate::config::shown;
use crate::federation::FederationSection;
use crate::federation::person::AttributesSection;
use crate::jws::algorithm::Algorithm;
use crate::kind::IssuerKind;
use crate::party::config::PartySection;
use crate::profile::Profile;
use crate::resource::Settings;
use crate::resource::configuration::SmartOptions;
use crate::resource::configuration::is_capability;
use crate::scope::is_extension_scope;
use crate::scope::is_scope_token;
use crate::sender::proof::DpopSection;

/// The replacement each removed section key names.
impl Resolved {
    /// Returns the discovery document options the section names: its
    /// scopes and its capabilities.
    ///
    /// A product sets what the section cannot know on the result: the
    /// permission capabilities its route table enforces
    /// ([`SmartOptions::permissions`]), whether it advertises `OpenID` Connect
    /// sign-in ([`SmartOptions::openid_connect`]), and the openEHR services
    /// of [`SmartOptions::with_openehr`].
    #[must_use]
    pub fn smart_options(&self) -> SmartOptions {
        SmartOptions {
            scopes_supported: self.scopes_supported.clone(),
            capabilities: self.capabilities.clone(),
            ..SmartOptions::default()
        }
    }

    /// Returns the identifier of the issuer the section names `name`, the
    /// value a product reads a key that names an issuer through.
    ///
    /// # Errors
    ///
    /// [`ConfigError::UnknownIssuer`] naming `key`, `name` and every name
    /// the section carries.
    pub fn issuer_named(&self, key: &'static str, name: &str) -> Result<&str, ConfigError> {
        self.names
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| ConfigError::UnknownIssuer {
                key,
                name: name.to_owned(),
                known: self.names.keys().cloned().collect(),
            })
    }

    /// Returns the identifiers of a product role list, the names of the
    /// issuers a product honours an administrator, emergency or
    /// identifier-reader role from: each must name a `persons` issuer (no
    /// specification governs this: our own design, since only a person
    /// holds such a role).
    ///
    /// # Errors
    ///
    /// [`ConfigError::UnknownIssuer`] for a name the section does not carry,
    /// and [`ConfigError::RoleIssuer`] for one of another kind, each naming
    /// `key`.
    pub fn role_issuers(
        &self,
        key: &'static str,
        names: &[String],
    ) -> Result<Vec<String>, ConfigError> {
        names
            .iter()
            .map(|name| {
                let issuer = self.issuer_named(key, name)?;
                match self.kinds.get(issuer) {
                    Some(&kind) if kind != IssuerKind::Smart => Err(ConfigError::RoleIssuer {
                        key,
                        name: name.clone(),
                        kind,
                    }),
                    _ => Ok(issuer.to_owned()),
                }
            })
            .collect()
    }
}

impl AuthSection {
    /// Returns the `[auth.issuer.<name>]` tables the section names, in name
    /// order.
    pub fn issuers(&self) -> impl Iterator<Item = (&str, &IssuerEntry)> {
        self.issuer
            .iter()
            .map(|(name, entry)| (name.as_str(), entry))
    }

    /// Resolves the section for a product serving `bases`, the audience of
    /// every issuer whose table names none: every rule checked, every
    /// secret read.
    ///
    /// An enabled section with Basic users and no issuer resolves to the
    /// Basic store alone, a Basic-only surface; an enabled section that
    /// admits neither a token nor a Basic user is refused.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] naming the first rule broken: no issuer and
    /// no Basic user, an issuer name outside the name form, no audience, an
    /// issuer outside the URL rule, a symmetric algorithm, a skew over the
    /// bound, a profile or a kind-bound setting refused, a nested table on
    /// an issuer of a kind that takes none, a name no issuer table carries,
    /// a Basic user with a bad hash, user-id or scope, a secret set twice or
    /// not at all, a capability SMART does not define, a listed scope
    /// outside RFC 6749 §3.3, a product scope in no extension form, or a
    /// cache key the random source cannot draw.
    pub fn resolve(&self, bases: &[&str]) -> Result<Resolved, ConfigError> {
        self.resolve_over(None, bases)
    }

    /// Resolves the section as [`AuthSection::resolve`] does, every `tls`
    /// table it holds (`auth.tls` and the `tls` of each introspection grant)
    /// built by `tls`, the product's reader of TLS material.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] as [`AuthSection::resolve`] does, and
    /// [`ConfigError::TlsBuild`] when `tls` refuses a table.
    pub fn resolve_with_tls(
        &self,
        tls: &dyn TlsBuilder,
        bases: &[&str],
    ) -> Result<Resolved, ConfigError> {
        self.resolve_over(Some(tls), bases)
    }

    /// Resolves the section for a product serving `bases`, over the
    /// product's TLS builder when one is handed.
    fn resolve_over(
        &self,
        builder: Option<&dyn TlsBuilder>,
        bases: &[&str],
    ) -> Result<Resolved, ConfigError> {
        if self.post_quantum_only {
            let mut narrowed = self.clone();
            narrowed.narrow_to_ml_dsa()?;
            narrowed.post_quantum_only = false;
            return narrowed.resolve_over(builder, bases);
        }
        self.check_discovery()?;
        let basic_users = self
            .basic
            .as_ref()
            .is_some_and(|section| !section.users.is_empty());
        let tls = Tls {
            presented: match builder {
                Some(builder) => Some(build_tls(
                    builder,
                    "auth.tls",
                    &self.tls,
                    &self.tls_endpoints(),
                )?),
                None if self.tls.names_material() => {
                    return Err(ConfigError::TlsNotBuilt { key: "auth.tls" });
                }
                None => None,
            },
            min_version: self.tls.min_version,
        };
        let mut kinds = BTreeMap::new();
        let mut names = BTreeMap::new();
        let mut issuers = Vec::new();
        let mut party = Vec::new();
        #[cfg(feature = "fetch")]
        let mut introspection = Vec::new();
        if self.enabled {
            self.check_names()?;
            for (name, entry) in self.issuers() {
                let kind = check_entry(entry)?;
                check_nested(entry, kind)?;
                kinds.insert(entry.issuer.expose().to_owned(), kind);
                names.insert(name.to_owned(), entry.issuer.expose().to_owned());
                if let Some(table) = party_of(entry) {
                    party.push(table);
                }
                match entry.mode {
                    AuthMode::Jwt => {
                        let mut settings = settings_of(entry, kind, bases);
                        settings.tls = tls.clone();
                        settings.validate().map_err(|source| ConfigError::Issuer {
                            issuer: shown(&entry.issuer),
                            source: Box::new(source),
                        })?;
                        issuers.push(settings);
                    }
                    #[cfg(feature = "fetch")]
                    AuthMode::Introspection => {
                        introspection.push(introspection_of(entry, kind, builder, bases)?);
                    }
                    #[cfg(not(feature = "fetch"))]
                    AuthMode::Introspection => return Err(ConfigError::IntrospectionUnavailable),
                }
            }
        }
        // NOTE: no specification governs the configuration model: our own
        // design, and a surface that admits no credential at all fails closed.
        if self.enabled && kinds.is_empty() && !basic_users {
            return Err(ConfigError::Missing { key: "auth.issuer" });
        }
        if self.enabled {
            self.check_party(&party)?;
        }
        let basic = self.basic_store()?;
        let dpop = self.dpop_settings()?;
        let mut resolved = Resolved {
            enabled: self.enabled,
            issuers,
            kinds,
            names,
            basic,
            realm: (!self.realm.is_empty()).then(|| self.realm.clone()),
            capabilities: self.capabilities.clone(),
            scopes_supported: self.scopes_supported.clone(),
            described_issuer: None,
            product_scope: (!self.product_scope.is_empty()).then(|| self.product_scope.clone()),
            dpop,
            #[cfg(feature = "fetch")]
            introspection,
            party,
        };
        if let Some(name) = &self.described_issuer {
            let issuer = resolved.issuer_named("auth.described_issuer", name)?;
            resolved.described_issuer = Some(SecretUrl::new(issuer));
        }
        Ok(resolved)
    }

    /// Narrows the signature algorithms of the section to ML-DSA (RFC 9964
    /// §5) for `post_quantum_only`.
    ///
    /// A list at its default becomes [`crate::jws::algorithm::ML_DSA`], an
    /// ML-DSA list stays, and
    /// a list naming any other algorithm is refused. An issuer under
    /// `mode = "introspection"` keeps its list, since its authorization
    /// server checks its tokens.
    fn narrow_to_ml_dsa(&mut self) -> Result<(), ConfigError> {
        let issuer_default = IssuerEntry::default().algorithms;
        for (name, entry) in &mut self.issuer {
            if entry.mode == AuthMode::Introspection {
                continue;
            }
            narrow(&mut entry.algorithms, &issuer_default, || {
                format!("auth.issuer.{name}.algorithms")
            })?;
        }
        if let Some(dpop) = &mut self.dpop {
            narrow(
                &mut dpop.algorithms,
                &DpopSection::default().algorithms,
                || String::from("auth.dpop.algorithms"),
            )?;
        }
        Ok(())
    }

    /// Returns the endpoints `auth.tls` reaches from the start, which its
    /// builder clears for revocation at once; a key set or other endpoint
    /// the metadata names is cleared before its first connection.
    fn tls_endpoints(&self) -> Vec<url::Url> {
        // NOTE: no specification governs which endpoints are cleared at once: each issuer
        // (resolve refuses a malformed one).
        self.issuers()
            .filter_map(|(_, entry)| url::Url::parse(entry.issuer.expose()).ok())
            .collect()
    }

    /// Refuses a capability SMART does not define, a listed scope outside
    /// RFC 6749 §3.3, and a product scope in no extension form.
    fn check_discovery(&self) -> Result<(), ConfigError> {
        if let Some(bad) = self
            .capabilities
            .iter()
            .find(|capability| !is_capability(capability))
        {
            return Err(ConfigError::Capability {
                capability: bad.clone(),
            });
        }
        if let Some(bad) = self
            .scopes_supported
            .iter()
            .find(|scope| !is_scope_token(scope))
        {
            return Err(ConfigError::Scope { scope: bad.clone() });
        }
        if !self.product_scope.is_empty() && !is_extension_scope(&self.product_scope) {
            return Err(ConfigError::ProductScope {
                scope: self.product_scope.clone(),
            });
        }
        Ok(())
    }

    /// Refuses an issuer name outside the name form, and two tables naming
    /// one issuer: the resource server holds one table per issuer
    /// identifier, so the later would silently replace the earlier (no
    /// specification governs the configuration model: our own design; the
    /// name form keeps every name addressable from the environment).
    fn check_names(&self) -> Result<(), ConfigError> {
        let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
        for (name, entry) in self.issuers() {
            if !is_issuer_name(name) {
                return Err(ConfigError::IssuerName {
                    name: name.to_owned(),
                });
            }
            if let Some(first) = seen.insert(entry.issuer.expose(), name) {
                return Err(ConfigError::DuplicateIssuer {
                    key: "auth.issuer",
                    issuer: shown(&entry.issuer),
                    first: first.to_owned(),
                    second: name.to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Refuses a party table that shares its `identifier_issuer` with
    /// another, or whose issuer's profile breaks a binding rule (no
    /// specification governs this: our own design).
    fn check_party(&self, party: &[PartySection]) -> Result<(), ConfigError> {
        let kinds = self
            .issuers()
            .filter(|(_, entry)| entry.party.is_some())
            .map(|(_, entry)| Ok((entry.issuer.expose(), check_entry(entry)?)))
            .collect::<Result<Vec<_>, ConfigError>>()?;
        crate::party::config::check_tables(party, |issuer| {
            kinds
                .iter()
                .find(|(named, _)| *named == issuer)
                .map(|(_, kind)| *kind)
        })
        .map_err(|source| ConfigError::Party { source })
    }

    /// Returns the `[auth.dpop]` table checked, when the section has one.
    fn dpop_settings(&self) -> Result<Option<DpopSection>, ConfigError> {
        let Some(section) = &self.dpop else {
            return Ok(None);
        };
        section
            .validate()
            .map_err(|source| ConfigError::Dpop { source })?;
        Ok(Some(section.clone()))
    }

    /// Returns the Basic store of `[auth.basic]`, when the section has one.
    fn basic_store(&self) -> Result<Option<PasswordStore>, ConfigError> {
        let Some(section) = &self.basic else {
            return Ok(None);
        };
        let mut store = PasswordStore::new();
        for user in &section.users {
            let hash = secret(
                user.password_hash.as_ref(),
                user.password_hash_file.as_deref(),
                "auth.basic.users.password_hash",
            )?;
            store = store
                .with_user(user.user.clone(), hash)
                .map_err(|source| ConfigError::Basic { source })?;
        }
        store
            .with_cache(section.cache_ttl.get())
            .map(Some)
            .map_err(|source| ConfigError::Basic { source })
    }
}

/// Returns the settings of the JWT issuer `entry`, an issuer of `kind`, for
/// a product serving `bases`.
fn settings_of(entry: &IssuerEntry, kind: IssuerKind, bases: &[&str]) -> Settings {
    let mut settings = Settings::new(entry.issuer.expose(), String::new(), kind);
    settings.audience = audience_of(entry, bases);
    settings.algorithms.clone_from(&entry.algorithms);
    settings.profile = profile_of(entry);
    settings.clock_skew = entry.clock_skew.get();
    settings.jwks_max_age = entry.jwks_max_age.get();
    settings.jwks_refresh_interval = entry.jwks_refresh_interval.get();
    settings.jwks_file = (!entry.jwks_file.is_empty()).then(|| PathBuf::from(&entry.jwks_file));
    settings.timeout = entry.timeout.get();
    settings.role_claims = role_claims_of(entry, kind);
    settings.assurance.clone_from(&entry.assurance);
    settings.federation = federation_of(entry);
    settings.attributes = attributes_of(entry);
    settings.sender_constraint = entry.sender_constraint;
    settings
}

/// Returns the introspection settings of the `mode = "introspection"`
/// issuer `entry`, an issuer of `kind`.
#[cfg(feature = "fetch")]
fn introspection_of(
    entry: &IssuerEntry,
    kind: IssuerKind,
    builder: Option<&dyn TlsBuilder>,
    bases: &[&str],
) -> Result<crate::resource::introspection::IntrospectionSettings, ConfigError> {
    use crate::resource::introspection::IntrospectionAuth;
    use crate::resource::introspection::IntrospectionError;
    use crate::resource::introspection::IntrospectionSettings;
    if !entry.jwks_file.is_empty() {
        return Err(ConfigError::Exclusive {
            left: "auth.issuer.mode = \"introspection\"",
            right: "auth.issuer.jwks_file",
        });
    }
    let section = entry.introspection.as_ref().ok_or(ConfigError::Missing {
        key: "auth.issuer.introspection",
    })?;
    let auth = match (&section.client, &section.bearer) {
        (Some(_), Some(_)) => {
            return Err(ConfigError::Exclusive {
                left: "auth.issuer.introspection.client",
                right: "auth.issuer.introspection.bearer",
            });
        }
        (None, None) => {
            return Err(ConfigError::Missing {
                key: "auth.issuer.introspection.client or auth.issuer.introspection.bearer",
            });
        }
        (Some(client), None) => {
            let mut client = client.clone();
            if client.issuer.is_empty() && client.token_endpoint.is_empty() {
                client.issuer.clone_from(&entry.issuer);
            }
            let credentials = match builder {
                Some(builder) => client.resolve_with_tls(builder)?,
                None => client.resolve()?,
            };
            IntrospectionAuth::Client(Box::new(credentials))
        }
        (None, Some(bearer)) => {
            let grant = match builder {
                Some(builder) => bearer.resolve_with_tls(builder)?,
                None => bearer.resolve()?,
            };
            let source = crate::client::cache::TokenSource::new(grant).map_err(|source| {
                ConfigError::Introspection {
                    source: Box::new(IntrospectionError::Credential {
                        source: std::sync::Arc::new(source),
                    }),
                }
            })?;
            IntrospectionAuth::Bearer(source)
        }
    };
    let mut settings = IntrospectionSettings::new(entry.issuer.expose(), String::new(), auth, kind);
    settings.audience = audience_of(entry, bases);
    if !section.endpoint.is_empty() {
        settings.endpoint = Some(crate::config::read::parse_url(
            section.endpoint.expose(),
            "auth.issuer.introspection.endpoint",
        )?);
    }
    settings.clock_skew = entry.clock_skew.get();
    settings.cache_max_age = section.cache_max_age.get();
    settings.cache_capacity = section.cache_capacity;
    settings.timeout = entry.timeout.get();
    settings.role_claims = role_claims_of(entry, kind);
    settings.profile = profile_of(entry);
    settings.assurance.clone_from(&entry.assurance);
    settings.federation = federation_of(entry);
    settings.attributes = attributes_of(entry);
    settings.sender_constraint = entry.sender_constraint;
    settings
        .validate()
        .map_err(|source| ConfigError::Introspection {
            source: Box::new(source),
        })?;
    Ok(settings)
}

/// Returns the audience of `entry`: its own, or the product's `bases` when
/// it names none.
fn audience_of(entry: &IssuerEntry, bases: &[&str]) -> Vec<String> {
    if entry.audience.is_empty() {
        bases.iter().map(|base| (*base).to_owned()).collect()
    } else {
        entry.audience.clone()
    }
}

/// Refuses a nested table on an issuer of a kind that takes none: a
/// `federation` issuer requires its federation table and takes no
/// attributes table (no specification governs this: our own design). The
/// party table's rules are [`AuthSection`]'s.
fn check_nested(entry: &IssuerEntry, kind: IssuerKind) -> Result<(), ConfigError> {
    let issuer = || shown(&entry.issuer);
    match (kind, &entry.federation) {
        (IssuerKind::Federation, None) => {
            return Err(ConfigError::Federation {
                issuer: issuer(),
                reason: "a federation issuer needs its federation table",
            });
        }
        (IssuerKind::Federation, Some(_)) | (_, None) => {}
        (_, Some(_)) => {
            return Err(ConfigError::Federation {
                issuer: issuer(),
                reason: "only a federation issuer takes a federation table",
            });
        }
    }
    if entry.attributes.is_some() && kind == IssuerKind::Federation {
        return Err(ConfigError::Attributes {
            issuer: issuer(),
            reason: "a federation issuer takes no attributes table",
        });
    }
    Ok(())
}

/// Returns the attributes table of `entry`, attributed to its issuer.
fn attributes_of(entry: &IssuerEntry) -> Option<AttributesSection> {
    entry.attributes.clone().map(|table| AttributesSection {
        issuer: entry.issuer.clone(),
        ..table
    })
}

/// Returns the federation table of `entry`, attributed to its issuer.
fn federation_of(entry: &IssuerEntry) -> Option<FederationSection> {
    entry.federation.clone().map(|table| FederationSection {
        issuer: entry.issuer.clone(),
        ..table
    })
}

/// Returns the party table of `entry`, attributed to its issuer, with the
/// issuer's identifier as its `identifier_issuer` and `pairwise` as its
/// `identifier_type` where it names none.
fn party_of(entry: &IssuerEntry) -> Option<PartySection> {
    let table = entry.party.as_ref()?;
    let mut table = PartySection {
        issuer: entry.issuer.clone(),
        ..table.clone()
    };
    if table.identifier_issuer.is_empty() {
        entry
            .issuer
            .expose()
            .clone_into(&mut table.identifier_issuer);
    }
    // NOTE: docs/architecture.md §13.6 item 9: FerroSMART's `sub` is a pairwise
    // subject, compared exactly.
    if table.identifier_type.is_empty() {
        table.identifier_type = String::from("pairwise");
    }
    Some(table)
}

/// Returns whether `name` is an issuer name: a lower-case ASCII letter, then
/// lower-case letters, digits and `_`, at most 64 bytes.
fn is_issuer_name(name: &str) -> bool {
    name.len() <= 64
        && name
            .bytes()
            .next()
            .is_some_and(|first| first.is_ascii_lowercase())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Returns the profile of `entry`: its `profile` table over the defaults.
fn profile_of(entry: &IssuerEntry) -> Profile {
    Profile::default().with_keys(entry.profile.clone())
}

/// Returns the role claims of `entry`: its own, or the RFC 9068 §2.2.3.1
/// defaults; none for a `federation` issuer.
fn role_claims_of(entry: &IssuerEntry, kind: IssuerKind) -> Vec<String> {
    match (&entry.role_claims, kind) {
        (Some(claims), _) => claims.clone(),
        (None, IssuerKind::Federation) => Vec::new(),
        (None, _) => crate::roles::default_claims(),
    }
}

impl Default for AuthSection {
    fn default() -> Self {
        Self {
            enabled: true,
            issuer: BTreeMap::new(),
            realm: String::new(),
            capabilities: Vec::new(),
            scopes_supported: Vec::new(),
            described_issuer: None,
            product_scope: String::new(),
            basic: None,
            dpop: None,
            tls: TlsClientSection::default(),
            post_quantum_only: false,
        }
    }
}

impl Default for BasicSection {
    fn default() -> Self {
        Self {
            users: Vec::new(),
            // NOTE: no specification governs the cache: our own design, safe on
            // by default because the user list changes only at a restart.
            cache_ttl: ferrohealth_config::units::Duration::from_mins(5),
        }
    }
}

/// Replaces `list` with [`crate::jws::algorithm::ML_DSA`] when it equals
/// `default`, and refuses it
/// under `key` when it names an algorithm that is no ML-DSA parameter set.
fn narrow(
    list: &mut Vec<Algorithm>,
    default: &[Algorithm],
    key: impl FnOnce() -> String,
) -> Result<(), ConfigError> {
    if list.as_slice() == default {
        *list = crate::jws::algorithm::ML_DSA.to_vec();
        return Ok(());
    }
    match list.iter().find(|algorithm| !algorithm.is_ml_dsa()) {
        Some(algorithm) => Err(ConfigError::ClassicalAlgorithm {
            key: key(),
            algorithm: *algorithm,
        }),
        None => Ok(()),
    }
}
