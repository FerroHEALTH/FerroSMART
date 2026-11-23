// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The checked settings the server runs on, resolved from [`Config`].

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ferrohealth_secret::file::require_secret;
use ferrohealth_server::section::ServerSection;
use ferrohealth_smart::client::assertion::AssertionKey;
use ferrohealth_smart::client::keys::KeyRing;
use ferrohealth_smart::client::outbound::OutboundClient;
use ferrohealth_smart::config::ServerTls;
use ihe_atna::atna::feed::FeedRepository;
use ihe_atna::balp::{NetworkAddress, Observer, SOURCE_SECURITY_SERVER};
use jsonwebtoken::Algorithm;
use secrecy::SecretString;
use url::Url;

use crate::upstream::{
    AssertionKeys, Authentication, Effective, OidcSection, OidcUpstream, PrivateKeyJwtSection,
    Protocol, Upstream, UpstreamSection,
};

use crate::config::error::Error;
use crate::config::{AuditSection, BrandingSection, Config, KeysSection, SigningKeysSection};
use crate::signing::SigningKeys;
use crate::store::signing::Schedule;

/// The settings the server runs on.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The `[server]` section.
    pub server: ServerSection,
    /// The issuer identifier exactly as configured, which every document
    /// repeats, since a client holds the `issuer` it reads "identical" to
    /// the one it was configured with (RFC 8414 §3.3).
    pub issuer: String,
    /// The issuer identifier as a URL, for its path.
    pub issuer_url: Url,
    /// How long an access token lives.
    pub access_token_lifetime: Duration,
    /// How long an `offline_access` refresh token lasts unused.
    pub refresh_idle: Duration,
    /// How long an `online_access` refresh token lasts unused.
    pub online_idle: Duration,
    /// The keys that sign every token, in rotation.
    pub keys: Arc<SigningKeys>,
    /// The connection URL of the database.
    pub database_url: SecretString,
    /// The most connections one replica holds.
    pub max_connections: u32,
    /// The base URLs of the resource servers, each as configured.
    pub resources: Vec<String>,
    /// The base URLs among them that serve openEHR.
    pub openehr_resources: Vec<String>,
    /// The subject namespace of each openEHR base that names one.
    pub subject_namespaces: BTreeMap<String, String>,
    /// The FHIR base each openEHR base that names one is paired with.
    pub pairings: BTreeMap<String, Pairing>,
    /// The purposes of use each openEHR base that names any accepts.
    pub purposes: BTreeMap<String, Purposes>,
    /// The `fhirUser` lookups of each FHIR base that names any
    /// (`docs/architecture.md` §13.6 item 9).
    pub fhir_user_lookups: BTreeMap<String, Vec<crate::config::FhirUserLookupSection>>,
    /// The upstream providers people log in at, in configuration order.
    pub upstreams: Vec<Upstream>,
    /// FerroSMART as a SAML 2.0 service provider, when `[ferrosmart.saml]`
    /// is set.
    pub saml: Option<Arc<crate::upstream::saml::ServiceProviderSettings>>,
    /// The scopes each role may be granted.
    pub roles: BTreeMap<String, Vec<String>>,
    /// The deployment's name.
    pub name: String,
    /// The deployment's words on the pages.
    pub branding: BrandingSection,
    /// The scopes an app that registered itself may be granted at most,
    /// when the deployment lets apps register themselves.
    pub registration: Option<Vec<String>>,
    /// The User Access Brands Bundle, when the deployment publishes one.
    pub brand: Option<crate::brands::Brands>,
    /// Where every login and token is recorded.
    pub audit: AuditSettings,
}

/// The audit lane, resolved from `[ferrosmart.audit]`.
#[derive(Debug, Clone)]
pub struct AuditSettings {
    /// The Audit Record Repository's FHIR Feed, when the records are
    /// forwarded.
    pub feed: Option<FeedRepository>,
    /// FerroSMART as the recording system.
    pub observer: Observer,
}

impl Settings {
    /// Returns the absolute URL of the endpoint at `route` under the issuer,
    /// as the metadata names it (SMART App Launch 2.2.0, Conformance: "All
    /// endpoint URLs in the response document SHALL be absolute URLs").
    #[must_use]
    pub fn endpoint(&self, route: &str) -> String {
        format!("{}{route}", self.issuer.trim_end_matches('/'))
    }

    /// Returns [`Settings::endpoint`] as a URL.
    #[must_use]
    pub fn endpoint_url(&self, route: &str) -> Url {
        let mut url = self.issuer_url.clone();
        let path = format!("{}{route}", self.issuer_url.path().trim_end_matches('/'));
        url.set_path(&path);
        url
    }

    /// Returns the path of the RFC 8414 §3 metadata: the well-known suffix
    /// inserted between the host and the issuer's path.
    #[must_use]
    pub fn metadata_path(&self) -> String {
        format!(
            "/.well-known/oauth-authorization-server{}",
            self.issuer_url.path().trim_end_matches('/')
        )
    }
}

impl Config {
    /// Resolves the tree into the [`Settings`] the server runs on, reading
    /// the key files.
    ///
    /// # Errors
    /// Returns [`Error`] naming the first key the server cannot run with.
    pub fn resolve(&self) -> Result<Settings, Error> {
        let section = &self.ferrosmart;
        if section.issuer.is_empty() {
            return Err(Error::Missing {
                key: "ferrosmart.issuer",
            });
        }
        let issuer = ferrohealth_smart::metadata::issuer_url(&section.issuer)
            .map_err(|source| Error::Issuer { source })?;
        // NOTE: RFC 8414 §3, the metadata of an issuer with a path sits beside that
        // path, so the issuer's path is the one the routes are served under.
        if issuer.path().trim_end_matches('/') != self.server.base_path.as_str() {
            return Err(Error::IssuerPath);
        }
        if section.access_token_lifetime.is_zero() {
            return Err(Error::Zero {
                key: "ferrosmart.access_token_lifetime",
            });
        }
        // NOTE: SMART App Launch 2.2.0, App Launch, Response, access tokens SHOULD
        // have a valid lifetime no greater than one hour.
        if section.access_token_lifetime.get() > Duration::from_secs(3600) {
            return Err(Error::LongLifetime);
        }
        if section.refresh_idle.is_zero() {
            return Err(Error::Zero {
                key: "ferrosmart.refresh_idle",
            });
        }
        if section.online_idle.is_zero() {
            return Err(Error::Zero {
                key: "ferrosmart.online_idle",
            });
        }
        if section.database.max_connections == 0 {
            return Err(Error::Zero {
                key: "ferrosmart.database.max_connections",
            });
        }
        let database_url: SecretString = require_secret(
            "ferrosmart.database.url",
            section
                .database
                .url
                .as_ref()
                .map(ferrohealth_secret::secret::Secret::to_secret_string),
            section.database.url_file.as_deref(),
        )?;
        let keys = Arc::new(signing_keys(
            &section.keys,
            section.access_token_lifetime.get(),
        )?);
        Ok(Settings {
            server: self.server.clone(),
            issuer: section.issuer.clone(),
            issuer_url: issuer.clone(),
            access_token_lifetime: section.access_token_lifetime.get(),
            refresh_idle: section.refresh_idle.get(),
            online_idle: section.online_idle.get(),
            keys: Arc::clone(&keys),
            database_url,
            max_connections: section.database.max_connections,
            resources: resources(&section.resource)?,
            openehr_resources: section
                .resource
                .iter()
                .filter(|resource| resource.kind == crate::config::ResourceKind::Openehr)
                .map(|resource| resource.base.clone())
                .collect(),
            subject_namespaces: subject_namespaces(&section.resource)?,
            pairings: pairings(&section.resource)?,
            purposes: purposes(&section.resource)?,
            fhir_user_lookups: fhir_user_lookups(&section.resource)?,
            upstreams: upstreams(&section.upstream, &keys, section.assurance_minimum)?,
            saml: service_provider(section)?,
            roles: roles(&section.role)?,
            name: section.name.clone(),
            branding: branding(&section.branding)?,
            registration: registration(&section.registration)?,
            brand: section
                .brand
                .as_ref()
                .map(|brand| {
                    let fhir: Vec<String> = section
                        .resource
                        .iter()
                        .filter(|resource| resource.kind == crate::config::ResourceKind::Fhir)
                        .map(|resource| resource.base.clone())
                        .collect();
                    let bundle = format!(
                        "{}{}",
                        section.issuer.trim_end_matches('/'),
                        crate::brands::BRANDS_ROUTE
                    );
                    let mut brand = brand.clone();
                    if brand.name.trim().is_empty() {
                        brand.name.clone_from(&section.name);
                    }
                    crate::brands::Brands::resolve(&brand, &fhir, &bundle)
                })
                .transpose()?,
            audit: audit(&section.audit, &issuer)?,
        })
    }
}

/// Returns the audit lane `section` describes for the server at `issuer`.
fn audit(section: &AuditSection, issuer: &Url) -> Result<AuditSettings, Error> {
    let feed = section
        .feed
        .as_ref()
        .map(|endpoint| {
            let client = OutboundClient::build(endpoint, "ferrosmart.audit.feed", &ServerTls)
                .map_err(|source| Error::AuditFeed { source })?;
            let base = client.url().clone();
            let between_rounds = Duration::from(client.retry().max_backoff);
            FeedRepository::new(
                &base,
                Arc::new(crate::audit_feed::OutboundFeed(client)),
                between_rounds,
            )
            .map_err(|source| Error::AuditBase { source })
        })
        .transpose()?;
    let host = issuer.host_str().unwrap_or_default().to_owned();
    let source_id = if section.source_id.is_empty() {
        host.clone()
    } else {
        section.source_id.clone()
    };
    Ok(AuditSettings {
        feed,
        // NOTE: FHIR R4 security-source-type, 6 "Security Server": the system
        // that authenticates people and issues tokens.
        observer: Observer {
            source_id,
            site: section.site.clone(),
            host: NetworkAddress::host(&host),
            source_types: vec![SOURCE_SECURITY_SERVER],
        },
    })
}

/// Returns `section` once its style URL holds: empty, or an https URL.
fn branding(section: &BrandingSection) -> Result<BrandingSection, Error> {
    let style = &section.smart_style_url;
    // NOTE: SMART App Launch 2.2.0, App Launch, Styling: the app downloads the
    // document `smart_style_url` names, so it is an absolute https URL.
    if !style.is_empty() && Url::parse(style).map_or(true, |url| url.scheme() != "https") {
        return Err(Error::StyleUrl);
    }
    Ok(section.clone())
}

/// Returns the ceiling of an app that registers itself, when `section`
/// opens the registration endpoint: scope tokens that are neither `user/` nor
/// `system/`, since professional and backend apps are an administrator's to
/// register (RFC 7591 §5 keeps an app's own metadata self-asserted).
fn registration(
    section: &crate::config::RegistrationSection,
) -> Result<Option<Vec<String>>, Error> {
    if !section.open {
        return Ok(None);
    }
    let rule = |rule| Error::Registration { rule };
    let scopes: Vec<String> = section
        .scope
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    if scopes.is_empty() {
        return Err(rule("an open registration names its `scope`"));
    }
    if scopes
        .iter()
        .any(|scope| !ferrohealth_smart::scope::is_scope_token(scope))
    {
        return Err(rule(
            "`scope` holds a value outside the RFC 6749 §3.3 character set",
        ));
    }
    if scopes
        .iter()
        .any(|scope| scope.starts_with("user/") || scope.starts_with("system/"))
    {
        return Err(rule("`scope` holds a `user/` or `system/` scope"));
    }
    Ok(Some(scopes))
}

/// The configuration keys of one ring's three files, for its errors.
struct RingNames {
    /// The current key's file.
    current: &'static str,
    /// The previous key's file.
    previous: &'static str,
    /// The next key's file.
    next: &'static str,
}

/// The names of `[ferrosmart.upstream.oidc.private_key_jwt.keys]`, the ring that
/// signs client assertions to the upstream provider.
const ASSERTION_KEYS: RingNames = RingNames {
    current: "ferrosmart.upstream.oidc.private_key_jwt.keys.private_key_file",
    previous: "ferrosmart.upstream.oidc.private_key_jwt.keys.previous_private_key_file",
    next: "ferrosmart.upstream.oidc.private_key_jwt.keys.next_private_key_file",
};

/// Returns the signing keys `section` names, rotating so a key is published
/// a JWK Set cache lifetime before it signs and stays published for the
/// longest token it signed after that (`docs/architecture.md` §13.11).
fn signing_keys(
    section: &SigningKeysSection,
    access_token_lifetime: Duration,
) -> Result<SigningKeys, Error> {
    const KEY: &str = "ferrosmart.keys.private_key_files";
    let mut pool: Vec<AssertionKey> = Vec::with_capacity(section.private_key_files.len());
    for path in &section.private_key_files {
        let key = read_key(KEY, path, None, Algorithm::RS256)?;
        if pool.iter().any(|other| other.kid() == key.kid()) {
            return Err(Error::RepeatedKey {
                kid: key.kid().to_owned(),
            });
        }
        pool.push(key);
    }
    let lead = crate::server::JWKS_MAX_AGE.saturating_add(crate::signing::REFRESH_INTERVAL);
    let schedule = Schedule {
        period: section.rotation_period.get(),
        lead,
        retirement: lead.saturating_add(access_token_lifetime),
    };
    if schedule.period < schedule.retirement {
        return Err(Error::RotationPeriod {
            shortest: schedule.retirement,
        });
    }
    SigningKeys::new(pool, schedule).map_err(|_empty| Error::Missing { key: KEY })
}

/// Returns the ring `keys` names: the current key, the previous one for its
/// overlap and the next one, each read to sign with `algorithm`.
fn key_ring(keys: &KeysSection, names: &RingNames, algorithm: Algorithm) -> Result<KeyRing, Error> {
    let path = keys
        .private_key_file
        .as_deref()
        .ok_or(Error::Missing { key: names.current })?;
    let kid = (!keys.kid.is_empty()).then(|| keys.kid.clone());
    let mut ring = KeyRing::new(read_key(names.current, path, kid, algorithm)?);
    if let Some(path) = keys.previous_private_key_file.as_deref() {
        let previous = read_key(names.previous, path, None, algorithm)?;
        ring = if keys.previous_key_overlap.is_zero() {
            ring.with_previous_until_removed(previous)
        } else {
            ring.with_previous_for(previous, keys.previous_key_overlap.get())
        }
        .map_err(|source| Error::KeyRing { source })?;
    }
    if let Some(path) = keys.next_private_key_file.as_deref() {
        let next = read_key(names.next, path, None, algorithm)?;
        ring = ring
            .with_next(next)
            .map_err(|source| Error::KeyRing { source })?;
    }
    Ok(ring)
}

/// Reads the key at `path`, which `key` names, to sign with `algorithm`.
fn read_key(
    key: &'static str,
    path: &Path,
    kid: Option<String>,
    algorithm: Algorithm,
) -> Result<AssertionKey, Error> {
    let pem = std::fs::read(path).map_err(|source| Error::KeyFile {
        key,
        path: path.to_owned(),
        source,
    })?;
    AssertionKey::from_pem(&pem, Some(algorithm), kid).map_err(|source| Error::Key { key, source })
}

/// Returns the base URLs `sections` configure: at least one, each an
/// absolute `https` URL (a loopback host may be `http`) with no query and
/// no fragment, none twice.
fn resources(sections: &[crate::config::ResourceSection]) -> Result<Vec<String>, Error> {
    if sections.is_empty() {
        return Err(Error::Resource {
            rule: "at least one resource server is configured",
        });
    }
    let mut bases: Vec<String> = Vec::with_capacity(sections.len());
    for section in sections {
        // NOTE: SMART App Launch 2.2.0, the `aud` is the "URL of the EHR resource
        // server"; the loopback exception is the one `issuer_url` makes.
        ferrohealth_smart::metadata::issuer_url(&section.base)
            .map_err(|source| Error::ResourceBase { source })?;
        if bases.contains(&section.base) {
            return Err(Error::Resource {
                rule: "a base is configured twice",
            });
        }
        bases.push(section.base.clone());
    }
    Ok(bases)
}

/// Returns the subject namespace of each openEHR base in `sections` that
/// names one.
fn subject_namespaces(
    sections: &[crate::config::ResourceSection],
) -> Result<BTreeMap<String, String>, Error> {
    let mut namespaces = BTreeMap::new();
    for section in sections {
        let Some(namespace) = &section.subject_namespace else {
            continue;
        };
        // NOTE: openEHR ITS-REST 1.1.0, ehr_get_by_subject, the namespace is matched
        // against `EHR_STATUS.subject`, which only an openEHR server holds.
        if section.kind != crate::config::ResourceKind::Openehr {
            return Err(Error::Resource {
                rule: "a `subject_namespace` is for an openEHR base",
            });
        }
        if namespace.trim().is_empty() {
            return Err(Error::Resource {
                rule: "a `subject_namespace` is not empty",
            });
        }
        namespaces.insert(section.base.clone(), namespace.clone());
    }
    Ok(namespaces)
}

/// Returns the `fhirUser` lookups of each FHIR base in `sections` that names
/// any, each with a claim and an absolute URI as its system.
fn fhir_user_lookups(
    sections: &[crate::config::ResourceSection],
) -> Result<BTreeMap<String, Vec<crate::config::FhirUserLookupSection>>, Error> {
    let mut lookups = BTreeMap::new();
    for section in sections
        .iter()
        .filter(|section| !section.fhir_user_lookup.is_empty())
    {
        if section.kind != crate::config::ResourceKind::Fhir {
            return Err(Error::Resource {
                rule: "a `fhir_user_lookup` is for a FHIR base",
            });
        }
        for lookup in &section.fhir_user_lookup {
            if lookup.claim.trim().is_empty() {
                return Err(Error::Resource {
                    rule: "a `fhir_user_lookup` names its `claim`",
                });
            }
            // NOTE: FHIR R4 Identifier.system is a uri, "an absolute URI".
            if Url::parse(&lookup.system).is_err() {
                return Err(Error::Resource {
                    rule: "a `fhir_user_lookup` `system` is an absolute URI",
                });
            }
        }
        lookups.insert(section.base.clone(), section.fhir_user_lookup.clone());
    }
    Ok(lookups)
}

/// The FHIR server an openEHR base is paired with, and how one of its
/// patients names their EHR's subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pairing {
    /// The FHIR base, one of the configured FHIR resource servers.
    pub fhir_base: String,
    /// The `system` of the `Patient.identifier` that carries the subject id.
    pub subject_system: String,
}

/// Returns the pairing of each openEHR base in `sections` that names a
/// `fhir_base`.
fn pairings(
    sections: &[crate::config::ResourceSection],
) -> Result<BTreeMap<String, Pairing>, Error> {
    let refuse = |rule| Err(Error::Resource { rule });
    let mut pairings = BTreeMap::new();
    for section in sections {
        let (fhir_base, subject_system) = match (&section.fhir_base, &section.subject_system) {
            (None, None) => continue,
            (Some(fhir_base), Some(subject_system)) => (fhir_base, subject_system),
            _ => return refuse("`fhir_base` and `subject_system` are set together"),
        };
        // NOTE: SMART on openEHR draft, Service Discovery, `org.fhir.rest` is the FHIR
        // API of a platform whose required service is `org.openehr.rest`.
        if section.kind != crate::config::ResourceKind::Openehr {
            return refuse("a `fhir_base` is for an openEHR base");
        }
        // NOTE: openEHR ITS-REST 1.1.0, ehr_get_by_subject, the EHR is looked up by
        // a subject id and its namespace, so a paired base names the namespace.
        if section.subject_namespace.is_none() {
            return refuse("a base with a `fhir_base` names its `subject_namespace`");
        }
        let fhir = sections.iter().any(|other| {
            other.kind == crate::config::ResourceKind::Fhir && &other.base == fhir_base
        });
        if !fhir {
            return refuse("a `fhir_base` is a configured FHIR `ferrosmart.resource` base");
        }
        if subject_system.trim().is_empty() {
            return refuse("a `subject_system` is not empty");
        }
        pairings.insert(
            section.base.clone(),
            Pairing {
                fhir_base: fhir_base.clone(),
                subject_system: subject_system.clone(),
            },
        );
    }
    Ok(pairings)
}

/// The purposes of use an openEHR base accepts, and their header.
///
/// A professional's picker lookup declares one in the header. No
/// specification governs a picker's purpose: our own design, as FerroEHR
/// reads it (`docs/architecture.md` §13.6 item 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Purposes {
    /// The header.
    pub header: http::HeaderName,
    /// The purposes, in configuration order, each code once.
    pub codes: Vec<PurposeOfUse>,
}

impl Purposes {
    /// Returns the purpose whose code is `code`.
    #[must_use]
    pub fn get(&self, code: &str) -> Option<&PurposeOfUse> {
        self.codes.iter().find(|purpose| purpose.code == code)
    }
}

/// One purpose of use an openEHR base accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurposeOfUse {
    /// The code, the header's value.
    pub code: String,
    /// The code system.
    pub system: String,
    /// The words the picker page shows.
    pub display: String,
}

/// The header a purpose is declared in when the table names none, the one
/// FerroEHR reads by default (its `[audit] purpose_header`).
const PURPOSE_HEADER: &str = "x-purpose-of-use";

/// Returns the purposes of each openEHR base in `sections` that names any.
fn purposes(
    sections: &[crate::config::ResourceSection],
) -> Result<BTreeMap<String, Purposes>, Error> {
    let refuse = |rule| Err(Error::Resource { rule });
    let mut purposes = BTreeMap::new();
    for section in sections {
        if section.purpose.is_empty() {
            if section.purpose_header.is_some() {
                return refuse("a `purpose_header` comes with `purpose` tables");
            }
            continue;
        }
        if section.kind != crate::config::ResourceKind::Openehr {
            return refuse("a `purpose` is for an openEHR base");
        }
        let header = section.purpose_header.as_deref().unwrap_or(PURPOSE_HEADER);
        // NOTE: RFC 9110 §5.1, a field name is a token.
        let Ok(header) = http::HeaderName::try_from(header) else {
            return refuse("a `purpose_header` is a header name");
        };
        let mut codes: Vec<PurposeOfUse> = Vec::with_capacity(section.purpose.len());
        for purpose in &section.purpose {
            // NOTE: RFC 9110 §5.5, a field value of visible characters; a comma would
            // split it into a list (§5.6.1), so a code carries none.
            let visible = purpose
                .code
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b',');
            if purpose.code.is_empty() || !visible {
                return refuse("a `purpose` `code` is visible ASCII with no comma");
            }
            if codes.iter().any(|known| known.code == purpose.code) {
                return refuse("a `purpose` `code` is configured once per base");
            }
            // NOTE: FHIR R4 Coding.system is a uri, "an absolute URI".
            if Url::parse(&purpose.system).is_err() {
                return refuse("a `purpose` `system` is an absolute URI");
            }
            if purpose.display.trim().is_empty() {
                return refuse("a `purpose` names its `display`");
            }
            codes.push(PurposeOfUse {
                code: purpose.code.clone(),
                system: purpose.system.clone(),
                display: purpose.display.clone(),
            });
        }
        purposes.insert(section.base.clone(), Purposes { header, codes });
    }
    Ok(purposes)
}

/// Returns the providers `sections` name, each by a name of its own and an
/// issuer of its own (OpenID Connect Discovery 1.0 §4.3 holds each issuer
/// to its metadata), checking each assertion ring against `keys` and each
/// provider's assurance against the deployment's `floor`.
fn upstreams(
    sections: &[UpstreamSection],
    keys: &SigningKeys,
    floor: crate::assurance::Floor,
) -> Result<Vec<Upstream>, Error> {
    let mut resolved: Vec<Upstream> = Vec::with_capacity(sections.len());
    for section in sections {
        let upstream = upstream(section, keys, floor)?;
        if resolved.iter().any(|other| other.name == upstream.name) {
            return Err(Error::Upstream {
                rule: "each entry has a name of its own",
            });
        }
        if resolved
            .iter()
            .any(|other| other.issuer() == upstream.issuer())
        {
            return Err(Error::Upstream {
                rule: "each entry has an issuer of its own",
            });
        }
        resolved.push(upstream);
    }
    Ok(resolved)
}

/// Returns the provider `section` names.
fn upstream(
    section: &UpstreamSection,
    keys: &SigningKeys,
    floor: crate::assurance::Floor,
) -> Result<Upstream, Error> {
    let named = !section.name.is_empty()
        && section
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-');
    if !named {
        return Err(Error::Upstream {
            rule: "`name` is set, of letters, digits and `-`",
        });
    }
    // NOTE: no specification governs the entry: our own design, the table present
    // names the protocol and a preset fills only an OpenID Connect table (#733).
    let (protocol, fhir_user_claim, role_claims) = match (&section.oidc, &section.saml) {
        (Some(oidc), None) => {
            let effective = oidc.effective(&section.defaults()?);
            let resolved = oidc_upstream(oidc, &effective, keys)?;
            (
                Protocol::Oidc(resolved),
                effective.fhir_user_claim,
                effective.role_claims,
            )
        }
        (None, Some(_)) if section.preset.is_some() => {
            return Err(Error::Upstream {
                rule: "a `preset` fills an `[ferrosmart.upstream.oidc]` table, never a SAML one",
            });
        }
        (None, Some(saml)) => {
            let (resolved, fhir_user_claim, role_claims) = crate::upstream::saml::upstream(saml)?;
            (Protocol::Saml(resolved), fhir_user_claim, role_claims)
        }
        _ => {
            return Err(Error::Upstream {
                rule: "one of `[ferrosmart.upstream.oidc]` and `[ferrosmart.upstream.saml]` is set, never both",
            });
        }
    };
    let assurance =
        crate::assurance::Assurance::resolve(&section.assurance, floor).map_err(|source| {
            Error::Assurance {
                name: section.name.clone(),
                source,
            }
        })?;
    let named = |claim: &String| !claim.is_empty();
    Ok(Upstream {
        name: section.name.clone(),
        label: if section.label.is_empty() {
            section.name.clone()
        } else {
            section.label.clone()
        },
        fhir_user_claim: Some(fhir_user_claim).filter(named),
        role_claims: role_claims.into_iter().filter(named).collect(),
        assurance,
        protocol,
    })
}

/// Returns FerroSMART's SAML 2.0 service provider `[ferrosmart.saml]`
/// describes, which every SAML 2.0 provider needs; a provider
/// answering by artifact needs its TLS client identity too
/// (saml-profiles-2.0-os §4.1.4.4).
fn service_provider(
    section: &crate::config::FerroSmartSection,
) -> Result<Option<Arc<crate::upstream::saml::ServiceProviderSettings>>, Error> {
    let entries: Vec<&crate::upstream::saml::SamlSection> = section
        .upstream
        .iter()
        .filter_map(|upstream| upstream.saml.as_ref())
        .collect();
    let Some(sp) = &section.saml else {
        if entries.is_empty() {
            return Ok(None);
        }
        return Err(Error::Missing {
            key: "ferrosmart.saml",
        });
    };
    let resolved = crate::upstream::saml::service_provider(sp, &section.issuer, &entries)?;
    let artifact = entries
        .iter()
        .any(|entry| entry.response_binding == crate::upstream::saml::ResponseBinding::Artifact);
    if artifact && !resolved.mutual_tls {
        return Err(Error::Upstream {
            rule: "a provider answering by artifact needs `[ferrosmart.saml.tls]` with a client identity",
        });
    }
    Ok(Some(Arc::new(resolved)))
}

/// Returns the OpenID Connect provider `section` names with the values
/// `effective` fills, authenticating with `keys`' current key under
/// `private_key_jwt`.
fn oidc_upstream(
    section: &OidcSection,
    effective: &Effective,
    keys: &SigningKeys,
) -> Result<OidcUpstream, Error> {
    if section.issuer.is_empty() || section.client_id.is_empty() {
        return Err(Error::Upstream {
            rule: "`issuer` and `client_id` are set",
        });
    }
    // NOTE: OpenID Connect Core 1.0 §9, private_key_jwt by default, or a secret as
    // HTTP Basic per provider (owner, 2026-11-19, #679, reversing #619); one of the two.
    let authentication = match (&section.private_key_jwt, &section.client_secret_basic) {
        (jwt, None) => Authentication::PrivateKeyJwt(assertion_keys(
            jwt.as_ref().unwrap_or(&PrivateKeyJwtSection::default()),
            &effective.algorithm,
            keys,
        )?),
        (None, Some(basic)) => Authentication::ClientSecretBasic(require_secret(
            "ferrosmart.upstream.oidc.client_secret_basic.secret",
            basic
                .secret
                .as_ref()
                .map(ferrohealth_secret::secret::Secret::to_secret_string),
            basic.secret_file.as_deref(),
        )?),
        (Some(_), Some(_)) => {
            return Err(Error::Upstream {
                rule: "one of `private_key_jwt` and `client_secret_basic` is set, never both",
            });
        }
    };
    Ok(OidcUpstream {
        issuer: section.issuer.clone(),
        client_id: section.client_id.clone(),
        authentication,
        scopes: effective.scopes.clone(),
        trusted_audiences: effective.trusted_audiences.clone(),
    })
}

/// Returns the assertion ring `section` names, signing at `algorithm`, the
/// provider's registration's, and naming the certificate it knows the
/// current key by, once it holds none of `tokens`' keys.
fn assertion_keys(
    section: &PrivateKeyJwtSection,
    algorithm: &str,
    tokens: &SigningKeys,
) -> Result<AssertionKeys, Error> {
    const KEY: &str = "ferrosmart.upstream.oidc.private_key_jwt";
    let algorithm = algorithm
        .parse::<Algorithm>()
        .map_err(|_unknown| Error::Upstream {
            rule: "`private_key_jwt.algorithm` names a JWS algorithm (RFC 7518 §3.1)",
        })?;
    let ring = key_ring(&section.keys, &ASSERTION_KEYS, algorithm)?;
    // NOTE: RFC 8725 §3.12: a key that signs client assertions never signs a
    // token, so the two rings share no key.
    let pool: Vec<&AssertionKey> = tokens.pool().iter().collect();
    if shares_key(
        &ring.published(),
        &ferrohealth_smart::client::assertion::jwk_set(&pool),
    ) {
        return Err(Error::Upstream {
            rule: "the assertion keys share no key with `[ferrosmart.keys]`",
        });
    }
    let mut key = ring.current().clone();
    if let Some(path) = section.certificate_file.as_deref() {
        let pem = std::fs::read(path).map_err(|source| Error::KeyFile {
            key: "ferrosmart.upstream.oidc.private_key_jwt.certificate_file",
            path: path.to_owned(),
            source,
        })?;
        key = key
            .with_certificate(&pem)
            .map_err(|source| Error::Key { key: KEY, source })?;
    }
    Ok(AssertionKeys {
        signer: Box::new(key),
        ring: Arc::new(ring),
    })
}

/// Whether the JWK Sets `one` and `other` publish a key in common, compared
/// by its RFC 7638 members.
fn shares_key(one: &serde_json::Value, other: &serde_json::Value) -> bool {
    let members = |set: &serde_json::Value| -> Vec<String> {
        set.get("keys")
            .and_then(serde_json::Value::as_array)
            .map(|keys| {
                keys.iter()
                    .map(|key| {
                        ["kty", "crv", "n", "e", "x", "y"]
                            .iter()
                            .map(|name| key.get(*name).map(ToString::to_string).unwrap_or_default())
                            .collect::<Vec<_>>()
                            .join("|")
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let theirs = members(other);
    members(one).iter().any(|key| theirs.contains(key))
}

/// Returns the scopes of each role `sections` name: a role named once,
/// each scope a `user/` or `patient/` scope token or an extension scope
/// starting with `__` (SMART App Launch 2.2.0, Scopes and Launch Context,
/// Extensibility), since a person's role grants a person's access, never a
/// system's.
fn roles(sections: &[crate::config::RoleSection]) -> Result<BTreeMap<String, Vec<String>>, Error> {
    let mut roles = BTreeMap::new();
    for section in sections {
        if !ferrohealth_smart::roles::is_role(&section.name) {
            return Err(Error::Role {
                rule: "a role has no name, or one with a space",
            });
        }
        let person = section.scopes.iter().all(|scope| {
            ferrohealth_smart::scope::is_scope_token(scope)
                && (scope.starts_with("user/")
                    || scope.starts_with("patient/")
                    || crate::scopes::is_extension(scope))
        });
        if !person {
            return Err(Error::Role {
                rule: "a role grants a scope other than a user/, patient/ or __ extension one",
            });
        }
        if roles
            .insert(section.name.clone(), section.scopes.clone())
            .is_some()
        {
            return Err(Error::Role {
                rule: "a role is named twice",
            });
        }
    }
    Ok(roles)
}
