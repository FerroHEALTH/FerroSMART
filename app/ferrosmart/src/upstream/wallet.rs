// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The EUDI Wallet as an upstream provider: a person logs in by presenting
//! their PID (`docs/architecture.md` §13.32).
//!
//! `[ferrosmart.upstream.openid4vp]` names the verifier's access key and
//! certificate, its registration certificate, the anchors of the PID
//! providers and what it asks for. This module reads the files, fetches
//! what a presentation points at (an `x5u` chain, a Token Status List) and
//! turns a verified PID into the [`Identity`] every login yields; the
//! protocol machinery is `crate::wallet`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use url::Url;

use super::{Identity, UPSTREAM_TIMEOUT};
use crate::wallet::Refusal;
use crate::wallet::jwe::EphemeralKey;
use crate::wallet::request::{Asks, Lane, Request, Verifier, VerifierError};
use crate::wallet::sdjwt::{Expected, IssuerKey, Presentation, Verified};
use crate::wallet::status::StatusToken;
use crate::wallet::x509::{AnchorError, Anchors};

/// The login page that offers the wallet by redirect and through the
/// Digital Credentials API.
pub const PAGE_ROUTE: &str = "/wallet";

/// The route the page posts the Digital Credentials API's answer to
/// (OpenID4VP 1.0 Appendix A.4).
pub const DIGITAL_CREDENTIALS_ROUTE: &str = "/wallet/dc";

/// The route of the page's script module.
pub const MODULE_ROUTE: &str = "/wallet/dc.js";

/// The route a wallet fetches a request object at, by the request's
/// `state` (OpenID4VP 1.0 §5.10).
pub const REQUEST_ROUTE: &str = "/wallet/request/{state}";

/// The route a wallet posts its response to (OpenID4VP 1.0 §8.2).
pub const RESPONSE_ROUTE: &str = "/wallet/response";

/// The route the wallet sends the browser back to with the response code
/// (OpenID4VP 1.0 §8.2, §14.2).
pub const COMPLETE_ROUTE: &str = "/wallet/complete";

/// The `acr` of a PID login: the PID is issued at assurance level high
/// (Regulation (EU) 2024/1183 Art 5a(11); Implementing Regulation (EU)
/// 2024/2977 Art 3(7)).
pub const ACR: &str = "http://eidas.europa.eu/LoA/high";

/// The largest document fetched for a presentation, in bytes (no
/// specification sets one: our own design).
const MAX_BODY: usize = 4 * 1024 * 1024;

/// The claim that holds the PID's issuing country, which with the
/// identifier names the person (Implementing Regulation (EU) 2024/2977
/// Annex, as amended by 2026/1731, §4.2 Table 8).
pub const ISSUING_COUNTRY: &str = "issuing_country";

/// `[ferrosmart.upstream.openid4vp]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct WalletSection {
    /// The PEM path of the access certificate, the wallet-relying party
    /// access certificate first and its path up to, but not including, the
    /// anchor (ETSI TS 119 472-2 OIDFVP-HAIP-REDIRECTS_RO-02).
    pub access_certificate_file: PathBuf,
    /// The PKCS#8 PEM P-256 key of the access certificate, which signs every
    /// request object.
    pub access_key_file: PathBuf,
    /// The registration certificate as the registrar issued it, which every
    /// request object carries (Implementing Regulation (EU) 2024/2979 Annex
    /// II as amended by 2026/1731, OIDFVP-HAIP-COMMON-REQ-RO-13).
    pub registration_certificate_file: PathBuf,
    /// The PEM files of the PID providers' trust anchors, which join the
    /// list of PID providers when one is configured.
    pub issuer_anchor_files: Vec<PathBuf>,
    /// `[ferrosmart.upstream.openid4vp.pid_providers_list]`: the list of PID
    /// providers the Commission publishes; none by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid_providers_list: Option<ListSection>,
    /// Where the wallet is invoked: `eu-eaap://` by default (ETSI TS 119
    /// 472-2 OIDFVP-HAIP-REDIRECTS-03).
    pub wallet_endpoint: String,
    /// The credential types accepted; the PID's `urn:eudi:pid:1` by
    /// default (Implementing Regulation (EU) 2024/2977 Annex §4.2).
    pub vct_values: Vec<String>,
    /// The claims asked for, dotted for a nested claim; the PID's names,
    /// the identifier claim and `issuing_country` among them.
    pub claims: Vec<String>,
    /// The claim whose value is the person's identifier, which the
    /// `fhirUser` lookup reads; `personal_administrative_number` by default.
    pub identifier_claim: String,
    /// Whether the login page offers the wallet through the W3C Digital
    /// Credentials API beside the redirect, as a relying party "shall"
    /// (Implementing Regulation (EU) 2024/2979 Annex II as amended by
    /// 2026/1731, OIDFVP-HAIP-SUPPORT-05); `true` by default. Off, the browser
    /// goes straight to `wallet_endpoint`.
    pub digital_credentials_api: bool,
}

impl Default for WalletSection {
    fn default() -> Self {
        Self {
            access_certificate_file: PathBuf::new(),
            access_key_file: PathBuf::new(),
            registration_certificate_file: PathBuf::new(),
            issuer_anchor_files: Vec::new(),
            pid_providers_list: None,
            wallet_endpoint: String::from("eu-eaap://"),
            vct_values: vec![String::from("urn:eudi:pid:1")],
            claims: [
                "family_name",
                "given_name",
                "birthdate",
                "personal_administrative_number",
                ISSUING_COUNTRY,
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            identifier_claim: String::from("personal_administrative_number"),
            digital_credentials_api: true,
        }
    }
}

impl WalletSection {
    /// Returns the issuer a person's pairwise `sub` is derived under: the
    /// first credential type accepted.
    #[must_use]
    pub fn issuer(&self) -> Option<&str> {
        self.vct_values.first().map(String::as_str)
    }
}

/// `[ferrosmart.upstream.openid4vp.pid_providers_list]`: the list of PID providers.
///
/// It names where the list is read and who signs it, which the Commission
/// publishes beside it (Implementing Regulation (EU) 2024/2980 Art 5(4)(b)
/// and (c), as amended by 2026/1731).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ListSection {
    /// The https URL of the list; exclusive with `file`.
    pub url: String,
    /// A file holding a copy of the list; exclusive with `url`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    /// The PEM files of the certificates that sign the list.
    pub signing_certificate_files: Vec<PathBuf>,
    /// How often the list is read again; `1h` by default. It is read again
    /// at its next update too.
    pub refresh: ferrohealth_config::units::Duration,
}

impl Default for ListSection {
    fn default() -> Self {
        Self {
            url: String::new(),
            file: None,
            signing_certificate_files: Vec::new(),
            refresh: ferrohealth_config::units::Duration::from_hours(1),
        }
    }
}

/// Why `[ferrosmart.upstream.openid4vp]` cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum WalletConfigError {
    /// A rule of the table is broken.
    #[error("`ferrosmart.upstream.openid4vp`: {0}")]
    Rule(&'static str),
    /// A file cannot be read.
    #[error("`{key}` cannot be read at {}", path.display())]
    File {
        /// The key.
        key: &'static str,
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// The access key or certificate is not usable.
    #[error("the access key or certificate of `ferrosmart.upstream.openid4vp` is not usable")]
    Verifier(#[source] VerifierError),
    /// An anchor file is not usable.
    #[error("`ferrosmart.upstream.openid4vp.issuer_anchor_files` is not usable")]
    Anchors(#[source] AnchorError),
}

/// A wallet entry, resolved.
#[derive(Debug, Clone)]
pub struct WalletUpstream {
    /// The issuer a person's `sub` is derived under.
    pub issuer: String,
    /// The verifier.
    verifier: Arc<Verifier>,
    /// The PID providers' anchors from files.
    anchors: Arc<Anchors>,
    /// The list of PID providers, when one is configured.
    list: Option<ListSource>,
    /// Where the wallet is invoked.
    endpoint: Url,
    /// The request object route, with no `state`.
    request_base: Url,
    /// The login page that offers the wallet.
    page: Url,
    /// The credential types accepted.
    vct_values: Vec<String>,
    /// The claims asked for, by name.
    claims: Vec<String>,
    /// The identifier claim.
    identifier_claim: String,
    /// The origin of the issuer, where the login page is served.
    origin: String,
    /// Whether the login page offers the Digital Credentials API.
    digital_credentials_api: bool,
}

impl WalletUpstream {
    /// Returns the verifier's client identifier.
    #[must_use]
    pub fn client_id(&self) -> &str {
        self.verifier.client_id()
    }

    /// Returns the origin of the login page.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Returns the audience a presentation names in `lane`: the client
    /// identifier by redirect, `origin:` and the page's origin over the
    /// Digital Credentials API (OpenID4VP 1.0 Appendix A.4, B.3.6).
    #[must_use]
    pub fn audience(&self, lane: &Lane<'_>) -> String {
        match lane {
            Lane::Redirect { .. } => self.client_id().to_owned(),
            Lane::DigitalCredentials { origin } => format!("origin:{origin}"),
        }
    }

    /// Whether the login page offers the Digital Credentials API.
    #[must_use]
    pub const fn digital_credentials_api(&self) -> bool {
        self.digital_credentials_api
    }
}

/// Returns the wallet entry `section` describes, answering under the
/// issuer `issuer`.
///
/// # Errors
/// Returns [`WalletConfigError`] for a broken rule, a file that cannot be
/// read, or a key, certificate or anchor that cannot be used.
pub fn upstream(
    section: &WalletSection,
    issuer: &Url,
) -> Result<WalletUpstream, WalletConfigError> {
    let endpoint = Url::parse(&section.wallet_endpoint)
        .map_err(|_unparsed| WalletConfigError::Rule("`wallet_endpoint` is an absolute URL"))?;
    let vct_issuer = section
        .issuer()
        .filter(|vct| Url::parse(vct).is_ok())
        .ok_or(WalletConfigError::Rule(
            "`vct_values` names at least one type, the first an absolute URI",
        ))?;
    if section.identifier_claim.is_empty()
        || !section.claims.contains(&section.identifier_claim)
        || !section.claims.iter().any(|claim| claim == ISSUING_COUNTRY)
    {
        return Err(WalletConfigError::Rule(
            "`claims` names `identifier_claim` and `issuing_country`",
        ));
    }
    let anchor_files = section
        .issuer_anchor_files
        .iter()
        .map(|path| read("ferrosmart.upstream.openid4vp.issuer_anchor_files", path))
        .collect::<Result<Vec<_>, _>>()?;
    let anchors = if anchor_files.is_empty() && section.pid_providers_list.is_some() {
        Anchors::default()
    } else {
        Anchors::from_pem(&anchor_files).map_err(WalletConfigError::Anchors)?
    };
    let list = section
        .pid_providers_list
        .as_ref()
        .map(list_source)
        .transpose()?;
    let paths: Vec<Vec<String>> = section
        .claims
        .iter()
        .map(|claim| claim.split('.').map(str::to_owned).collect())
        .collect();
    let key_identifiers = anchors.key_identifiers();
    let asks = Asks {
        vct_values: &section.vct_values,
        claims: &paths,
        key_identifiers: &key_identifiers,
    };
    let verifier = Verifier::new(
        &read(
            "ferrosmart.upstream.openid4vp.access_key_file",
            &section.access_key_file,
        )?,
        &read(
            "ferrosmart.upstream.openid4vp.access_certificate_file",
            &section.access_certificate_file,
        )?,
        &read(
            "ferrosmart.upstream.openid4vp.registration_certificate_file",
            &section.registration_certificate_file,
        )?,
        &route(issuer, RESPONSE_ROUTE),
        &asks,
    )
    .map_err(WalletConfigError::Verifier)?;
    Ok(WalletUpstream {
        issuer: vct_issuer.to_owned(),
        verifier: Arc::new(verifier),
        anchors: Arc::new(anchors),
        list,
        endpoint,
        request_base: route(issuer, "/wallet/request"),
        page: route(issuer, PAGE_ROUTE),
        vct_values: section.vct_values.clone(),
        claims: section.claims.clone(),
        identifier_claim: section.identifier_claim.clone(),
        origin: issuer.origin().ascii_serialization(),
        digital_credentials_api: section.digital_credentials_api,
    })
}

/// Where the list of PID providers is read, and who signs it.
#[derive(Debug, Clone)]
struct ListSource {
    /// The URL or the file.
    location: ListLocation,
    /// The certificates that sign the list, DER.
    signers: Vec<Vec<u8>>,
    /// How often the list is read again.
    refresh: Duration,
}

/// Where the list is read.
#[derive(Debug, Clone)]
enum ListLocation {
    /// An https URL.
    Url(Url),
    /// A file.
    File(PathBuf),
}

/// Returns the list source `section` describes.
fn list_source(section: &ListSection) -> Result<ListSource, WalletConfigError> {
    const KEY: &str = "ferrosmart.upstream.openid4vp.pid_providers_list.signing_certificate_files";
    // NOTE: Implementing Regulation (EU) 2024/2980 Art 5(3)(c), the list is read over
    // state-of-the-art transport encryption.
    let location = match (section.url.as_str(), &section.file) {
        ("", Some(file)) => ListLocation::File(file.clone()),
        (url, None) if !url.is_empty() => match Url::parse(url) {
            Ok(url) if url.scheme() == "https" => ListLocation::Url(url),
            _ => {
                return Err(WalletConfigError::Rule(
                    "`pid_providers_list.url` is an https URL",
                ));
            }
        },
        _ => {
            return Err(WalletConfigError::Rule(
                "`pid_providers_list` sets one of `url` and `file`",
            ));
        }
    };
    let mut signers = Vec::new();
    for path in &section.signing_certificate_files {
        signers.extend(
            crate::wallet::x509::certificates(&read(KEY, path)?)
                .map_err(WalletConfigError::Anchors)?,
        );
    }
    if signers.is_empty() {
        return Err(WalletConfigError::Rule(
            "`pid_providers_list.signing_certificate_files` names the list's signing certificates",
        ));
    }
    if section.refresh.is_zero() {
        return Err(WalletConfigError::Rule(
            "`pid_providers_list.refresh` is greater than zero",
        ));
    }
    Ok(ListSource {
        location,
        signers,
        refresh: section.refresh.get(),
    })
}

/// Returns the URL of `route` under the issuer `issuer`.
fn route(issuer: &Url, route: &str) -> Url {
    let mut url = issuer.clone();
    url.set_path(&format!("{}{route}", issuer.path().trim_end_matches('/')));
    url
}

/// Returns the bytes of the file `path`, the value of `key`.
fn read(key: &'static str, path: &Path) -> Result<Vec<u8>, WalletConfigError> {
    std::fs::read(path).map_err(|source| WalletConfigError::File {
        key,
        path: path.to_owned(),
        source,
    })
}

/// Why a wallet login cannot be set up or go on.
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    /// The HTTP client cannot be built.
    #[error("the HTTP client of the wallet verifier cannot be built")]
    Client(#[source] reqwest::Error),
    /// The ephemeral key cannot be made or read back.
    #[error("the request's ephemeral key cannot be used")]
    Key(#[source] crate::wallet::jwe::JweError),
    /// The request object cannot be signed.
    #[error("the request object cannot be signed")]
    Sign(#[source] VerifierError),
    /// The random source failed.
    #[error("the random source failed")]
    Random,
    /// The request URI cannot carry a `state`.
    #[error("the request URI cannot carry the request's state")]
    Url,
}

/// A login begun at the wallet.
#[derive(Debug, Clone)]
pub struct Begun {
    /// Where the browser goes: the wallet, or the login page that offers
    /// it through the Digital Credentials API too.
    pub departure: Url,
    /// The request's `state`, which names the request.
    pub state: String,
    /// The request's `nonce`.
    pub nonce: String,
    /// The request's ephemeral key, as the request keeps it.
    pub key: String,
}

/// The wallet login of one entry.
#[derive(Debug)]
pub struct WalletLogin {
    /// The entry.
    upstream: WalletUpstream,
    /// The client of `x5u` chains, status lists and the list of PID
    /// providers.
    http: reqwest::Client,
    /// The list of PID providers as this replica last read it.
    held: tokio::sync::Mutex<ListRead>,
}

/// The list of PID providers as a replica last read it.
#[derive(Debug, Clone, Default)]
pub struct ListRead {
    /// The last list that verified.
    pub list: Option<crate::wallet::lote::ProvidersList>,
    /// When the list was last read, in seconds since the epoch.
    pub read_at: Option<i64>,
    /// Why the last read failed, when it did.
    pub failure: Option<String>,
}

impl WalletLogin {
    /// Returns the login of `upstream`.
    ///
    /// # Errors
    /// Returns [`WalletError::Client`] when the HTTP client cannot be built.
    pub fn connect(upstream: &WalletUpstream) -> Result<Self, WalletError> {
        let http = reqwest::Client::builder()
            .timeout(UPSTREAM_TIMEOUT)
            .build()
            .map_err(WalletError::Client)?;
        Ok(Self {
            upstream: upstream.clone(),
            http,
            held: tokio::sync::Mutex::new(ListRead::default()),
        })
    }

    /// Returns the entry.
    #[must_use]
    pub const fn upstream(&self) -> &WalletUpstream {
        &self.upstream
    }

    /// Returns where the wallet is invoked.
    #[must_use]
    pub const fn endpoint(&self) -> &Url {
        &self.upstream.endpoint
    }

    /// Begins a login: a fresh `state`, `nonce` and ephemeral key, and the
    /// URL that invokes the wallet with the request they name (OpenID4VP
    /// 1.0 §5.2; HAIP 1.0 §5).
    ///
    /// # Errors
    /// Returns [`WalletError`] when the random source or the key generator
    /// fails.
    pub fn begin(&self) -> Result<Begun, WalletError> {
        let state = crate::authorize::random().map_err(|_failed| WalletError::Random)?;
        let nonce = crate::authorize::random().map_err(|_failed| WalletError::Random)?;
        let key = EphemeralKey::generate()
            .and_then(|key| key.stored())
            .map_err(WalletError::Key)?;
        let departure = if self.upstream.digital_credentials_api {
            self.upstream.page.clone()
        } else {
            self.invocation(&state)?
        };
        Ok(Begun {
            departure,
            state,
            nonce,
            key,
        })
    }

    /// Returns the URL that invokes the wallet with the request `state`
    /// (OpenID4VP 1.0 §5.10, §9).
    ///
    /// # Errors
    /// Returns [`WalletError::Url`] when the request URI cannot carry the
    /// `state`.
    pub fn invocation(&self, state: &str) -> Result<Url, WalletError> {
        let mut request_uri = self.upstream.request_base.clone();
        request_uri
            .path_segments_mut()
            .map_err(|()| WalletError::Url)?
            .push(state);
        Ok(self
            .upstream
            .verifier
            .invocation(&self.upstream.endpoint, &request_uri))
    }

    /// Returns the signed request object of the request `state` with
    /// `nonce` and the stored ephemeral `key` for `lane`, lapsing at
    /// `expires_at`.
    ///
    /// # Errors
    /// Returns [`WalletError`] when the key does not read back or the
    /// object cannot be signed.
    pub fn request_object(
        &self,
        state: &str,
        nonce: &str,
        key: &str,
        lane: Lane<'_>,
        expires_at: i64,
    ) -> Result<String, WalletError> {
        let key = EphemeralKey::from_stored(key).map_err(WalletError::Key)?;
        self.upstream
            .verifier
            .request_object(&Request {
                state,
                nonce,
                key: &key,
                lane,
                issued_at: jiff::Timestamp::now().as_second(),
                expires_at,
            })
            .map_err(WalletError::Sign)
    }

    /// Checks the one presentation `presentation` against the request's
    /// `nonce` and the `audience` of its lane at `now`, and returns the
    /// person it names.
    ///
    /// # Errors
    /// Returns the [`Refusal`] of the first check that fails.
    pub async fn verify(
        &self,
        presentation: &str,
        nonce: &str,
        audience: &str,
        now: i64,
    ) -> Result<Identity, Refusal> {
        let read = Presentation::parse(presentation)?;
        let chain = match read.issuer_key()? {
            IssuerKey::Chain(chain) => chain,
            IssuerKey::Url { url, thumbprint } => {
                self.chain_at(&url, thumbprint.as_deref()).await?
            }
        };
        let (anchors, status_anchors) = self.anchors(now).await?;
        let issuer = anchors
            .verify(&chain, now)
            .map_err(|_untrusted| Refusal::UntrustedIssuer)?;
        let verified = read.verify(
            &issuer,
            &Expected {
                nonce,
                audience,
                vct_values: &self.upstream.vct_values,
                now,
            },
        )?;
        // NOTE: draft-ietf-oauth-sd-jwt-vc-13 §3.4, the status is checked when the
        // credential carries one; Implementing Regulation (EU) 2024/2979 EAA-4.2.13-03.
        if let Some(reference) = &verified.status {
            let text = self
                .fetch(&reference.uri, Some("application/statuslist+jwt"))
                .await
                .map_err(|error| unreached(&error, Refusal::StatusUnavailable))?;
            let token = StatusToken::parse(&text)?;
            let signer = status_anchors
                .verify(&token.chain()?, now)
                .map_err(|_untrusted| Refusal::StatusUnavailable)?;
            token.check(&signer, reference, now)?;
        }
        self.identity(verified)
    }

    /// Returns the anchors of credentials and of status lists at `now`: the
    /// files', joined by the list of PID providers when one is configured.
    ///
    /// The list is read again once its refresh or its next update has passed.
    /// A read that fails keeps the last list that verified until its next
    /// update; without one, every login is refused (ETSI TS 119 602 §6.3.15).
    async fn anchors(&self, now: i64) -> Result<(Anchors, Anchors), Refusal> {
        let Some(source) = &self.upstream.list else {
            let anchors = (*self.upstream.anchors).clone();
            return Ok((anchors.clone(), anchors));
        };
        let mut held = self.held.lock().await;
        let refresh = i64::try_from(source.refresh.as_secs()).unwrap_or(i64::MAX);
        let stale = held
            .read_at
            .is_none_or(|at| now >= at.saturating_add(refresh))
            || held
                .list
                .as_ref()
                .is_none_or(|list| now >= list.next_update);
        if stale {
            held.read_at = Some(now);
            match self.read_list(source, now).await {
                Ok(list) => {
                    held.list = Some(list);
                    held.failure = None;
                }
                Err(failure) => {
                    tracing::warn!(failure = %failure, "the list of PID providers could not be read; the last one that verified stays");
                    held.failure = Some(failure);
                }
            }
        }
        let Some(list) = held.list.as_ref().filter(|list| now < list.next_update) else {
            tracing::warn!(
                "no list of PID providers that verified is current; the wallet login is refused"
            );
            return Err(Refusal::TrustedListUnavailable);
        };
        let issuance = Anchors::from_der(list.issuance.clone());
        let revocation = Anchors::from_der(list.revocation.clone());
        let anchors = self.upstream.anchors.joined(&issuance);
        let status = anchors.joined(&revocation);
        Ok((anchors, status))
    }

    /// Reads and verifies the list at `source` at `now`, or says why not.
    async fn read_list(
        &self,
        source: &ListSource,
        now: i64,
    ) -> Result<crate::wallet::lote::ProvidersList, String> {
        let text = match &source.location {
            ListLocation::Url(url) => self
                .fetch(url.as_str(), None)
                .await
                .map_err(|error| ferrohealth_server::run::chain(&error))?,
            ListLocation::File(path) => tokio::fs::read_to_string(path)
                .await
                .map_err(|error| ferrohealth_server::run::chain(&error))?,
        };
        crate::wallet::lote::read(&text, &source.signers, now).map_err(|error| error.to_string())
    }

    /// Returns the list of PID providers as this replica last read it, none
    /// when no list is configured.
    pub async fn list_read(&self) -> Option<ListRead> {
        self.upstream.list.as_ref()?;
        Some(self.held.lock().await.clone())
    }

    /// Returns the person `verified` names, refusing one without the
    /// identifier or another claim asked for.
    fn identity(&self, verified: Verified) -> Result<Identity, Refusal> {
        let claims = verified.claims;
        let text = |name: &str| {
            ferrohealth_smart::roles::claim_text(&claims, name)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned)
        };
        let identifier =
            text(&self.upstream.identifier_claim).ok_or(Refusal::NoAdministrativeNumber)?;
        let present = |name: &String| claim_at(&claims, name).is_some_and(|value| !value.is_null());
        if !self.upstream.claims.iter().all(present) {
            return Err(Refusal::MissingClaim);
        }
        let country = text(ISSUING_COUNTRY).ok_or(Refusal::MissingClaim)?;
        let name = [text("given_name"), text("family_name")]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
        let name = Some(name).filter(|name| !name.is_empty());
        Ok(Identity {
            issuer: self.upstream.issuer.clone(),
            subject: format!("{country}:{identifier}"),
            display_name: name.clone(),
            name,
            preferred_username: None,
            claims,
            session: None,
            auth_time: Some(verified.presented_at),
            acr: Some(String::from(ACR)),
        })
    }

    /// Returns the certificate chain at the `x5u` URL `url`, whose leaf
    /// matches `thumbprint` when one is named (RFC 7515 §4.1.5, §4.1.8).
    async fn chain_at(
        &self,
        url: &str,
        thumbprint: Option<&[u8]>,
    ) -> Result<Vec<Vec<u8>>, Refusal> {
        // NOTE: RFC 7515 §4.1.5, the x5u resource is fetched over TLS.
        if !Url::parse(url).is_ok_and(|url| url.scheme() == "https") {
            return Err(Refusal::UntrustedIssuer);
        }
        let text = self
            .fetch(url, None)
            .await
            .map_err(|error| unreached(&error, Refusal::UntrustedIssuer))?;
        let chain = crate::wallet::x509::certificates(text.as_bytes())
            .map_err(|_unread| Refusal::UntrustedIssuer)?;
        let leaf = chain.first().ok_or(Refusal::UntrustedIssuer)?;
        if thumbprint.is_some_and(|thumbprint| thumbprint != crate::wallet::sha256(leaf)) {
            return Err(Refusal::UntrustedIssuer);
        }
        Ok(chain)
    }

    /// Fetches the document at `url`, capped at [`MAX_BODY`].
    async fn fetch(&self, url: &str, accept: Option<&str>) -> Result<String, FetchError> {
        let mut request = self.http.get(url);
        if let Some(accept) = accept {
            request = request.header(http::header::ACCEPT, accept);
        }
        let mut response = request.send().await.map_err(FetchError::Request)?;
        if !response.status().is_success() {
            return Err(FetchError::Status(response.status()));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(FetchError::Request)? {
            if body.len().saturating_add(chunk.len()) > MAX_BODY {
                return Err(FetchError::Body);
            }
            body.extend_from_slice(&chunk);
        }
        String::from_utf8(body).map_err(|_not_utf8| FetchError::Body)
    }
}

/// Why a document a presentation points at could not be fetched.
#[derive(Debug, thiserror::Error)]
enum FetchError {
    /// The request failed.
    #[error("the document could not be fetched")]
    Request(#[source] reqwest::Error),
    /// The server answered with a status other than success.
    #[error("the document's server answered {0}")]
    Status(http::StatusCode),
    /// The document is larger than FerroSMART reads, or not UTF-8.
    #[error("the document is too large or not UTF-8")]
    Body,
}

/// Logs `error` and returns the refusal `refusal` it leads to.
fn unreached(error: &FetchError, refusal: Refusal) -> Refusal {
    tracing::warn!(error = %ferrohealth_server::run::chain(error), reason = %refusal, "a wallet presentation's document could not be fetched");
    refusal
}

/// Returns the claim the dotted `name` reaches in `claims`.
fn claim_at<'a>(
    claims: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Option<&'a serde_json::Value> {
    let mut steps = name.split('.');
    let first = claims.get(steps.next()?)?;
    steps.try_fold(first, |value, step| value.get(step))
}
