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

use serde::{Deserialize, Serialize};
use url::Url;

use super::{Identity, UPSTREAM_TIMEOUT};
use crate::wallet::Refusal;
use crate::wallet::jwe::EphemeralKey;
use crate::wallet::request::{Asks, Request, Verifier, VerifierError};
use crate::wallet::sdjwt::{Expected, IssuerKey, Presentation, Verified};
use crate::wallet::status::StatusToken;
use crate::wallet::x509::{AnchorError, Anchors};

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
    /// The PEM files of the PID providers' trust anchors.
    pub issuer_anchor_files: Vec<PathBuf>,
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
}

impl Default for WalletSection {
    fn default() -> Self {
        Self {
            access_certificate_file: PathBuf::new(),
            access_key_file: PathBuf::new(),
            registration_certificate_file: PathBuf::new(),
            issuer_anchor_files: Vec::new(),
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
    /// The PID providers' anchors.
    anchors: Arc<Anchors>,
    /// Where the wallet is invoked.
    endpoint: Url,
    /// The request object route, with no `state`.
    request_base: Url,
    /// The credential types accepted.
    vct_values: Vec<String>,
    /// The claims asked for, by name.
    claims: Vec<String>,
    /// The identifier claim.
    identifier_claim: String,
}

impl WalletUpstream {
    /// Returns the verifier's client identifier.
    #[must_use]
    pub fn client_id(&self) -> &str {
        self.verifier.client_id()
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
    let anchors = Anchors::from_pem(&anchor_files).map_err(WalletConfigError::Anchors)?;
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
        endpoint,
        request_base: route(issuer, "/wallet/request"),
        vct_values: section.vct_values.clone(),
        claims: section.claims.clone(),
        identifier_claim: section.identifier_claim.clone(),
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
}

/// A login begun at the wallet.
#[derive(Debug, Clone)]
pub struct Begun {
    /// The URL that invokes the wallet.
    pub invocation: Url,
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
    /// The client of `x5u` chains and status lists.
    http: reqwest::Client,
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
        let mut request_uri = self.upstream.request_base.clone();
        request_uri
            .path_segments_mut()
            .map_err(|()| WalletError::Random)?
            .push(&state);
        Ok(Begun {
            invocation: self
                .upstream
                .verifier
                .invocation(&self.upstream.endpoint, &request_uri),
            state,
            nonce,
            key,
        })
    }

    /// Returns the signed request object of the request `state` with
    /// `nonce` and the stored ephemeral `key`, lapsing at `expires_at`.
    ///
    /// # Errors
    /// Returns [`WalletError`] when the key does not read back or the
    /// object cannot be signed.
    pub fn request_object(
        &self,
        state: &str,
        nonce: &str,
        key: &str,
        wallet_nonce: Option<&str>,
        expires_at: i64,
    ) -> Result<String, WalletError> {
        let key = EphemeralKey::from_stored(key).map_err(WalletError::Key)?;
        self.upstream
            .verifier
            .request_object(&Request {
                state,
                nonce,
                key: &key,
                wallet_nonce,
                issued_at: jiff::Timestamp::now().as_second(),
                expires_at,
            })
            .map_err(WalletError::Sign)
    }

    /// Checks the one presentation `presentation` against the request's
    /// `nonce` at `now` and returns the person it names.
    ///
    /// # Errors
    /// Returns the [`Refusal`] of the first check that fails.
    pub async fn verify(
        &self,
        presentation: &str,
        nonce: &str,
        now: i64,
    ) -> Result<Identity, Refusal> {
        let read = Presentation::parse(presentation)?;
        let chain = match read.issuer_key()? {
            IssuerKey::Chain(chain) => chain,
            IssuerKey::Url { url, thumbprint } => {
                self.chain_at(&url, thumbprint.as_deref()).await?
            }
        };
        let issuer = self
            .upstream
            .anchors
            .verify(&chain, now)
            .map_err(|_untrusted| Refusal::UntrustedIssuer)?;
        let verified = read.verify(
            &issuer,
            &Expected {
                nonce,
                audience: self.upstream.client_id(),
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
            let signer = self
                .upstream
                .anchors
                .verify(&token.chain()?, now)
                .map_err(|_untrusted| Refusal::StatusUnavailable)?;
            token.check(&signer, reference, now)?;
        }
        self.identity(verified)
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
