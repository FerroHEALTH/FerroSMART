// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The check of a `DPoP` proof presented to a protected resource (RFC 9449
//! §4.3, §7.1), and the authentication of a `DPoP` request through it.
//!
//! The proof is held to the request it arrived with: its method, and its
//! URI as the client addressed it, which is the external base URL the
//! product names plus the request path, never the URI the server sees
//! behind a TLS-terminating proxy. Its `jti` is recorded in the product's
//! [`ReplayStore`] for the window the proof is accepted in, so a replay is
//! refused (RFC 9449 §11.1).

use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

use http::HeaderMap;
use http::Method;
use serde_json::Value;
use url::Url;

use crate::jws::JwsError;
use crate::jws::algorithm::Algorithm;
use crate::jws::compact::Unverified;
use crate::jws::compact::decode;
use crate::uri::normalized;

use crate::refusal::Reason;
use crate::resource::Caller;
use crate::resource::MAX_CLOCK_SKEW;
use crate::resource::Rejection;
use crate::resource::Verifier;
use crate::sender::Binding;
use crate::sender::Check;
use crate::sender::ClientCertificate;
use crate::sender::ProvenKey;
use crate::sender::replay::ProofId;
use crate::sender::replay::ReplayStore;

/// The longest proof window a deployment may configure; RFC 9449 §11.1
/// prefers "a relatively brief period on the order of seconds or minutes".
pub const MAX_PROOF_AGE: Duration = Duration::from_secs(300);

/// The longest `jti` a proof may carry; RFC 9449 §11.1 has a server "reject
/// `DPoP` proof JWTs with unnecessarily large jti values".
pub const MAX_JTI_LENGTH: usize = 256;

/// The name of the header a `DPoP` proof travels in (RFC 9449 §4.1).
pub const DPOP: http::HeaderName = http::HeaderName::from_static("dpop");

/// What one surface checks a `DPoP` proof against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofSettings {
    /// The surface's base URL as its clients address it: the `htu` of a
    /// proof is this URL with the request path appended (RFC 9449 §4.3,
    /// check 9).
    pub external_url: Url,
    /// How long after its `iat` a proof is accepted (RFC 9449 §11.1), at
    /// most [`MAX_PROOF_AGE`].
    pub max_age: Duration,
    /// How far a proof's `iat` may lie in the future, at most
    /// [`MAX_CLOCK_SKEW`] (RFC 9449 §11.1).
    pub clock_skew: Duration,
    /// The signature algorithms a proof may use; asymmetric only (RFC 9449
    /// §4.2, §11.6).
    pub algorithms: Vec<Algorithm>,
}

impl ProofSettings {
    /// Returns settings for proofs addressed to `external_url`.
    ///
    /// A proof is accepted for 60 seconds after its `iat`, an `iat` up to
    /// 10 seconds ahead is accepted, and RS256, RS384, PS256, PS384, ES256
    /// and ES384 are accepted, the defaults of [`DpopSection`].
    #[must_use]
    pub fn new(external_url: Url) -> Self {
        DpopSection::default().settings(external_url)
    }

    /// Checks the settings: an `http` or `https` base URL with a host and
    /// no query or fragment, a window within its bound, and at least one
    /// algorithm.
    ///
    /// # Errors
    ///
    /// Returns the [`ProofSettingsError`] naming the first rule broken.
    pub fn validate(&self) -> Result<(), ProofSettingsError> {
        let url = &self.external_url;
        if !matches!(url.scheme(), "https" | "http")
            || url.host_str().is_none()
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(ProofSettingsError::ExternalUrl);
        }
        check_window(self.max_age, self.clock_skew, &self.algorithms)
    }
}

/// Checks a proof window within its bound, a clock skew within its bound,
/// and at least one algorithm.
fn check_window(
    max_age: Duration,
    clock_skew: Duration,
    algorithms: &[Algorithm],
) -> Result<(), ProofSettingsError> {
    if max_age.is_zero() || max_age > MAX_PROOF_AGE {
        return Err(ProofSettingsError::MaxAge { max_age });
    }
    if clock_skew > MAX_CLOCK_SKEW {
        return Err(ProofSettingsError::ClockSkew { skew: clock_skew });
    }
    if algorithms.is_empty() {
        return Err(ProofSettingsError::NoAlgorithm);
    }
    Ok(())
}

/// The `[auth.dpop]` table: how the surface checks the `DPoP` proof of a
/// `DPoP` request (RFC 9449 §4.3, §7.1).
///
/// The surface's base URL, which a proof's `htu` is compared with, is no key
/// of the table: the product names its own public URL once and hands it to
/// [`DpopSection::settings`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(default, deny_unknown_fields)]
pub struct DpopSection {
    /// How long after its `iat` a proof is accepted, at most `300s`.
    pub max_age: ferrohealth_config::units::Duration,
    /// How far a proof's `iat` may lie ahead, at most `300s`.
    pub clock_skew: ferrohealth_config::units::Duration,
    /// The signature algorithms a proof may use; asymmetric only.
    #[cfg_attr(feature = "schema", schemars(with = "Vec<String>"))]
    pub algorithms: Vec<Algorithm>,
}

impl Default for DpopSection {
    fn default() -> Self {
        Self {
            // NOTE: RFC 9449 §11.1 prefers a window "on the order of seconds or
            // minutes"; the values are our own design.
            max_age: ferrohealth_config::units::Duration::from_secs(60),
            clock_skew: ferrohealth_config::units::Duration::from_secs(10),
            algorithms: vec![
                Algorithm::Rs256,
                Algorithm::Rs384,
                Algorithm::Ps256,
                Algorithm::Ps384,
                Algorithm::Es256,
                Algorithm::Es384,
            ],
        }
    }
}

impl DpopSection {
    /// Checks the table: a window within its bound, a clock skew within its
    /// bound, and at least one algorithm.
    ///
    /// # Errors
    ///
    /// Returns the [`ProofSettingsError`] naming the first rule broken.
    pub fn validate(&self) -> Result<(), ProofSettingsError> {
        check_window(self.max_age.get(), self.clock_skew.get(), &self.algorithms)
    }

    /// Returns the settings of proofs addressed to `external_url`, the
    /// surface's base URL as its clients address it, under this table's
    /// window and algorithms; [`ProofCheck::new`] checks them.
    #[must_use]
    pub fn settings(&self, external_url: Url) -> ProofSettings {
        ProofSettings {
            external_url,
            max_age: self.max_age.get(),
            clock_skew: self.clock_skew.get(),
            algorithms: self.algorithms.clone(),
        }
    }
}

/// Proof settings that break a rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProofSettingsError {
    /// The external base URL is not `http` or `https`, names no host, or
    /// carries a query, a fragment or user information.
    #[error(
        "the DPoP external URL is not an http or https URL with a host and nothing after its path"
    )]
    ExternalUrl,
    /// The proof window is zero or longer than [`MAX_PROOF_AGE`].
    #[error("the DPoP proof window of {max_age:?} is zero or longer than {MAX_PROOF_AGE:?}")]
    MaxAge {
        /// The window configured.
        max_age: Duration,
    },
    /// The clock skew is longer than [`MAX_CLOCK_SKEW`].
    #[error("the DPoP clock skew of {skew:?} is longer than {MAX_CLOCK_SKEW:?}")]
    ClockSkew {
        /// The skew configured.
        skew: Duration,
    },
    /// No algorithm is admitted.
    #[error("the DPoP settings admit no signature algorithm")]
    NoAlgorithm,
}

/// What a request presents to a `DPoP`-protected resource.
#[derive(Debug, Clone, Copy)]
pub struct Presented<'a> {
    /// The request's method.
    pub method: &'a Method,
    /// The request's path as the server received it, without its query.
    pub path: &'a str,
    /// The request's headers, which carry the `DPoP` proof.
    pub headers: &'a HeaderMap,
    /// The access token of the `DPoP` authorization scheme.
    pub token: &'a str,
    /// The client certificate of the connection, when there was one.
    pub certificate: Option<&'a ClientCertificate>,
}

/// A `DPoP` proof that passed every check of RFC 9449 §4.3, whose `jti` is
/// yet to be recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// The key the proof was signed with.
    key: ProvenKey,
    /// The digest of the proof's `jti`.
    id: ProofId,
    /// The end of the window the proof is accepted in.
    until: SystemTime,
}

impl Proof {
    /// Returns the key the proof was signed with.
    #[must_use]
    pub const fn key(&self) -> &ProvenKey {
        &self.key
    }

    /// Returns the digest the proof's `jti` is recorded under.
    #[must_use]
    pub const fn id(&self) -> &ProofId {
        &self.id
    }

    /// Returns the end of the window the proof is accepted in, until which
    /// its `jti` is kept.
    #[must_use]
    pub const fn until(&self) -> SystemTime {
        self.until
    }
}

/// The check of the `DPoP` proofs one surface receives.
pub struct ProofCheck {
    /// What the proofs are checked against.
    settings: ProofSettings,
    /// Where each accepted proof's `jti` is recorded.
    store: Arc<dyn ReplayStore>,
}

impl std::fmt::Debug for ProofCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofCheck")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl ProofCheck {
    /// Returns the check of proofs under `settings`, recording each
    /// accepted proof in `store`.
    ///
    /// # Errors
    ///
    /// Returns the [`ProofSettingsError`] of [`ProofSettings::validate`].
    pub fn new(
        settings: ProofSettings,
        store: Arc<dyn ReplayStore>,
    ) -> Result<Self, ProofSettingsError> {
        settings.validate()?;
        Ok(Self { settings, store })
    }

    /// Returns what the proofs are checked against.
    #[must_use]
    pub const fn settings(&self) -> &ProofSettings {
        &self.settings
    }

    /// Returns the caller a `DPoP` request authenticates under `verifier`:
    /// the proof checked, the token checked and held to the proof's key and
    /// the connection's certificate, and the proof's `jti` recorded last,
    /// so only a request that passed every check spends it.
    ///
    /// # Errors
    ///
    /// Returns [`Rejection::Invalid`] naming the failed [`Check`] for a
    /// proof or a binding that does not hold, every [`Rejection`] of the
    /// verifier, and [`Rejection::Upstream`] (`503`) when the replay store
    /// fails.
    pub async fn authenticate(
        &self,
        verifier: &dyn Verifier,
        presented: &Presented<'_>,
    ) -> Result<Caller, Rejection> {
        let proof = self.check(presented)?;
        let mut binding = Binding::dpop(proof.key.clone());
        if let Some(certificate) = presented.certificate {
            binding = binding.with_certificate(certificate);
        }
        let caller = verifier.verify_bound(presented.token, &binding).await?;
        crate::sender::confirm(
            crate::sender::SenderConstraint::None,
            caller.claims(),
            &binding,
        )
        .map_err(sender)?;
        self.consume(&proof).await?;
        Ok(caller)
    }

    /// Returns the proof `presented` carries, after every check of RFC 9449
    /// §4.3 but the replay check, which [`ProofCheck::consume`] makes.
    ///
    /// # Errors
    ///
    /// Returns [`Rejection::Invalid`] naming the failed [`Check`].
    pub fn check(&self, presented: &Presented<'_>) -> Result<Proof, Rejection> {
        self.inspect(
            presented.method,
            presented.path,
            presented.headers,
            Some(presented.token),
        )
    }

    /// Returns the proof of a token request to an authorization server, a
    /// request for `path` by `method` with `headers`, after every check of
    /// RFC 9449 §4.3 but the replay check: no access token is presented, so
    /// the proof carries no `ath` to hold to one (RFC 9449 §5).
    ///
    /// # Errors
    ///
    /// Returns [`Rejection::Invalid`] naming the failed [`Check`].
    pub fn check_token_request(
        &self,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
    ) -> Result<Proof, Rejection> {
        self.inspect(method, path, headers, None)
    }

    /// Returns the proof `headers` carry for a request for `path` by
    /// `method`, held to the access token `token` when one is presented.
    fn inspect(
        &self,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
        token: Option<&str>,
    ) -> Result<Proof, Rejection> {
        let mut values = headers.get_all(DPOP).iter();
        let value = match (values.next(), values.next()) {
            (None, _) => return Err(sender(Check::ProofMissing)),
            (Some(_), Some(_)) => return Err(sender(Check::ProofRepeated)),
            (Some(value), None) => value,
        };
        let jwt = value
            .to_str()
            .map_err(|_opaque| sender(Check::ProofMalformed))?;
        let proof = read(jwt)?;
        let header = proof.header();
        // NOTE: RFC 9449 §4.3 check 5, the algorithm is "supported by the
        // application, and is acceptable per local policy".
        if !self.settings.algorithms.contains(&header.alg) {
            return Err(sender(Check::ProofAlgorithm));
        }
        let jwk = header.jwk.as_ref().ok_or_else(|| sender(Check::ProofKey))?;
        let claims = proof.verify_claims(jwk).map_err(|error| match error {
            JwsError::Signature => sender(Check::ProofSignature),
            JwsError::KeyAlgorithm { .. } => sender(Check::ProofAlgorithm),
            _ => sender(Check::ProofMalformed),
        })?;
        let text = |name: &str| claims.get(name).and_then(Value::as_str);
        let (Some(jti), Some(htm), Some(htu), Some(iat)) = (
            text("jti"),
            text("htm"),
            text("htu"),
            claims.get("iat").and_then(Value::as_i64),
        ) else {
            return Err(sender(Check::ProofClaim));
        };
        let ath = text("ath");
        if token.is_some() && ath.is_none() {
            return Err(sender(Check::ProofClaim));
        }
        if jti.is_empty() {
            return Err(sender(Check::ProofClaim));
        }
        if jti.len() > MAX_JTI_LENGTH {
            return Err(sender(Check::ProofJti));
        }
        // NOTE: RFC 9110 §9.1, the method token is case-sensitive.
        if htm != method.as_str() {
            return Err(sender(Check::ProofMethod));
        }
        let expected = self.target(path)?;
        if normalized(htu).as_deref() != Some(expected.as_str()) {
            return Err(sender(Check::ProofUri));
        }
        // NOTE: RFC 9449 §4.2, `ath` is the base64url SHA-256 of the ASCII
        // access token; §4.3 check 12 holds it to the token presented.
        if let Some(token) = token
            && ath != Some(crate::sender::sha256(token.as_bytes()).as_str())
        {
            return Err(sender(Check::ProofTokenHash));
        }
        let until = self.window(iat)?;
        Ok(Proof {
            key: ProvenKey {
                jkt: jwk.thumbprint(),
            },
            id: ProofId::of(jti),
            until,
        })
    }

    /// Records `proof`'s `jti` for its window, refusing a proof whose `jti`
    /// was recorded before (RFC 9449 §11.1).
    ///
    /// # Errors
    ///
    /// Returns [`Rejection::Invalid`] with [`Check::ProofReplayed`] for a
    /// replay, and [`Rejection::Upstream`] (`503`) when the store fails, so
    /// a store that cannot answer never admits a proof.
    pub async fn consume(&self, proof: &Proof) -> Result<(), Rejection> {
        match self.store.first_use(&proof.id, proof.until).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(sender(Check::ProofReplayed)),
            Err(error) => Err(Rejection::upstream("DPoP replay store", error)),
        }
    }

    /// Returns the normalized target URI of a request for `path`: the
    /// external base URL's path followed by `path`.
    fn target(&self, path: &str) -> Result<String, Rejection> {
        let mut url = self.settings.external_url.clone();
        let base = url.path().trim_end_matches('/');
        let path = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        let joined = format!("{base}{path}");
        url.set_path(&joined);
        url.set_query(None);
        url.set_fragment(None);
        normalized(url.as_str()).ok_or_else(|| sender(Check::ProofRequestUnknown))
    }

    /// Returns the end of the window a proof issued at `iat` is accepted
    /// in, or the refusal of a proof outside it.
    fn window(&self, iat: i64) -> Result<SystemTime, Rejection> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_before| sender(Check::ProofStale))?;
        let now = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
        let skew = i64::try_from(self.settings.clock_skew.as_secs()).unwrap_or(i64::MAX);
        let age = i64::try_from(self.settings.max_age.as_secs()).unwrap_or(i64::MAX);
        if iat > now.saturating_add(skew) {
            return Err(sender(Check::ProofFuture));
        }
        let last = iat.saturating_add(age).saturating_add(skew);
        if last < now {
            return Err(sender(Check::ProofStale));
        }
        let last = u64::try_from(last).map_err(|_negative| sender(Check::ProofStale))?;
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(last))
            .ok_or_else(|| sender(Check::ProofStale))
    }
}

/// Returns the proof `jwt` read into its parts, after checks 2, 4 and 7 of
/// RFC 9449 §4.3: a well-formed JWT, typed `dpop+jwt`, with a public `jwk`.
fn read(jwt: &str) -> Result<Unverified<'_>, Rejection> {
    // NOTE: RFC 9449 §4.1, the header value is `token68`, and §4.3 check 2
    // has it a single well-formed JWT: three segments, a JWS.
    let body = jwt.trim_end_matches('=');
    let token68 = !body.is_empty()
        && body.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        });
    if !token68 {
        return Err(sender(Check::ProofMalformed));
    }
    // NOTE: RFC 9449 §4.3 check 5, an `alg` that names no asymmetric algorithm
    // (`none` among them) is refused as the algorithm; §4.2, the `jwk` "MUST NOT
    // contain a private key", and the JWK reader refuses one.
    let proof = decode(jwt).map_err(|error| match error {
        JwsError::Algorithm => sender(Check::ProofAlgorithm),
        JwsError::HeaderKey { .. } => sender(Check::ProofKey),
        _ => sender(Check::ProofMalformed),
    })?;
    // NOTE: RFC 7515 §4.1.9 reads a `typ` without a `/` as if `application/`
    // led it, and media types compare without regard to case.
    let typed = proof.header().typ.as_deref().is_some_and(|typ| {
        typ.eq_ignore_ascii_case("dpop+jwt") || typ.eq_ignore_ascii_case("application/dpop+jwt")
    });
    if !typed {
        return Err(sender(Check::ProofType));
    }
    if proof.header().jwk.is_none() {
        return Err(sender(Check::ProofKey));
    }
    Ok(proof)
}

/// Returns the rejection of a request that fails `check`.
const fn sender(check: Check) -> Rejection {
    Rejection::Invalid {
        reason: Reason::Sender(check),
    }
}
