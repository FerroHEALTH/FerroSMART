// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The check of a bearer token by OAuth 2.0 Token Introspection (RFC 7662),
//! for an authorization server that issues tokens a resource server cannot
//! read itself.
//!
//! The token is posted to the introspection endpoint (RFC 7662 §2.1) under
//! the product's own credential: the client authentication of the token
//! endpoint, or a bearer token the product obtained with the client
//! credentials grant (SMART App Launch 2.2.0, Token Introspection). A
//! response whose `active` is not `true` refuses the token (§2.2). An
//! active response must carry `scope`, `client_id` and `exp` (SMART App
//! Launch 2.2.0, Token Introspection, Required fields); its `iss`, when
//! present, must be the configured issuer and its `aud`, when present, must
//! name a configured audience, and the claims are then read by the step the
//! JWT check uses. An active response is cached until its `exp` and never
//! longer than the configured age (§4); an inactive one is never cached,
//! and a held one is classified again on every request it answers.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::time::Duration;
use std::time::Instant;

use http::Extensions;
use http::StatusCode;
use serde_json::Map;
use serde_json::Value;
use url::Url;

use crate::assurance::AssuranceSection;
use crate::client::ClientCredentials;
use crate::client::OAuthError;
use crate::client::TokenError;
use crate::client::cache::TokenSource;
use crate::kind::IssuerKind;
use crate::metadata::DiscoveryError;
use crate::metadata::Http;
use crate::metadata::ServerMetadata;
use crate::profile::Profile;
use crate::refusal::Reason;
use crate::resource::Caller;
use crate::resource::Rejection;
use crate::resource::ResourceError;
use crate::resource::ResourceTypes;
use crate::resource::Verifier;
use crate::resource::configuration;
use crate::resource::token::Admission;
use crate::resource::token::admit;
use crate::resource::token::invalid;
use crate::resource::token::text;
use crate::sender::Binding;
use crate::sender::SenderConstraint;

/// What the log names the introspection endpoint as.
const UPSTREAM: &str = "introspection endpoint";

/// How the resource server authenticates its call to the introspection
/// endpoint, which RFC 7662 §2.1 requires.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum IntrospectionAuth {
    /// The client authentication of the token endpoint (RFC 6749 §2.3,
    /// RFC 7523 §2.2, RFC 8705 §2), with the client id, method, secret, key
    /// and TLS material of the grant. Under `private_key_jwt` the
    /// assertion's `aud` is the introspection endpoint, or the issuer when
    /// the grant names it and asks for it. The grant's `scope`, `audience`
    /// and `resource` are not sent.
    Client(Box<ClientCredentials>),
    /// A bearer token the product obtains with the client credentials grant
    /// and sends in the `Authorization` header (RFC 6750 §2.1), the form
    /// SMART App Launch 2.2.0, Token Introspection, has an EHR accept. A
    /// `401` renews it once.
    Bearer(TokenSource),
}

/// What one deployment configured its introspection check with.
#[derive(Debug, Clone)]
pub struct IntrospectionSettings {
    /// The issuer identifier: its metadata names the introspection endpoint
    /// unless [`Self::endpoint`] does, and an `iss` in a response must equal
    /// it (RFC 8414 §3.3, §4).
    pub issuer: String,
    /// The introspection endpoint, in place of the metadata's
    /// `introspection_endpoint`.
    pub endpoint: Option<Url>,
    /// The audiences, of which an `aud` in a response must contain one.
    pub audience: Vec<String>,
    /// The resource server's credential at the endpoint.
    pub auth: IntrospectionAuth,
    /// The clock skew `exp`, `nbf` and `iat` are checked with, at most
    /// [`super::MAX_CLOCK_SKEW`].
    pub clock_skew: Duration,
    /// The longest an active response is used before the endpoint is asked
    /// again; zero caches nothing.
    pub cache_max_age: Duration,
    /// The most responses held at once. A full cache drops the responses
    /// whose time has ended, then the one that ends soonest, for a new one;
    /// zero holds none.
    pub cache_capacity: usize,
    /// How long one call to the authorization server may take.
    pub timeout: Duration,
    /// The members of a response the caller's roles are read from, each a
    /// dotted path (RFC 9068 §2.2.3.1; [`crate::roles`]).
    pub role_claims: Vec<String>,
    /// Whose tokens the issuer signs.
    pub kind: IssuerKind,
    /// How the response's caller is classified and its scope read.
    pub profile: Profile,
    /// The assurance level a response carries, when the deployment maps
    /// its authentication context values.
    pub assurance: Option<AssuranceSection>,
    /// What a `federation` issuer asserts, required on one.
    pub federation: Option<crate::federation::FederationSection>,
    /// What a `persons` issuer states about its professionals.
    pub attributes: Option<crate::federation::person::AttributesSection>,
    /// Whether the issuer's tokens must be bound to a `DPoP` key or a client
    /// certificate ([`crate::sender`]).
    pub sender_constraint: SenderConstraint,
}

impl IntrospectionSettings {
    /// Returns settings for tokens of `issuer`, an issuer of `kind`,
    /// addressed to `audience` and introspected under `auth`, read under
    /// the `rfc9068` profile.
    ///
    /// The introspection endpoint is the one the issuer's metadata names,
    /// the clock skew is 60 seconds, an active response is held for at most
    /// 60 seconds and at most 10 000 of them at once, and a call may take
    /// 10 seconds.
    #[must_use]
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        auth: IntrospectionAuth,
        kind: IssuerKind,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            endpoint: None,
            audience: vec![audience.into()],
            auth,
            clock_skew: Duration::from_secs(60),
            cache_max_age: Duration::from_secs(60),
            cache_capacity: 10_000,
            timeout: Duration::from_secs(10),
            // NOTE: no specification governs this: our own design; another party's
            // issuer asserts no role of this deployment.
            role_claims: if kind == IssuerKind::Federation {
                Vec::new()
            } else {
                crate::roles::default_claims()
            },
            kind,
            profile: Profile::default(),
            assurance: None,
            federation: None,
            attributes: None,
            sender_constraint: SenderConstraint::None,
        }
    }

    /// Checks the settings: the issuer URL rule, the endpoint's `https` rule,
    /// at least one audience, the clock skew bound, and the credential its
    /// method needs.
    ///
    /// # Errors
    ///
    /// Returns the [`IntrospectionError`] naming the first rule broken.
    pub fn validate(&self) -> Result<(), IntrospectionError> {
        crate::metadata::issuer_url(&self.issuer)?;
        if let Some(endpoint) = &self.endpoint {
            crate::metadata::secure(endpoint, "the introspection endpoint")?;
        }
        if self.audience.iter().all(String::is_empty) {
            return Err(IntrospectionError::NoAudience);
        }
        if self.clock_skew > super::MAX_CLOCK_SKEW {
            return Err(IntrospectionError::ClockSkew {
                skew: self.clock_skew,
            });
        }
        super::rules::check_issuer_rules(
            self.kind,
            &self.profile,
            self.assurance.as_ref(),
            self.federation.as_ref(),
            self.sender_constraint,
            &self.role_claims,
        )
        .and_then(|()| super::rules::check_attributes(self.kind, self.attributes.as_ref()))
        .map_err(|source| IntrospectionError::Rules {
            source: Box::new(source),
        })?;
        if let IntrospectionAuth::Client(credentials) = &self.auth {
            credentials
                .validate()
                .map_err(|source| IntrospectionError::Credential {
                    source: Arc::new(source),
                })?;
        }
        Ok(())
    }
}

/// A failure to set up the introspection check, or to complete one call to
/// the introspection endpoint.
///
/// No variant carries the token under check or the product's credential.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IntrospectionError {
    /// The metadata could not be read, the issuer or the endpoint is
    /// outside the URL rule, or the call never completed.
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
    /// The issuer's profile, assurance mapping or a kind-bound setting
    /// breaks a rule.
    #[error("the issuer settings are refused")]
    Rules {
        /// The rule.
        #[source]
        source: Box<ResourceError>,
    },
    /// The product's credential could not be used: a missing secret or
    /// key, an assertion that could not be signed, or a bearer token that
    /// could not be obtained.
    #[error("the credential of the introspection call could not be used")]
    Credential {
        /// Why.
        #[source]
        source: Arc<TokenError>,
    },
    /// The `DPoP` proof of the introspection call could not be signed
    /// (RFC 9449 §4.2); nothing was sent.
    #[error("the DPoP proof of the introspection call could not be signed")]
    Proof {
        /// Why.
        #[source]
        source: crate::client::dpop::DpopError,
    },
    /// The endpoint refused the bearer token (`401`) and no new one could
    /// be obtained.
    #[error(transparent)]
    Renewal {
        /// Why the new token could not be obtained.
        source: crate::client::RenewalError,
    },
    /// The settings name no audience.
    #[error("the introspection settings name no audience")]
    NoAudience,
    /// The clock skew is longer than [`super::MAX_CLOCK_SKEW`].
    #[error(
        "the clock skew of {skew:?} is longer than {:?}",
        super::MAX_CLOCK_SKEW
    )]
    ClockSkew {
        /// The skew configured.
        skew: Duration,
    },
    /// The settings name no endpoint and the metadata names none.
    #[error("the authorization server metadata names no introspection_endpoint")]
    NoEndpoint,
    /// The metadata names an introspection endpoint that is not a URL.
    #[error("the authorization server metadata names an introspection endpoint that is not a URL")]
    EndpointUrl {
        /// What the URL parser reported.
        #[source]
        source: url::ParseError,
    },
    /// The endpoint answered anything other than `200` (RFC 7662 §2.3), with
    /// the RFC 6749 §5.2 error code when the body carried one.
    #[error(
        "the introspection endpoint {url} answered {status}{}",
        if body.is_empty() { String::new() } else { format!(": {body}") }
    )]
    Status {
        /// The endpoint.
        url: Url,
        /// The status it answered.
        status: StatusCode,
        /// The RFC 6749 §5.2 `error` code the body carried, cut to
        /// [`MAX_ERROR_TEXT`](crate::client::MAX_ERROR_TEXT) characters, or empty when the body is no
        /// such error or its code leaves that section's character set;
        /// nothing else of the answer is kept.
        body: String,
    },
    /// The `200` body repeats a member name (RFC 8259 §4).
    #[error("the introspection response repeats a member name")]
    RepeatedName {
        /// What the JSON reader reported, with the position.
        #[source]
        source: crate::json::JsonError,
    },
    /// The `200` body is not the JSON object RFC 7662 §2.2 describes, or its
    /// `active` member is not a boolean.
    #[error("the introspection endpoint answered a body that is not an introspection response")]
    Malformed {
        /// What the JSON reader reported, when it was the reader that
        /// refused.
        #[source]
        source: Option<crate::json::JsonError>,
    },
}

impl IntrospectionError {
    /// Returns the status the authorization server answered, when the
    /// failure carries one.
    #[must_use]
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Discovery(DiscoveryError::Status { status, .. })
            | Self::Status { status, .. } => Some(*status),
            Self::Credential { source } => source.status(),
            Self::Renewal { source } => source.token_error().status(),
            _ => None,
        }
    }
}

/// One cached active response.
#[derive(Debug)]
struct Entry {
    /// When the response stops being used.
    until: Instant,
    /// The caller it admitted.
    caller: Caller,
    /// An estimate of the bytes the entry takes: its key, itself and the
    /// members of the response as JSON.
    bytes: usize,
}

/// Returns an estimate of the bytes a held `caller` takes under its
/// 32-byte key.
fn weigh(caller: &Caller) -> usize {
    size_of::<[u8; 32]>()
        .saturating_add(size_of::<Entry>())
        .saturating_add(super::verdict::json_bytes(caller.claims()))
}

/// The introspection check of one authorization server.
pub struct Introspector {
    /// What the deployment configured.
    settings: IntrospectionSettings,
    /// The authorization server's metadata.
    metadata: ServerMetadata,
    /// The introspection endpoint.
    endpoint: Url,
    /// The HTTP engine, with the TLS material of the client credential.
    http: Http,
    /// The resource types a clinical scope may name, when the product holds
    /// a table.
    resource_types: Option<ResourceTypes>,
    /// The product's values copied onto every caller this check admits.
    extensions: Extensions,
    /// The active responses, by the SHA-256 of the token, so no token is
    /// held in memory.
    cache: Mutex<BTreeMap<[u8; 32], Entry>>,
}

impl std::fmt::Debug for Introspector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Introspector")
            .field("issuer", &self.settings.issuer)
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl Introspector {
    /// Reads the issuer's metadata and returns the introspection check
    /// `settings` describe.
    ///
    /// The metadata is read once here, so an authorization server that
    /// cannot be reached refuses the start; it names the introspection
    /// endpoint unless the settings do, and builds the SMART discovery
    /// document. The metadata and introspection calls trust the roots of
    /// the credential's grant beside the platform's: the client grant's TLS
    /// material, or the bearer grant's trust roots.
    ///
    /// # Errors
    ///
    /// Returns every [`IntrospectionError`] of [`IntrospectionSettings::validate`],
    /// the metadata read, and an endpoint the metadata does not name or
    /// names outside the `https` rule.
    pub async fn discover(settings: IntrospectionSettings) -> Result<Self, IntrospectionError> {
        settings.validate()?;
        let http = match &settings.auth {
            IntrospectionAuth::Client(credentials) => {
                Http::with_tls(settings.timeout, &credentials.tls)?
            }
            IntrospectionAuth::Bearer(source) => Http::with_tls(settings.timeout, source.tls())?,
        };
        let metadata = http.discover(&settings.issuer).await?;
        let endpoint = if let Some(endpoint) = &settings.endpoint {
            endpoint.clone()
        } else {
            let endpoint = metadata
                .introspection_endpoint
                .as_deref()
                .ok_or(IntrospectionError::NoEndpoint)?
                .parse::<Url>()
                .map_err(|source| IntrospectionError::EndpointUrl { source })?;
            crate::metadata::secure(&endpoint, "the introspection_endpoint")?;
            endpoint
        };
        tracing::info!(
            issuer = %settings.issuer,
            %endpoint,
            "introspecting access tokens of this issuer"
        );
        Ok(Self {
            settings,
            metadata,
            endpoint,
            http,
            resource_types: None,
            extensions: Extensions::new(),
            cache: Mutex::new(BTreeMap::new()),
        })
    }

    /// Returns this check copying `value` onto every caller it admits.
    #[must_use]
    pub fn with_extension<T: Clone + Send + Sync + 'static>(mut self, value: T) -> Self {
        self.extensions.insert(value);
        self
    }

    /// Returns this check reading a clinical scope's resource type against
    /// `known`, in place of the lexical rule.
    #[must_use]
    pub fn with_resource_types(
        mut self,
        known: impl Fn(&str) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.resource_types = Some(Arc::new(known));
        self
    }

    /// Returns what the deployment configured.
    #[must_use]
    pub const fn settings(&self) -> &IntrospectionSettings {
        &self.settings
    }

    /// Returns the introspection endpoint the check calls.
    #[must_use]
    pub const fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    /// Returns the authorization server's metadata.
    #[must_use]
    pub const fn metadata(&self) -> &ServerMetadata {
        &self.metadata
    }

    /// Returns the SMART discovery document of this resource server under
    /// `options`.
    #[must_use]
    pub fn smart_configuration(&self, options: &configuration::SmartOptions) -> Value {
        configuration::document(&self.metadata, options)
    }

    /// Returns the caller `token` authenticates, from the cache while its
    /// response is held.
    ///
    /// # Errors
    ///
    /// Returns [`Rejection::Invalid`] for a token the endpoint reports not
    /// active, or whose response lacks a required member or names another
    /// issuer or audience, and [`Rejection::Upstream`] (`503`) when the
    /// endpoint could not be called or answered anything but an
    /// introspection response.
    pub async fn authenticate(&self, token: &str) -> Result<Caller, Rejection> {
        self.authenticate_bound(token, &Binding::bearer()).await
    }

    /// Returns the caller `token` authenticates, the response's `cnf` held
    /// to what `binding` proves and to the issuer's sender constraint on
    /// every request, a held response included ([`crate::sender`]).
    ///
    /// # Errors
    ///
    /// Returns every [`Rejection`] of [`Introspector::authenticate`], and
    /// [`Rejection::Invalid`] naming the [`crate::sender::Check`] for a
    /// token whose binding does not hold.
    pub async fn authenticate_bound(
        &self,
        token: &str,
        binding: &Binding,
    ) -> Result<Caller, Rejection> {
        let caller = self.lookup(token).await?;
        crate::sender::confirm(self.settings.sender_constraint, caller.claims(), binding)
            .map_err(|check| invalid(Reason::Sender(check)))?;
        Ok(caller)
    }

    /// Returns the caller of `token`, from the cache while its response is
    /// held.
    async fn lookup(&self, token: &str) -> Result<Caller, Rejection> {
        let key = super::verdict::digest(token);
        if let Some(held) = self.cached(&key) {
            // NOTE: no specification governs this: our own design; a held response is
            // classified again, so the issuer's standing answers every request.
            let (caller, _) = self.admit(held.claims().clone())?;
            return Ok(caller.with_cached(true));
        }
        let claims = self
            .introspect(token)
            .await
            .map_err(|error| Rejection::upstream(UPSTREAM, error))?;
        let (caller, exp) = self.admit(claims)?;
        self.hold(key, &caller, exp);
        Ok(caller)
    }

    /// Returns the members of the endpoint's response for `token`.
    async fn introspect(&self, token: &str) -> Result<Map<String, Value>, IntrospectionError> {
        // NOTE: no specification governs this: our own design; the form encoder
        // is not `Sync`, so each one is finished and dropped before an await.
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("token", token)
            .append_pair("token_type_hint", "access_token")
            .finish();
        let response = match &self.settings.auth {
            IntrospectionAuth::Client(credentials) => {
                let (request, body) = {
                    let mut form = url::form_urlencoded::Serializer::for_suffix(body, 0);
                    let request = crate::client::endpoint::authenticate(
                        self.request(),
                        &mut form,
                        credentials,
                        &self.endpoint,
                    )
                    .map_err(|source| IntrospectionError::Credential {
                        source: Arc::new(source),
                    })?;
                    (request, form.finish())
                };
                request
                    .body(body)
                    .send()
                    .await
                    .map_err(|source| self.transport(source))?
            }
            IntrospectionAuth::Bearer(source) => source
                .send(&http::Method::POST, &self.endpoint, |attempt| {
                    let mut request = self
                        .request()
                        .header(http::header::AUTHORIZATION, attempt.authorization().clone());
                    if let Some(proof) = attempt.proof() {
                        request = request.header(crate::client::dpop::HEADER, proof.clone());
                    }
                    request.body(body.clone()).send()
                })
                .await
                .map_err(|error| match error {
                    crate::client::CallError::Token { source } => {
                        IntrospectionError::Credential { source }
                    }
                    crate::client::CallError::Renewal(source) => {
                        IntrospectionError::Renewal { source }
                    }
                    crate::client::CallError::Call { source } => self.transport(source),
                    crate::client::CallError::Proof { source } => {
                        IntrospectionError::Proof { source }
                    }
                    crate::client::CallError::Unproven => IntrospectionError::Credential {
                        source: Arc::new(TokenError::Credential { what: "DPoP proof" }),
                    },
                })?,
        };
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|source| self.transport(source))?;
        if status != StatusCode::OK {
            return Err(IntrospectionError::Status {
                url: self.endpoint.clone(),
                status,
                body: refusal_code(&body),
            });
        }
        read_response(&body)
    }

    /// Returns the bare introspection request (RFC 7662 §2.1).
    fn request(&self) -> reqwest::RequestBuilder {
        self.http
            .client()
            .post(self.endpoint.clone())
            .header(http::header::ACCEPT, "application/json")
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
    }

    /// Returns the transport failure of a call to the endpoint.
    fn transport(&self, source: reqwest::Error) -> IntrospectionError {
        IntrospectionError::Discovery(DiscoveryError::Transport {
            url: self.endpoint.clone(),
            source,
        })
    }

    /// Returns the caller an introspection response describes, and its
    /// `exp`.
    fn admit(&self, claims: Map<String, Value>) -> Result<(Caller, i64), Rejection> {
        // NOTE: RFC 7662 §2.2, `active` is REQUIRED and only `true` names an
        // active token; anything else refuses it.
        if claims.get("active") != Some(&Value::Bool(true)) {
            return Err(invalid(Reason::Inactive));
        }
        // NOTE: SMART App Launch 2.2.0, Token Introspection, the response
        // "SHALL" include `scope`, `client_id` and `exp`.
        let exp = claims.get("exp").and_then(Value::as_i64);
        let (Some(exp), Some(_), Some(_)) = (
            exp,
            claims.get("scope").and_then(Value::as_str),
            claims.get("client_id").and_then(Value::as_str),
        ) else {
            return Err(invalid(Reason::MissingClaim));
        };
        let skew = i64::try_from(self.settings.clock_skew.as_secs()).unwrap_or(i64::MAX);
        let now = jiff::Timestamp::now().as_second();
        if exp <= now.saturating_sub(skew) {
            return Err(invalid(Reason::Expired));
        }
        if claims
            .get("nbf")
            .and_then(Value::as_i64)
            .is_some_and(|nbf| nbf > now.saturating_add(skew))
        {
            return Err(invalid(Reason::NotYetValid));
        }
        if let Some(issuer) = claims.get("iss") {
            let same = issuer.as_str().is_some_and(|issuer| {
                crate::metadata::check_issuer(&self.settings.issuer, issuer).is_ok()
            });
            if !same {
                return Err(invalid(Reason::Issuer));
            }
        }
        if claims.contains_key("aud") && !audience_holds(&claims, &self.settings.audience) {
            return Err(invalid(Reason::Audience));
        }
        // NOTE: RFC 6750 and RFC 9449 §6.2, a `token_type` is `Bearer`, or `DPoP`
        // exactly when the response binds the token to a key.
        if !crate::sender::token_type_holds(&claims) {
            return Err(invalid(Reason::Type));
        }
        // NOTE: RFC 9068 §2.2, a token no resource owner is involved in names
        // the client as `sub`, so a response without `sub` is the client's.
        let subject = match claims.get("sub") {
            None => text(&claims, "client_id").unwrap_or_default(),
            Some(Value::String(subject)) => subject.clone(),
            Some(_) => return Err(invalid(Reason::Subject)),
        };
        let caller = admit(
            claims,
            subject,
            &Admission {
                issuer: &self.settings.issuer,
                kind: self.settings.kind,
                profile: &self.settings.profile,
                assurance: self.settings.assurance.as_ref(),
                federation: self.settings.federation.as_ref(),
                attributes: self.settings.attributes.as_ref(),
                audiences: &self.settings.audience,
                clock_skew: self.settings.clock_skew,
                role_claims: &self.settings.role_claims,
                resource_types: self.resource_types.as_ref(),
                extensions: &self.extensions,
            },
        )?;
        Ok((caller, exp))
    }

    /// Returns the held caller of the token whose digest is `key`, when its
    /// response is still used.
    fn cached(&self, key: &[u8; 32]) -> Option<Caller> {
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        match cache.get(key) {
            Some(entry) if now < entry.until => Some(entry.caller.clone()),
            Some(_) => {
                cache.remove(key);
                None
            }
            None => None,
        }
    }

    /// Holds `caller` for the token whose digest is `key` until `exp` and at
    /// most the configured age (RFC 7662 §4: "the response MUST NOT be
    /// cached beyond the time indicated" by `exp`).
    fn hold(&self, key: [u8; 32], caller: &Caller, exp: i64) {
        let left = exp.saturating_sub(jiff::Timestamp::now().as_second());
        let left = Duration::from_secs(u64::try_from(left).unwrap_or(0));
        let age = left.min(self.settings.cache_max_age);
        if age.is_zero() || self.settings.cache_capacity == 0 {
            return;
        }
        let now = Instant::now();
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.len() >= self.settings.cache_capacity {
            cache.retain(|_, entry| now < entry.until);
        }
        if cache.len() >= self.settings.cache_capacity
            && let Some(soonest) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.until)
                .map(|(key, _)| *key)
        {
            cache.remove(&soonest);
        }
        cache.insert(
            key,
            Entry {
                until: now.checked_add(age).unwrap_or(now),
                caller: caller.clone(),
                bytes: weigh(caller),
            },
        );
    }

    /// Returns the cap, the entries and the estimated bytes of the response
    /// cache: per entry its key, its record and the response's members as
    /// JSON.
    #[must_use]
    pub fn cache_usage(&self) -> crate::usage::CacheUsage {
        let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        let bytes = cache
            .values()
            .map(|entry| entry.bytes)
            .fold(0_usize, usize::saturating_add);
        crate::usage::CacheUsage::new(self.settings.cache_capacity, cache.len(), bytes)
    }
}

impl Verifier for Introspector {
    fn verify<'a>(
        &'a self,
        token: &'a str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Caller, Rejection>> + Send + 'a>> {
        Box::pin(self.authenticate(token))
    }

    fn verify_bound<'a>(
        &'a self,
        token: &'a str,
        binding: &'a Binding,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Caller, Rejection>> + Send + 'a>> {
        Box::pin(self.authenticate_bound(token, binding))
    }
}

/// Returns the RFC 6749 §5.2 `error` code of the refusal `body`, cut to
/// [`MAX_ERROR_TEXT`](crate::client::MAX_ERROR_TEXT) characters, or an empty string when the body is no
/// such error or the code holds a character the section forbids.
fn refusal_code(body: &str) -> String {
    // NOTE: RFC 7662 §2.3 answers a refused client as RFC 6749 §5.2 does; a
    // body that is no such error is legitimately absent, and nothing is kept.
    let Ok(error) = serde_json::from_str::<OAuthError>(body) else {
        return String::new();
    };
    let code = error.bounded().error;
    let allowed = |c: char| matches!(c, '\x20'..='\x21' | '\x23'..='\x5B' | '\x5D'..='\x7E');
    if code.chars().all(allowed) {
        code
    } else {
        String::new()
    }
}

/// Returns the members of the introspection response `body`, refusing one
/// that repeats a member name (RFC 8259 §4) or is no JSON object.
fn read_response(body: &str) -> Result<Map<String, Value>, IntrospectionError> {
    if let Err(source) = crate::metadata::repeats_no_name(body.as_bytes()) {
        // NOTE: RFC 8259 §4, only the repeated-name refusal reads as a data
        // error, so any other failure is a body that is no JSON at all.
        if source.category() == serde_json::error::Category::Data {
            return Err(IntrospectionError::RepeatedName { source });
        }
        return Err(IntrospectionError::Malformed {
            source: Some(source),
        });
    }
    let claims: Map<String, Value> =
        serde_json::from_str(body).map_err(|source| IntrospectionError::Malformed {
            source: Some(source.into()),
        })?;
    if !matches!(claims.get("active"), Some(Value::Bool(_))) {
        return Err(IntrospectionError::Malformed { source: None });
    }
    Ok(claims)
}

/// Returns whether the `aud` of `claims`, a string or an array of strings
/// (RFC 7519 §4.1.3), names one of `audience`.
fn audience_holds(claims: &Map<String, Value>, audience: &[String]) -> bool {
    match claims.get("aud") {
        Some(Value::String(named)) => audience.iter().any(|expected| expected == named),
        Some(Value::Array(named)) => named
            .iter()
            .filter_map(Value::as_str)
            .any(|named| audience.iter().any(|expected| expected == named)),
        _ => false,
    }
}
