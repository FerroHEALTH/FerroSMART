// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! HTTP Basic authentication (RFC 7617): a credential verified against a
//! store of Argon2id hashes, and a credential sent to an upstream.
//!
//! Only the PHC hash of a password is ever held; verification is `argon2`'s,
//! never a comparison of our own. An unknown user still pays the key
//! derivation against a decoy hash, so the response time carries no
//! account-existence signal (no specification governs the hash or the
//! decoy: our own design, after the OWASP Password Storage Cheat Sheet).
//! The store holds the credential alone. A product grants each user its
//! scope and roles ([`PasswordStore::with_scope`],
//! [`PasswordStore::with_roles`], [`PasswordStore::with_grants`]), or adds
//! them to the verified caller ([`crate::resource::Caller::with_granted_scope`]),
//! so the same check serves a Basic caller and a bearer caller.

mod cache;

use std::collections::BTreeMap;
use std::sync::LazyLock;
use std::time::Duration;

use argon2::Argon2;
use argon2::PasswordHash;
use argon2::PasswordVerifier;
use base64::Engine as _;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::GeneralPurpose;
use base64::engine::GeneralPurposeConfig;
use http::HeaderValue;
use secrecy::ExposeSecret;
use secrecy::SecretString;

use crate::refusal::Reason;
use crate::scope::is_scope_token;
use cache::VerifiedCache;

/// The RFC 4648 §4 decoder of the RFC 7617 §2 credential, padded only:
/// RFC 7617 defers to RFC 4648 §4, and RFC 4648 §3.2 requires the pad
/// characters "unless the specification referring to this document
/// explicitly states otherwise", which RFC 7617 does not. A non-alphabet
/// byte, interior padding, or non-canonical trailing bits is refused too.
static BASIC_B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

/// The encoder of an outgoing credential, the same alphabet, padded.
static BASIC_B64_ENCODE: GeneralPurpose =
    GeneralPurpose::new(&alphabet::STANDARD, GeneralPurposeConfig::new());

/// The OWASP Password Storage Cheat Sheet §Argon2id floor: the memory cost
/// in KiB, the iteration count and the parallelism.
const MIN_M_COST: u32 = 19_456;
/// The iteration count of the floor.
const MIN_T_COST: u32 = 2;
/// The parallelism of the floor.
const MIN_P_COST: u32 = 1;

/// The PHC verified when no configured user matches the presented name.
///
/// It is derived at the OWASP Password Storage Cheat Sheet §Argon2id floor,
/// so the work matches a real verification; a fixed salt, because nothing
/// verifies against it.
static ENUMERATION_DEFENCE_PHC: LazyLock<Option<String>> = LazyLock::new(|| {
    let params = argon2::Params::new(MIN_M_COST, MIN_T_COST, MIN_P_COST, None).ok()?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2::password_hash::PasswordHasher::hash_password_with_salt(
        &argon2,
        b"no-such-user-placeholder",
        b"ferrohealth-enumeration-defence",
    )
    .ok()
    .map(|hash| hash.to_string())
});

/// A store entry or an outgoing credential that does not hold.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The hash of `username` is not a PHC string `argon2` can read.
    #[error("the password hash of user {username:?} is not a PHC string")]
    Malformed {
        /// The user whose hash is malformed.
        username: String,
    },
    /// The hash of `username` costs less than the OWASP Password Storage
    /// Cheat Sheet §Argon2id floor, `m=19456,t=2,p=1`; the verifier reads
    /// its cost from the stored string, so a cheaper hash would verify.
    #[error(
        "the password hash of user {username:?} costs m={m},t={t},p={p}, below the floor m={MIN_M_COST},t={MIN_T_COST},p={MIN_P_COST}"
    )]
    Weak {
        /// The user whose hash is weak.
        username: String,
        /// Its memory cost, in KiB.
        m: u32,
        /// Its iteration count.
        t: u32,
        /// Its parallelism.
        p: u32,
    },
    /// The hash of `username` names an algorithm other than Argon2id.
    #[error("the password hash of user {username:?} is {found}, not argon2id")]
    Algorithm {
        /// The user whose hash is of another algorithm.
        username: String,
        /// The algorithm the hash names.
        found: String,
    },
    /// The user-id is empty, carries a colon or carries a control character,
    /// which RFC 7617 §2 forbids.
    #[error("the user-id {username:?} is empty or carries a colon or a control character")]
    UserId {
        /// The user-id.
        username: String,
    },
    /// A scope token of `username` is outside the RFC 6749 §3.3 character
    /// set.
    #[error("the scope {scope:?} of user {username:?} is outside the RFC 6749 scope character set")]
    Scope {
        /// The user.
        username: String,
        /// The scope token.
        scope: String,
    },
    /// A role of `username` is empty or carries whitespace or a control
    /// character.
    #[error("a role of user {username:?} is empty or carries whitespace or a control character")]
    Role {
        /// The user.
        username: String,
        /// The role.
        role: String,
    },
    /// A scope or roles are granted to a user the store does not admit.
    #[error("a grant names the user {username:?}, whom the store does not admit")]
    UnknownUser {
        /// The user.
        username: String,
    },
    /// The key of the verified-credential cache could not be drawn from
    /// the system's random source.
    #[error("the key of the verified-credential cache could not be drawn")]
    CacheKey,
    /// `username` is granted a `system/` scope, a backend service's grant
    /// (SMART App Launch 2.2.0, Scopes and Launch Context): a Basic
    /// credential is a person's, and a machine authenticates with the client
    /// credentials grant (RFC 6749 §4.4).
    #[error(
        "the user {username:?} is granted the system scope {scope:?}, which a Basic credential, a person's, never carries"
    )]
    SystemScope {
        /// The user.
        username: String,
        /// The `system/` scope token.
        scope: String,
    },
}

/// A credential that does not hold.
///
/// Every failure on the credential path is this one outcome, deliberately:
/// a caller must not learn from the `401` whether the header was malformed,
/// the user unknown, or the password wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the Basic credential does not hold")]
pub struct InvalidCredential;

/// The user a credential authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The user-id.
    pub username: String,
    /// The space-delimited scope the product grants the user (RFC 6749
    /// §3.3), empty when it grants none.
    pub scope: String,
    /// The roles the product grants the user ([`crate::roles`]).
    pub roles: Vec<String>,
    /// Whether the credential was admitted without this request's own key
    /// derivation: from the verified-credential cache, or from the derivation
    /// a concurrent request with the same credential ran.
    pub cached: bool,
}

/// One user of the store.
#[derive(Debug)]
struct Entry {
    /// The Argon2id PHC string of the password.
    hash: SecretString,
    /// The scope the user is granted.
    scope: String,
    /// The roles the user is granted.
    roles: Vec<String>,
}

/// The users a surface admits with HTTP Basic, by name, each with the
/// Argon2id PHC hash of its password and the scope and roles the product
/// grants it.
#[derive(Debug, Default)]
pub struct PasswordStore {
    /// Each user, by user-id.
    users: BTreeMap<String, Entry>,
    /// The credentials verified within their lifetime, when the store keeps
    /// them.
    cache: Option<VerifiedCache>,
}

impl PasswordStore {
    /// Returns an empty store, which admits no one.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns this store keeping a credential that verified for at most
    /// `ttl`, so a repeat request within it skips the key derivation; a zero
    /// `ttl` keeps none.
    ///
    /// Only a credential that verified is kept, named by an HMAC-SHA-256 of
    /// `user-id:password` under a key drawn here, never the password
    /// itself, so a wrong password always pays the derivation. Each entry
    /// lives between nine tenths of `ttl` and `ttl`, by a jitter per
    /// credential; in its last tenth one request re-derives it while the
    /// others are still admitted, and concurrent misses for one credential
    /// share one derivation. The cache holds at most 4096 credentials: a
    /// full one keeps what it holds and admits no new entry until one
    /// expires, so a credential beyond the cap pays the derivation on every
    /// request. No specification governs the cache: our own design.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CacheKey`] when the key cannot be drawn.
    pub fn with_cache(mut self, ttl: Duration) -> Result<Self, StoreError> {
        self.cache = if ttl.is_zero() {
            None
        } else {
            Some(VerifiedCache::new(ttl)?)
        };
        Ok(self)
    }

    /// Returns the cap, the entries and the estimated bytes of the
    /// verified-credential cache, or `None` when the store keeps none.
    #[must_use]
    pub fn cache_usage(&self) -> Option<crate::usage::CacheUsage> {
        self.cache.as_ref().map(VerifiedCache::usage)
    }

    /// Returns this store admitting `username` with the password `hash`
    /// names, an Argon2id PHC string, granted no scope and no role until
    /// [`PasswordStore::with_scope`] or [`PasswordStore::with_roles`] grants
    /// them.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for a hash that does not parse, names
    /// another algorithm or costs less than the OWASP floor
    /// ([`StoreError::Weak`]), or a user-id that is empty or carries a colon
    /// or a control character.
    pub fn with_user(
        mut self,
        username: impl Into<String>,
        hash: SecretString,
    ) -> Result<Self, StoreError> {
        let username = username.into();
        if !user_id_ok(&username) {
            return Err(StoreError::UserId { username });
        }
        let parsed = PasswordHash::new(hash.expose_secret()).map_err(|_malformed| {
            StoreError::Malformed {
                username: username.clone(),
            }
        })?;
        if parsed.algorithm.as_str() != "argon2id" {
            return Err(StoreError::Algorithm {
                found: parsed.algorithm.as_str().to_owned(),
                username,
            });
        }
        let params =
            argon2::Params::try_from(&parsed).map_err(|_malformed| StoreError::Malformed {
                username: username.clone(),
            })?;
        if params.m_cost() < MIN_M_COST
            || params.t_cost() < MIN_T_COST
            || params.p_cost() < MIN_P_COST
        {
            return Err(StoreError::Weak {
                username,
                m: params.m_cost(),
                t: params.t_cost(),
                p: params.p_cost(),
            });
        }
        self.users.insert(
            username,
            Entry {
                hash,
                scope: String::new(),
                roles: Vec::new(),
            },
        );
        Ok(self)
    }

    /// Returns this store granting the space-delimited `scope` to
    /// `username`, a user it already admits, in place of any scope granted
    /// before.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownUser`] when the store admits no such
    /// user, [`StoreError::Scope`] for a scope token outside RFC 6749 §3.3,
    /// and [`StoreError::SystemScope`] for a `system/` scope.
    pub fn with_scope(mut self, username: &str, scope: &str) -> Result<Self, StoreError> {
        if let Some(bad) = scope
            .split(' ')
            .filter(|token| !token.is_empty())
            .find(|token| !is_scope_token(token))
        {
            return Err(StoreError::Scope {
                scope: bad.to_owned(),
                username: username.to_owned(),
            });
        }
        if let Some(system) = scope.split(' ').find(|token| is_system_scope(token)) {
            return Err(StoreError::SystemScope {
                scope: system.to_owned(),
                username: username.to_owned(),
            });
        }
        scope.clone_into(&mut self.entry(username)?.scope);
        Ok(self)
    }

    /// Returns this store granting `roles` to `username`, a user it already
    /// admits, in place of any roles granted before.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownUser`] when the store admits no such
    /// user, and [`StoreError::Role`] for a role that is empty or carries
    /// whitespace or a control character ([`crate::roles::is_role`]).
    pub fn with_roles(mut self, username: &str, roles: Vec<String>) -> Result<Self, StoreError> {
        if let Some(bad) = roles.iter().find(|role| !crate::roles::is_role(role)) {
            return Err(StoreError::Role {
                username: username.to_owned(),
                role: bad.clone(),
            });
        }
        self.entry(username)?.roles = roles;
        Ok(self)
    }

    /// Returns this store granting each user of `grants` its scopes and
    /// roles, the table a product that keeps them in its own configuration
    /// reads ([`crate::config::BasicGrants`]).
    ///
    /// # Errors
    ///
    /// Returns the [`StoreError`] of [`PasswordStore::with_scope`] or
    /// [`PasswordStore::with_roles`] for the first grant that does not
    /// hold, [`StoreError::UnknownUser`] for a grant naming a user the store
    /// does not admit.
    pub fn with_grants(self, grants: &crate::config::BasicGrants) -> Result<Self, StoreError> {
        grants
            .users
            .iter()
            .try_fold(self, |store, (username, grant)| {
                store
                    .with_scope(username, &grant.scopes.join(" "))?
                    .with_roles(username, grant.roles.clone())
            })
    }

    /// Returns the entry of `username`.
    fn entry(&mut self, username: &str) -> Result<&mut Entry, StoreError> {
        self.users
            .get_mut(username)
            .ok_or_else(|| StoreError::UnknownUser {
                username: username.to_owned(),
            })
    }

    /// Returns how many users the store admits.
    #[must_use]
    pub fn len(&self) -> usize {
        self.users.len()
    }

    /// Returns the user-ids the store admits, in order.
    pub fn users(&self) -> impl Iterator<Item = &str> {
        self.users.keys().map(String::as_str)
    }

    /// Returns whether the store admits no one.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    /// Returns the user a `Basic <credentials>` header value authenticates.
    ///
    /// The scheme is compared case-insensitively (RFC 9110 §11.1) and the
    /// octets are read as UTF-8 (RFC 7617 §2.1). The key derivation runs on
    /// the calling thread and takes tens of milliseconds, so an async caller
    /// runs it on a blocking thread.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCredential`] for a malformed header, an unknown user,
    /// or a password that does not match.
    pub fn verify(&self, header: &HeaderValue) -> Result<Verified, InvalidCredential> {
        self.check(header).map_err(|_reason| InvalidCredential)
    }

    /// Returns the user a `Basic <credentials>` header value authenticates,
    /// or which check refused it, for the gate's log.
    ///
    /// A credential the cache holds within its lifetime is admitted without
    /// the key derivation; one that verifies is added to it, and concurrent
    /// misses with one credential run one derivation between them.
    pub(crate) fn check(&self, header: &HeaderValue) -> Result<Verified, Reason> {
        let decoded = decode(header)?;
        let (username, password) = decoded.split_once(':').ok_or(Reason::BasicMalformed)?;
        let derive = || self.verify_password(username, password);
        match &self.cache {
            Some(cache) => cache.admit(&decoded, derive),
            None => derive(),
        }
        .map_err(|_invalid| Reason::BasicRejected)
    }

    /// Returns the user a `Basic <credentials>` header value authenticates
    /// when the verified-credential cache holds it before its refresh point,
    /// with no key derivation, so an async caller needs no blocking thread.
    /// `None` for anything else: [`check`](Self::check) then decides.
    #[cfg(feature = "axum")]
    pub(crate) fn cached(&self, header: &HeaderValue) -> Option<Verified> {
        let cache = self.cache.as_ref()?;
        // NOTE: a header that does not decode is no cache hit; `check` names its refusal.
        let decoded = decode(header).ok()?;
        cache.fresh(&decoded)
    }

    /// Returns `username` when `password` is the one its hash names.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCredential`] for an unknown user or a password that
    /// does not match.
    pub fn verify_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Verified, InvalidCredential> {
        let Some(entry) = self.users.get(username) else {
            if let Some(phc) = ENUMERATION_DEFENCE_PHC.as_deref()
                && let Ok(decoy) = PasswordHash::new(phc)
            {
                // The outcome is discarded deliberately: only the work matters.
                let _outcome = Argon2::default().verify_password(password.as_bytes(), &decoy);
            }
            return Err(InvalidCredential);
        };
        let parsed = PasswordHash::new(entry.hash.expose_secret())
            .map_err(|_malformed| InvalidCredential)?;
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .map_err(|_mismatch| InvalidCredential)?;
        Ok(Verified {
            username: username.to_owned(),
            scope: entry.scope.clone(),
            roles: entry.roles.clone(),
            cached: false,
        })
    }
}

/// Returns the `user-id:password` a `Basic <credentials>` header value
/// carries: the scheme compared case-insensitively (RFC 9110 §11.1), the
/// token base64 (RFC 7617 §2) and its octets UTF-8 (RFC 7617 §2.1).
fn decode(header: &HeaderValue) -> Result<String, Reason> {
    let raw = header.to_str().map_err(|_opaque| Reason::BasicMalformed)?;
    let (scheme, encoded) = raw.split_once(' ').ok_or(Reason::BasicMalformed)?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return Err(Reason::BasicMalformed);
    }
    let decoded = BASIC_B64
        .decode(encoded.trim())
        .map_err(|_malformed| Reason::BasicMalformed)?;
    String::from_utf8(decoded).map_err(|_opaque| Reason::BasicMalformed)
}

/// Returns whether `username` is a user-id RFC 7617 §2 admits: not empty,
/// no colon, no control character.
fn user_id_ok(username: &str) -> bool {
    !username.is_empty() && !username.chars().any(|c| c == ':' || c.is_control())
}

/// Returns whether `token` is a `system/` scope, the grant of a backend
/// service (SMART App Launch 2.2.0, Scopes and Launch Context), in either
/// grammar: SMART on FHIR or SMART on openEHR.
pub(crate) fn is_system_scope(token: &str) -> bool {
    token.starts_with("system/")
}

/// A credential sent to an upstream with HTTP Basic.
///
/// The `Debug` rendering never carries the password.
#[derive(Clone)]
pub struct Credential {
    /// The user-id.
    username: String,
    /// The password.
    password: SecretString,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl Credential {
    /// Returns the credential of `username` with `password`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UserId`] for a user-id that is empty or carries
    /// a colon or a control character, which RFC 7617 §2 forbids.
    pub fn new(username: impl Into<String>, password: SecretString) -> Result<Self, StoreError> {
        let username = username.into();
        if !user_id_ok(&username) {
            return Err(StoreError::UserId { username });
        }
        Ok(Self { username, password })
    }

    /// Returns the user-id.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Returns the password, still behind [`SecretString`], for an HTTP
    /// client that takes the user-id and the password itself rather than
    /// the field value of [`Credential::header_value`].
    ///
    /// The value is read only through [`ExposeSecret`] at the call site, and
    /// its `Debug` rendering stays redacted.
    #[must_use]
    pub const fn password(&self) -> &SecretString {
        &self.password
    }

    /// Returns the `Authorization` field value of the credential (RFC 7617
    /// §2, UTF-8 then base64), marked sensitive so a header `Debug`
    /// rendering never shows it.
    #[must_use]
    pub fn header_value(&self) -> HeaderValue {
        let user_pass = format!("{}:{}", self.username, self.password.expose_secret());
        let encoded = BASIC_B64_ENCODE.encode(user_pass.as_bytes());
        // NOTE: RFC 4648 §4 emits only alphabet and pad characters, so the
        // value is always a legal field value and this never fails.
        let mut value = HeaderValue::from_str(&format!("Basic {encoded}"))
            .unwrap_or_else(|_never| HeaderValue::from_static("Basic"));
        value.set_sensitive(true);
        value
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Credential, ENUMERATION_DEFENCE_PHC, InvalidCredential, PasswordStore, StoreError, Verified,
    };
    use crate::refusal::Reason;
    use argon2::password_hash::PasswordHasher;
    use argon2::{Argon2, PasswordHash};
    use base64::Engine as _;
    use http::HeaderValue;
    use secrecy::{ExposeSecret, SecretString};
    use std::time::Duration;

    fn hash(password: &str) -> SecretString {
        // A fixed salt keeps the test hermetic without a random source.
        SecretString::from(
            Argon2::default()
                .hash_password_with_salt(password.as_bytes(), b"synthetic-salt-16")
                .expect("the hash")
                .to_string(),
        )
    }

    fn store() -> PasswordStore {
        PasswordStore::new()
            .with_user("alice", hash("s3cret"))
            .and_then(|store| store.with_scope("alice", "user/*.rs"))
            .expect("a well-formed hash")
    }

    fn header(scheme: &str, user: &str, password: &str) -> HeaderValue {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        HeaderValue::from_str(&format!("{scheme} {token}")).expect("a legal value")
    }

    fn raw(token: &str) -> HeaderValue {
        HeaderValue::from_str(&format!("Basic {token}")).expect("a legal value")
    }

    #[test]
    fn a_valid_credential_names_its_user_and_scope() {
        let verified = Verified {
            username: String::from("alice"),
            scope: String::from("user/*.rs"),
            roles: Vec::new(),
            cached: false,
        };
        assert_eq!(
            Ok(verified.clone()),
            store().verify(&header("Basic", "alice", "s3cret"))
        );
        assert_eq!(
            Ok(verified),
            store().verify(&header("basic", "alice", "s3cret"))
        );
    }

    #[test]
    fn a_verified_credential_is_cached_for_its_lifetime_and_a_wrong_one_never() {
        let store = store()
            .with_cache(Duration::from_secs(60))
            .expect("the cache key is drawn");
        let cache = store.cache.as_ref().expect("a cache");
        assert_eq!(None, cache.get("alice:s3cret"));
        assert!(store.verify(&header("Basic", "alice", "s3cret")).is_ok());
        assert_eq!(
            Some(String::from("alice")),
            cache.get("alice:s3cret").map(|verified| verified.username),
            "a repeat request skips the key derivation"
        );
        assert_eq!(
            Err(Reason::BasicRejected),
            store.check(&header("Basic", "alice", "nope"))
        );
        assert_eq!(
            None,
            cache.get("alice:nope"),
            "a wrong password is never kept"
        );
        assert_eq!(Err(Reason::BasicMalformed), store.check(&raw("QQ===")));
    }

    #[test]
    fn the_outcome_says_whether_the_cache_admitted_the_credential() {
        let cached = store()
            .with_cache(Duration::from_secs(60))
            .expect("the cache key is drawn");
        let first = cached
            .verify(&header("Basic", "alice", "s3cret"))
            .expect("verifies");
        assert!(!first.cached, "the first request pays the key derivation");
        let repeat = cached
            .verify(&header("Basic", "alice", "s3cret"))
            .expect("verifies");
        assert!(repeat.cached, "the repeat is admitted from the cache");
        let uncached = store();
        for _ in 0..2 {
            let verified = uncached
                .verify(&header("Basic", "alice", "s3cret"))
                .expect("verifies");
            assert!(!verified.cached, "no cache, never cached");
        }
    }

    #[test]
    fn parallel_requests_with_an_uncached_credential_run_one_key_derivation() {
        const REQUESTS: usize = 16;
        let store = store()
            .with_cache(Duration::from_secs(60))
            .expect("the cache key is drawn");
        let start = std::sync::Barrier::new(REQUESTS);
        let derived = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..REQUESTS)
                .map(|_| {
                    scope.spawn(|| {
                        start.wait();
                        store.verify(&header("Basic", "alice", "s3cret"))
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("the request thread ends"))
                .filter(|outcome| !outcome.as_ref().expect("every request is admitted").cached)
                .count()
        });
        assert_eq!(1, derived, "one Argon2id derivation for the burst");
    }

    #[test]
    fn the_store_reports_its_cache_when_it_keeps_one() {
        assert_eq!(None, store().cache_usage(), "no cache, nothing to report");
        let cached = store()
            .with_cache(Duration::from_secs(60))
            .expect("the cache key is drawn");
        let empty = cached.cache_usage().expect("a cache");
        assert_eq!((4096, 0, 0), (empty.capacity, empty.entries, empty.bytes));
        assert!(cached.verify(&header("Basic", "alice", "s3cret")).is_ok());
        assert!(cached.verify(&header("Basic", "alice", "nope")).is_err());
        let held = cached.cache_usage().expect("a cache");
        assert_eq!(1, held.entries, "only the credential that verified");
        assert!(held.bytes > 0);
    }

    #[test]
    fn a_cached_credential_expires_and_a_zero_lifetime_keeps_none() {
        let store = store()
            .with_cache(Duration::from_millis(1))
            .expect("the cache key is drawn");
        assert!(store.verify(&header("Basic", "alice", "s3cret")).is_ok());
        std::thread::sleep(Duration::from_millis(5));
        let cache = store.cache.as_ref().expect("a cache");
        assert_eq!(None, cache.get("alice:s3cret"), "expired");
        let none = PasswordStore::new()
            .with_cache(Duration::ZERO)
            .expect("no key needed");
        assert!(none.cache.is_none());
    }

    #[test]
    fn a_wrong_password_an_unknown_user_and_another_scheme_are_one_refusal() {
        assert_eq!(
            Err(InvalidCredential),
            store().verify(&header("Basic", "alice", "nope"))
        );
        assert_eq!(
            Err(InvalidCredential),
            store().verify(&header("Basic", "bob", "s3cret"))
        );
        assert_eq!(
            Err(InvalidCredential),
            store().verify(&header("Bearer", "alice", "s3cret"))
        );
    }

    #[test]
    fn an_unknown_user_pays_the_kdf_against_an_argon2id_decoy() {
        let phc = ENUMERATION_DEFENCE_PHC
            .as_deref()
            .expect("the decoy derives at the OWASP floor");
        let parsed = PasswordHash::new(phc).expect("the decoy parses");
        assert_eq!("argon2id", parsed.algorithm.as_str());
        let params = argon2::Params::try_from(&parsed).expect("the params");
        assert_eq!(19_456, params.m_cost());
        assert_eq!(2, params.t_cost());
        assert_eq!(1, params.p_cost());
        assert_eq!(
            Err(InvalidCredential),
            store().verify(&header("Basic", "no-such-user", "no-such-user-placeholder")),
            "the decoy never authenticates"
        );
    }

    #[test]
    fn the_padded_canonical_form_is_the_credential() {
        let padded = base64::engine::general_purpose::STANDARD.encode("alice:s3cre");
        assert!(padded.ends_with('='), "the fixture pads");
        assert_eq!(
            Err(InvalidCredential),
            store().verify(&raw(padded.trim_end_matches('=')))
        );
        assert_eq!(
            Err(InvalidCredential),
            store().verify(&raw("YWxpY2U6*zNjcmV0"))
        );
        assert_eq!(Err(InvalidCredential), store().verify(&raw("QQ===")));
        assert_eq!(
            Err(InvalidCredential),
            store().verify(&raw("YWx=pY2U6czNjcmV0"))
        );
    }

    #[test]
    fn a_store_refuses_a_bad_hash_user_id_or_scope() {
        assert!(
            PasswordStore::new()
                .with_user("alice", SecretString::from("not-a-phc"))
                .is_err()
        );
        assert!(
            PasswordStore::new()
                .with_user(
                    "alice",
                    SecretString::from("$pbkdf2-sha256$i=1000,l=32$c2FsdA$YWJj")
                )
                .is_err()
        );
        assert!(PasswordStore::new().with_user("a:b", hash("x")).is_err());
        assert!(PasswordStore::new().with_user("", hash("x")).is_err());
        assert!(PasswordStore::new().with_user("a\tb", hash("x")).is_err());
        assert!(matches!(
            PasswordStore::new()
                .with_user("a", hash("x"))
                .and_then(|store| store.with_scope("a", "user/*.rs bad\"scope")),
            Err(StoreError::Scope { .. })
        ));
        assert!(PasswordStore::new().is_empty());
        assert_eq!(1, store().len());
    }

    #[test]
    fn an_outgoing_credential_is_rfc_7617_and_its_debug_hides_the_password() {
        let credential =
            Credential::new("ferro", SecretString::from("synthetic-pw")).expect("a legal user-id");
        let value = credential.header_value();
        assert_eq!(
            "Basic ZmVycm86c3ludGhldGljLXB3",
            value.to_str().expect("ASCII")
        );
        assert!(value.is_sensitive());
        assert!(!format!("{credential:?}").contains("synthetic-pw"));
        assert_eq!("ferro", credential.username());
        assert_eq!("synthetic-pw", credential.password().expose_secret());
        assert!(!format!("{:?}", credential.password()).contains("synthetic-pw"));
        assert!(Credential::new("fer:ro", SecretString::from("x")).is_err());
        let utf8 = Credential::new("Müller", SecretString::from("pässwörd")).expect("UTF-8");
        assert_eq!(
            "Basic TcO8bGxlcjpww6Rzc3fDtnJk",
            utf8.header_value().to_str().expect("ASCII")
        );
    }
}
