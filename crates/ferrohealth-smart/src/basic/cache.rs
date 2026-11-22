// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The verified-credential cache of a [`super::PasswordStore`].
//!
//! A credential that verified is kept under an HMAC-SHA-256 of
//! `user-id:password` under a key drawn when the cache is built, so the
//! password is never held and an entry's name cannot be computed without
//! the key. An entry lives at most the configured lifetime from the key
//! derivation that admitted it, shortened per credential by a jitter of up to
//! a tenth, so entries derived together do not expire together. In the last
//! tenth of the lifetime one request re-derives the credential while the
//! others are still admitted from the entry; a re-derivation that fails drops
//! the entry. Concurrent misses for one credential share one derivation: the
//! first runs it, the others wait for its outcome. No specification governs
//! the cache: our own design.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::time::Duration;
use std::time::Instant;

use aws_lc_rs::hmac;
use aws_lc_rs::rand::SystemRandom;

use super::InvalidCredential;
use super::StoreError;
use super::Verified;
use crate::usage::CacheUsage;

/// The most credentials a [`VerifiedCache`] holds; a full cache admits no
/// new entry until one expires (no specification governs the bound: our own
/// design).
pub(super) const MAX_CACHED: usize = 4096;

/// The share of the lifetime the jitter and the refresh window each span,
/// as a divisor: a tenth.
const SPAN_DIVISOR: u32 = 10;

/// The credentials that verified, each kept within the cache's lifetime under
/// a keyed hash of `user-id:password`, so the password itself is never held.
pub(super) struct VerifiedCache {
    /// The longest an entry lives from the derivation that admitted it.
    ttl: Duration,
    /// The HMAC key the entries are named with, drawn when the cache is
    /// built.
    key: hmac::Key,
    /// Each entry, by the keyed hash of its credential.
    entries: Mutex<BTreeMap<Vec<u8>, Cached>>,
    /// The derivation running for a credential, by the keyed hash of it.
    flights: Mutex<BTreeMap<Vec<u8>, Arc<Flight>>>,
}

/// One kept credential.
struct Cached {
    /// From when one request re-derives the credential.
    refresh_at: Instant,
    /// When the entry stops admitting.
    expires: Instant,
    /// The user the credential verified as.
    verified: Verified,
}

/// What a lookup found for a credential.
enum Lookup {
    /// An entry before its refresh point.
    Fresh(Verified),
    /// An entry in its refresh window, still admitting.
    Stale(Verified),
    /// No unexpired entry.
    Missing,
}

/// One derivation in progress, which the requests that missed with the same
/// credential wait on.
struct Flight {
    /// The outcome, once the derivation ends.
    outcome: Mutex<Option<Landed>>,
    /// Signalled when the outcome is set.
    landed: Condvar,
}

/// How a derivation ended.
#[derive(Clone)]
enum Landed {
    /// The credential verified as this user.
    Verified(Verified),
    /// The credential does not hold.
    Rejected,
    /// The derivation did not finish (its thread unwound), so a waiter runs
    /// its own.
    Abandoned,
}

/// What a request that misses does.
enum Role<'cache> {
    /// The entry appeared while the request looked for a flight.
    Admitted(Verified),
    /// The request runs the derivation for every request waiting on it.
    Lead(Lead<'cache>),
    /// The request waits on the derivation another request runs.
    Follow(Arc<Flight>),
}

/// The leader of a [`Flight`], which publishes its outcome exactly once,
/// [`Landed::Abandoned`] when it is dropped without one.
struct Lead<'cache> {
    /// The cache the flight belongs to.
    cache: &'cache VerifiedCache,
    /// The keyed hash of the credential.
    name: Vec<u8>,
    /// The flight the waiters hold.
    flight: Arc<Flight>,
    /// Whether the outcome was published.
    published: bool,
}

impl std::fmt::Debug for VerifiedCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedCache")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl VerifiedCache {
    /// Returns an empty cache keeping a credential at most `ttl`.
    pub(super) fn new(ttl: Duration) -> Result<Self, StoreError> {
        let key = hmac::Key::generate(hmac::HMAC_SHA256, &SystemRandom::new())
            .map_err(|_unspecified| StoreError::CacheKey)?;
        Ok(Self {
            ttl,
            key,
            entries: Mutex::new(BTreeMap::new()),
            flights: Mutex::new(BTreeMap::new()),
        })
    }

    /// Returns the user of `user_pass`: from the cache within its lifetime,
    /// else from `derive`, run once for every request that misses with the
    /// same credential at the same time.
    ///
    /// A request admitted without running `derive` itself carries
    /// [`Verified::cached`].
    pub(super) fn admit<F>(&self, user_pass: &str, derive: F) -> Result<Verified, InvalidCredential>
    where
        F: FnOnce() -> Result<Verified, InvalidCredential>,
    {
        let name = self.name(user_pass);
        match self.lookup(&name) {
            Lookup::Fresh(verified) => Ok(cached(verified)),
            Lookup::Stale(verified) => match self.refresh_lead(&name) {
                Some(lead) => lead.run(derive),
                None => Ok(cached(verified)),
            },
            Lookup::Missing => match self.join(&name) {
                Some(Role::Admitted(verified)) => Ok(cached(verified)),
                Some(Role::Lead(lead)) => lead.run(derive),
                Some(Role::Follow(flight)) => match flight.wait() {
                    Some(Landed::Verified(verified)) => Ok(cached(verified)),
                    Some(Landed::Rejected) => Err(InvalidCredential),
                    Some(Landed::Abandoned) | None => self.uncoalesced(&name, derive),
                },
                None => self.uncoalesced(&name, derive),
            },
        }
    }

    /// Returns the user of `user_pass` when the cache holds it before its
    /// refresh point, which needs no key derivation; `None` when a request
    /// must go through [`admit`](Self::admit).
    #[cfg(feature = "axum")]
    pub(super) fn fresh(&self, user_pass: &str) -> Option<Verified> {
        match self.lookup(&self.name(user_pass)) {
            Lookup::Fresh(verified) => Some(cached(verified)),
            Lookup::Stale(_) | Lookup::Missing => None,
        }
    }

    /// Returns the cap, the entries and the estimated bytes of the cache:
    /// per entry its 32-byte name and its record with the text it owns.
    pub(super) fn usage(&self) -> CacheUsage {
        // NOTE: no specification governs the cache: our own design, and a
        // poisoned lock holds entries the next write may still read, so it is read.
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let bytes = entries
            .iter()
            .map(|(name, entry)| {
                let verified = &entry.verified;
                let roles: usize = verified
                    .roles
                    .iter()
                    .map(|role| size_of::<String>().saturating_add(role.len()))
                    .sum();
                size_of::<Vec<u8>>()
                    .saturating_add(name.len())
                    .saturating_add(size_of::<Cached>())
                    .saturating_add(verified.username.len())
                    .saturating_add(verified.scope.len())
                    .saturating_add(roles)
            })
            .fold(0_usize, usize::saturating_add);
        CacheUsage::new(MAX_CACHED, entries.len(), bytes)
    }

    /// Returns the user of `user_pass` when the cache holds it unexpired.
    #[cfg(test)]
    pub(super) fn get(&self, user_pass: &str) -> Option<Verified> {
        match self.lookup(&self.name(user_pass)) {
            Lookup::Fresh(verified) | Lookup::Stale(verified) => Some(verified),
            Lookup::Missing => None,
        }
    }

    /// Returns the refresh point and the expiry of the entry of `user_pass`.
    #[cfg(test)]
    fn deadlines(&self, user_pass: &str) -> Option<(Instant, Instant)> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(&self.name(user_pass))?;
        Some((entry.refresh_at, entry.expires))
    }

    /// Returns the name of the credential `user_pass` in the cache.
    fn name(&self, user_pass: &str) -> Vec<u8> {
        hmac::sign(&self.key, user_pass.as_bytes())
            .as_ref()
            .to_vec()
    }

    /// Returns what the cache holds for `name` now.
    fn lookup(&self, name: &[u8]) -> Lookup {
        // NOTE: no specification governs the cache: our own design, and a
        // poisoned lock is a miss, which only costs the key derivation.
        let Ok(entries) = self.entries.lock() else {
            return Lookup::Missing;
        };
        lookup_in(&entries, name, Instant::now())
    }

    /// Returns the role of a request that missed `name`: the leader of a new
    /// flight, a follower of the running one, or admitted when an entry
    /// landed meanwhile. `None` when a lock is poisoned.
    fn join(&self, name: &[u8]) -> Option<Role<'_>> {
        let mut flights = self.flights.lock().ok()?;
        if let Some(flight) = flights.get(name) {
            return Some(Role::Follow(Arc::clone(flight)));
        }
        // NOTE: a leader stores its entry before it leaves the flight map, so
        // a lookup under the flight lock sees one or the other.
        if let Lookup::Fresh(verified) | Lookup::Stale(verified) = self.lookup(name) {
            return Some(Role::Admitted(verified));
        }
        let flight = Arc::new(Flight::new());
        flights.insert(name.to_vec(), Arc::clone(&flight));
        Some(Role::Lead(Lead::new(self, name.to_vec(), flight)))
    }

    /// Returns the leader of the refresh of `name`, `None` when another
    /// request already refreshes it.
    fn refresh_lead(&self, name: &[u8]) -> Option<Lead<'_>> {
        let mut flights = self.flights.lock().ok()?;
        if flights.contains_key(name) {
            return None;
        }
        let flight = Arc::new(Flight::new());
        flights.insert(name.to_vec(), Arc::clone(&flight));
        Some(Lead::new(self, name.to_vec(), flight))
    }

    /// Returns the outcome of `derive` run for this request alone, kept when
    /// it verified.
    fn uncoalesced<F>(&self, name: &[u8], derive: F) -> Result<Verified, InvalidCredential>
    where
        F: FnOnce() -> Result<Verified, InvalidCredential>,
    {
        let verified = derive()?;
        self.put(name, &verified);
        Ok(verified)
    }

    /// Keeps `verified` under `name` from now, dropping the expired entries
    /// first.
    fn put(&self, name: &[u8], verified: &Verified) {
        let now = Instant::now();
        let span = self.ttl / SPAN_DIVISOR;
        let life = self.ttl.saturating_sub(jitter(name, span));
        let (Some(expires), Some(refresh_at)) = (
            now.checked_add(life),
            now.checked_add(life.saturating_sub(span)),
        ) else {
            return;
        };
        if let Ok(mut entries) = self.entries.lock() {
            entries.retain(|_name, entry| entry.expires > now);
            if entries.len() < MAX_CACHED || entries.contains_key(name) {
                entries.insert(
                    name.to_vec(),
                    Cached {
                        refresh_at,
                        expires,
                        verified: verified.clone(),
                    },
                );
            }
        }
    }

    /// Drops the entry of `name`.
    fn drop_entry(&self, name: &[u8]) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(name);
        }
    }
}

/// Returns what `entries` holds for `name` at `now`.
fn lookup_in(entries: &BTreeMap<Vec<u8>, Cached>, name: &[u8], now: Instant) -> Lookup {
    match entries.get(name) {
        Some(entry) if now < entry.refresh_at => Lookup::Fresh(entry.verified.clone()),
        Some(entry) if now < entry.expires => Lookup::Stale(entry.verified.clone()),
        _ => Lookup::Missing,
    }
}

/// Returns how much of `span` the lifetime of the entry `name` gives up: a
/// fraction read from the keyed hash, so it differs per credential and cannot
/// be predicted without the key.
fn jitter(name: &[u8], span: Duration) -> Duration {
    let fraction = match name {
        [high, low, ..] => u32::from(u16::from_be_bytes([*high, *low])),
        _ => 0,
    };
    (span / 65_536).saturating_mul(fraction)
}

/// Returns `verified` as admitted without this request's own derivation.
fn cached(verified: Verified) -> Verified {
    Verified {
        cached: true,
        ..verified
    }
}

impl Flight {
    /// Returns a flight with no outcome yet.
    const fn new() -> Self {
        Self {
            outcome: Mutex::new(None),
            landed: Condvar::new(),
        }
    }

    /// Returns the outcome once the leader publishes it, `None` when the lock
    /// is poisoned.
    fn wait(&self) -> Option<Landed> {
        let guard = self.outcome.lock().ok()?;
        let guard = self
            .landed
            .wait_while(guard, |outcome| outcome.is_none())
            .ok()?;
        guard.clone()
    }

    /// Sets the outcome and wakes every waiter.
    fn publish(&self, landed: Landed) {
        if let Ok(mut outcome) = self.outcome.lock() {
            *outcome = Some(landed);
        }
        self.landed.notify_all();
    }
}

impl<'cache> Lead<'cache> {
    /// Returns the leader of `flight` for `name`.
    const fn new(cache: &'cache VerifiedCache, name: Vec<u8>, flight: Arc<Flight>) -> Self {
        Self {
            cache,
            name,
            flight,
            published: false,
        }
    }

    /// Returns the outcome of `derive`, kept when it verified and dropping
    /// the entry when it did not, published to every waiter.
    fn run<F>(mut self, derive: F) -> Result<Verified, InvalidCredential>
    where
        F: FnOnce() -> Result<Verified, InvalidCredential>,
    {
        let outcome = derive();
        let landed = if let Ok(verified) = &outcome {
            self.cache.put(&self.name, verified);
            Landed::Verified(verified.clone())
        } else {
            self.cache.drop_entry(&self.name);
            Landed::Rejected
        };
        self.land(landed);
        outcome
    }

    /// Leaves the flight map and publishes `landed`, in that order, so a
    /// request arriving after it finds the entry.
    fn land(&mut self, landed: Landed) {
        if let Ok(mut flights) = self.cache.flights.lock() {
            flights.remove(&self.name);
        }
        self.flight.publish(landed);
        self.published = true;
    }
}

impl Drop for Lead<'_> {
    fn drop(&mut self) {
        if !self.published {
            self.land(Landed::Abandoned);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CacheUsage, InvalidCredential, MAX_CACHED, Verified, VerifiedCache};
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    fn alice() -> Verified {
        Verified {
            username: String::from("alice"),
            scope: String::from("user/*.rs"),
            roles: Vec::new(),
            cached: false,
        }
    }

    fn sleep_until(deadline: Instant) {
        std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
    }

    #[test]
    fn a_full_cache_keeps_what_it_holds_and_sends_a_new_credential_to_the_store() {
        let cache = VerifiedCache::new(Duration::from_secs(60)).expect("the cache key is drawn");
        assert_eq!(
            CacheUsage::new(MAX_CACHED, 0, 0),
            cache.usage(),
            "an empty cache"
        );
        let derivations = AtomicUsize::new(0);
        let admit = |user_pass: &str| {
            cache
                .admit(user_pass, || {
                    derivations.fetch_add(1, Ordering::SeqCst);
                    Ok(alice())
                })
                .expect("the credential verifies")
        };
        admit("user-0:s3cret");
        let one = cache.usage();
        assert_eq!(1, one.entries);
        assert!(
            one.bytes >= 32 + "alice".len() + "user/*.rs".len(),
            "an entry weighs its name and the text of its record: {}",
            one.bytes
        );
        for user in 1..MAX_CACHED {
            admit(&format!("user-{user}:s3cret"));
        }
        assert_eq!(MAX_CACHED, derivations.load(Ordering::SeqCst));
        let full = cache.usage();
        assert_eq!(
            (MAX_CACHED, MAX_CACHED * one.bytes),
            (full.entries, full.bytes)
        );
        // Past the cap the credential store answers, on every request.
        for _ in 0..2 {
            let beyond = admit("user-beyond:s3cret");
            assert!(!beyond.cached, "the store derived it");
        }
        assert_eq!(MAX_CACHED + 2, derivations.load(Ordering::SeqCst));
        assert_eq!(MAX_CACHED, cache.usage().entries, "never past the cap");
        assert!(admit("user-0:s3cret").cached, "a held credential still is");
        assert_eq!(MAX_CACHED + 2, derivations.load(Ordering::SeqCst));
    }

    #[test]
    fn parallel_misses_for_one_credential_share_one_derivation() {
        const REQUESTS: usize = 32;
        let cache = VerifiedCache::new(Duration::from_secs(60)).expect("the cache key is drawn");
        let derivations = AtomicUsize::new(0);
        let start = Barrier::new(REQUESTS);
        let outcomes: Vec<Result<Verified, InvalidCredential>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..REQUESTS)
                .map(|_| {
                    scope.spawn(|| {
                        start.wait();
                        cache.admit("alice:s3cret", || {
                            derivations.fetch_add(1, Ordering::SeqCst);
                            std::thread::sleep(Duration::from_millis(200));
                            Ok(alice())
                        })
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("the request thread ends"))
                .collect()
        });
        assert_eq!(1, derivations.load(Ordering::SeqCst), "one derivation");
        assert!(outcomes.iter().all(Result::is_ok), "every request admitted");
        let derived = outcomes
            .iter()
            .filter(|outcome| outcome.as_ref().is_ok_and(|verified| !verified.cached))
            .count();
        assert_eq!(1, derived, "only the leader reports its own derivation");
    }

    #[test]
    fn parallel_misses_for_two_credentials_take_one_derivation_each() {
        const REQUESTS: usize = 16;
        let cache = VerifiedCache::new(Duration::from_secs(60)).expect("the cache key is drawn");
        let derivations = AtomicUsize::new(0);
        let start = Barrier::new(REQUESTS * 2);
        std::thread::scope(|scope| {
            for credential in ["alice:s3cret", "bob:hunter2"] {
                for _ in 0..REQUESTS {
                    let (cache, derivations, start) = (&cache, &derivations, &start);
                    scope.spawn(move || {
                        start.wait();
                        cache
                            .admit(credential, || {
                                derivations.fetch_add(1, Ordering::SeqCst);
                                std::thread::sleep(Duration::from_millis(200));
                                Ok(alice())
                            })
                            .expect("admitted")
                    });
                }
            }
        });
        assert_eq!(2, derivations.load(Ordering::SeqCst));
    }

    #[test]
    fn waiters_on_a_rejected_derivation_are_refused_and_nothing_is_kept() {
        const REQUESTS: usize = 16;
        let cache = VerifiedCache::new(Duration::from_secs(60)).expect("the cache key is drawn");
        let derivations = AtomicUsize::new(0);
        let start = Barrier::new(REQUESTS);
        std::thread::scope(|scope| {
            for _ in 0..REQUESTS {
                scope.spawn(|| {
                    start.wait();
                    let outcome = cache.admit("alice:nope", || {
                        derivations.fetch_add(1, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(200));
                        Err(InvalidCredential)
                    });
                    assert_eq!(Err(InvalidCredential), outcome);
                });
            }
        });
        assert_eq!(1, derivations.load(Ordering::SeqCst));
        assert_eq!(None, cache.get("alice:nope"), "a rejection is never kept");
    }

    #[test]
    fn a_waiter_on_an_abandoned_derivation_runs_its_own() {
        let cache = VerifiedCache::new(Duration::from_secs(60)).expect("the cache key is drawn");
        let derivations = AtomicUsize::new(0);
        let leading = Barrier::new(2);
        std::thread::scope(|scope| {
            let leader = scope.spawn(|| {
                cache.admit("alice:s3cret", || {
                    leading.wait();
                    std::thread::sleep(Duration::from_millis(200));
                    panic!("the derivation unwinds");
                })
            });
            leading.wait();
            let follower = cache.admit("alice:s3cret", || {
                derivations.fetch_add(1, Ordering::SeqCst);
                Ok(alice())
            });
            assert!(leader.join().is_err(), "the leader unwound");
            assert_eq!(Ok(alice()), follower, "the follower derived itself");
        });
        assert_eq!(1, derivations.load(Ordering::SeqCst));
    }

    #[test]
    fn an_entry_never_outlives_its_lifetime_and_the_jitter_shortens_it() {
        let ttl = Duration::from_secs(600);
        let cache = VerifiedCache::new(ttl).expect("the cache key is drawn");
        let before = Instant::now();
        let mut expiries = Vec::new();
        for user in 0..32 {
            let credential = format!("user{user}:s3cret");
            cache.admit(&credential, || Ok(alice())).expect("admitted");
            let (window, expiry) = cache.deadlines(&credential).expect("kept");
            let after = Instant::now();
            assert!(expiry <= after + ttl, "never past the lifetime");
            assert!(expiry + ttl / 10 >= before + ttl, "at most a tenth shorter");
            assert_eq!(
                expiry.duration_since(window),
                ttl / 10,
                "the refresh window is a tenth"
            );
            expiries.push(expiry.duration_since(before));
        }
        expiries.sort();
        expiries.dedup_by(|a, b| a.abs_diff(*b) < Duration::from_millis(100));
        assert!(
            expiries.len() > 16,
            "the credentials expire apart: {expiries:?}"
        );
    }

    #[test]
    fn a_revoked_credential_is_refused_once_its_entry_expires() {
        let cache = VerifiedCache::new(Duration::from_millis(400)).expect("the cache key is drawn");
        cache
            .admit("alice:s3cret", || Ok(alice()))
            .expect("admitted");
        let (refresh_at, expires) = cache.deadlines("alice:s3cret").expect("kept");
        let revoked = AtomicUsize::new(0);
        let refuse = || {
            revoked.fetch_add(1, Ordering::SeqCst);
            Err(InvalidCredential)
        };
        assert!(Instant::now() < refresh_at);
        let within = cache
            .admit("alice:s3cret", refuse)
            .expect("admitted within the lifetime");
        assert!(within.cached);
        assert_eq!(
            0,
            revoked.load(Ordering::SeqCst),
            "no derivation before the window"
        );
        sleep_until(expires);
        assert_eq!(Err(InvalidCredential), cache.admit("alice:s3cret", refuse));
        assert_eq!(
            1,
            revoked.load(Ordering::SeqCst),
            "the expired entry re-derives"
        );
        assert_eq!(None, cache.get("alice:s3cret"));
    }

    #[test]
    fn a_refresh_that_fails_drops_the_entry_before_its_expiry() {
        let cache = VerifiedCache::new(Duration::from_secs(2)).expect("the cache key is drawn");
        cache
            .admit("alice:s3cret", || Ok(alice()))
            .expect("admitted");
        let (refresh_at, expires) = cache.deadlines("alice:s3cret").expect("kept");
        sleep_until(refresh_at);
        let refused = cache.admit("alice:s3cret", || Err(InvalidCredential));
        assert!(Instant::now() < expires, "still inside the lifetime");
        assert_eq!(
            Err(InvalidCredential),
            refused,
            "the refresh found it revoked"
        );
        assert_eq!(None, cache.get("alice:s3cret"), "the entry is dropped");
    }

    #[test]
    fn a_refresh_renews_the_entry_while_the_others_are_admitted_from_it() {
        let cache = VerifiedCache::new(Duration::from_secs(2)).expect("the cache key is drawn");
        cache
            .admit("alice:s3cret", || Ok(alice()))
            .expect("admitted");
        let (refresh_at, expires) = cache.deadlines("alice:s3cret").expect("kept");
        sleep_until(refresh_at);
        let derivations = AtomicUsize::new(0);
        let refreshing = Barrier::new(2);
        std::thread::scope(|scope| {
            let refresher = scope.spawn(|| {
                cache.admit("alice:s3cret", || {
                    derivations.fetch_add(1, Ordering::SeqCst);
                    refreshing.wait();
                    std::thread::sleep(Duration::from_millis(100));
                    Ok(alice())
                })
            });
            refreshing.wait();
            let other = cache
                .admit("alice:s3cret", || {
                    derivations.fetch_add(1, Ordering::SeqCst);
                    Ok(alice())
                })
                .expect("admitted from the entry");
            assert!(other.cached, "admitted without waiting on the refresh");
            let renewal = refresher
                .join()
                .expect("the refresher ends")
                .expect("admitted");
            assert!(!renewal.cached, "the refresher derived");
        });
        assert_eq!(1, derivations.load(Ordering::SeqCst));
        let (_, renewed) = cache.deadlines("alice:s3cret").expect("kept");
        assert!(renewed > expires, "the refresh renews the lifetime");
    }
}
