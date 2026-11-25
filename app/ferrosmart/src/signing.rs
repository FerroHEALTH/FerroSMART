// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The keys that sign every token, rotated on a schedule the replicas share
//! through the store (`docs/architecture.md` §13.11).
//!
//! The configuration names a pool of key files, RS256 and ML-DSA-65 keys
//! side by side. For each algorithm the store decides which key signs,
//! which is published ahead of signing and which stays published after it
//! ([`crate::store::signing`]); each replica reads that decision every
//! [`REFRESH_INTERVAL`] and swaps the rings it signs with.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use ferrohealth_smart::client::assertion::AssertionKey;
use ferrohealth_smart::client::keys::{KeyRing, KeyRingError};
use ferrohealth_smart::jws::algorithm::Algorithm;
use serde_json::Value;

use crate::store::signing::{KeyRow, KeyState, Schedule};
use crate::store::{Store, StoreError};

/// How often a replica moves the keys on and reads which one signs. No
/// specification governs the value: our own design.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// A ring the store's decision cannot be built into on this replica.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SigningError {
    /// The store could not be read or written.
    #[error("the signing keys' state could not be read")]
    Store(#[from] StoreError),
    /// The store names an active key none of this replica's files hold.
    #[error("the active signing key {kid} is in none of `ferrosmart.keys.private_key_files`")]
    Unknown {
        /// The active key's `kid`.
        kid: String,
    },
    /// The store names no active key of an algorithm, or the pool holds no
    /// RS256 key.
    #[error("no signing key is active")]
    NoActive,
    /// The store's keys repeat one another.
    #[error("the signing keys repeat one another")]
    Ring(#[from] KeyRingError),
}

/// The keys of one signing algorithm, rotating on their own.
#[derive(Debug)]
struct Rotation {
    /// The algorithm every key of the rotation signs with.
    algorithm: Algorithm,
    /// The keys the configuration names, in the order they take over.
    pool: Vec<AssertionKey>,
    /// The ring the store last decided on.
    ring: ArcSwap<KeyRing>,
}

/// The pool of signing keys, the schedule they rotate on, and the ring
/// of each algorithm that signs the tokens now.
///
/// The keys of each algorithm rotate on their own under one schedule, so
/// an RS256 key and an ML-DSA-65 key (RFC 9964 §5) are published and sign
/// side by side. `Debug` shows each key's algorithm and `kid`, never a key.
#[derive(Debug)]
pub struct SigningKeys {
    /// The rotations, RS256 first.
    rotations: Vec<Rotation>,
    /// When the keys move on.
    schedule: Schedule,
}

impl SigningKeys {
    /// Returns the keys of `pool` rotating on `schedule` by algorithm, each
    /// algorithm signing with its first key until the store is read.
    ///
    /// # Errors
    /// Returns [`SigningError::NoActive`] when `pool` holds no RS256 key.
    pub fn new(pool: Vec<AssertionKey>, schedule: Schedule) -> Result<Self, SigningError> {
        let mut rotations: Vec<Rotation> = Vec::new();
        for key in pool {
            match rotations
                .iter_mut()
                .find(|rotation| rotation.algorithm == key.algorithm())
            {
                Some(rotation) => rotation.pool.push(key),
                None => rotations.push(Rotation {
                    algorithm: key.algorithm(),
                    ring: ArcSwap::from_pointee(KeyRing::new(key.clone())),
                    pool: vec![key],
                }),
            }
        }
        // NOTE: RFC 9068 §2.1, an authorization server MUST support RS256.
        if !rotations
            .iter()
            .any(|rotation| rotation.algorithm == Algorithm::Rs256)
        {
            return Err(SigningError::NoActive);
        }
        rotations.sort_by_key(|rotation| rotation.algorithm != Algorithm::Rs256);
        Ok(Self {
            rotations,
            schedule,
        })
    }

    /// Returns the ring that signs every token under `algorithm` now, when
    /// the pool holds a key of it.
    #[must_use]
    pub fn ring(&self, algorithm: Algorithm) -> Option<Arc<KeyRing>> {
        self.rotations
            .iter()
            .find(|rotation| rotation.algorithm == algorithm)
            .map(|rotation| rotation.ring.load_full())
    }

    /// Returns the algorithms the pool signs with, RS256 first.
    #[must_use]
    pub fn algorithms(&self) -> Vec<Algorithm> {
        self.rotations
            .iter()
            .map(|rotation| rotation.algorithm)
            .collect()
    }

    /// Returns the JWK Set of every ring (RFC 7517 §5): each algorithm's
    /// signing, next and retiring keys.
    #[must_use]
    pub fn published(&self) -> Value {
        let keys: Vec<Value> = self
            .rotations
            .iter()
            .flat_map(|rotation| {
                rotation
                    .ring
                    .load_full()
                    .published()
                    .get("keys")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
            })
            .collect();
        serde_json::json!({ "keys": keys })
    }

    /// Returns the schedule the keys rotate on.
    #[must_use]
    pub const fn schedule(&self) -> &Schedule {
        &self.schedule
    }

    /// Returns every key of the pool, published or not, by algorithm.
    pub fn pool(&self) -> impl Iterator<Item = &AssertionKey> {
        self.rotations.iter().flat_map(|rotation| &rotation.pool)
    }

    /// Moves the keys of each algorithm on in `store` at `now`, in seconds
    /// since the Unix epoch, and signs with the rings it decides on;
    /// returns the keys that are not retired.
    ///
    /// # Errors
    /// Returns [`SigningError`] when the store fails or names a ring this
    /// replica cannot build; the rings it signed with stay.
    pub async fn refresh(&self, store: &Store, now: i64) -> Result<Vec<KeyRow>, SigningError> {
        let mut every = Vec::new();
        for rotation in &self.rotations {
            let kids: Vec<&str> = rotation.pool.iter().map(AssertionKey::kid).collect();
            let rows = store
                .rotate_keys(rotation.algorithm.name(), &kids, &self.schedule, now)
                .await?;
            rotation.adopt(&rows)?;
            every.extend(rows);
        }
        Ok(every)
    }

    /// Moves the keys on every [`REFRESH_INTERVAL`]; a failed refresh is
    /// logged and the rings stay until the next one succeeds.
    pub async fn run(self: Arc<Self>, store: Store) {
        let mut interval = tokio::time::interval(REFRESH_INTERVAL);
        loop {
            interval.tick().await;
            if let Err(error) = self
                .refresh(&store, jiff::Timestamp::now().as_second())
                .await
            {
                tracing::error!(
                    error = %ferrohealth_server::run::chain(&error),
                    "the signing keys were not refreshed"
                );
            }
        }
    }
}

impl Rotation {
    /// Signs with the ring `rows` describe. A next or retiring key none of
    /// this replica's files hold is left unpublished here.
    fn adopt(&self, rows: &[KeyRow]) -> Result<(), SigningError> {
        let key = |state: KeyState| {
            rows.iter()
                .find(|row| row.state == state)
                .map(|row| (row.kid.as_str(), self.held(&row.kid)))
        };
        let (kid, active) = key(KeyState::Active).ok_or(SigningError::NoActive)?;
        let mut ring = KeyRing::new(active.cloned().ok_or_else(|| SigningError::Unknown {
            kid: kid.to_owned(),
        })?);
        if let Some((_, Some(retiring))) = key(KeyState::Retiring) {
            ring = ring.with_previous_until_removed(retiring.clone())?;
        }
        if let Some((_, Some(next))) = key(KeyState::Next) {
            ring = ring.with_next(next.clone())?;
        }
        self.ring.store(Arc::new(ring));
        Ok(())
    }

    /// Returns the key of the pool published as `kid`.
    fn held(&self, kid: &str) -> Option<&AssertionKey> {
        self.pool.iter().find(|key| key.kid() == kid)
    }
}
