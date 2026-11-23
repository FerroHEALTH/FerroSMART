// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The keys that sign every token, rotated on a schedule the replicas share
//! through the store (`docs/architecture.md` §13.11).
//!
//! The configuration names a pool of key files. The store decides which of
//! them signs, which is published ahead of signing and which stays
//! published after it ([`crate::store::signing`]); each replica reads that
//! decision every [`REFRESH_INTERVAL`] and swaps the ring it signs with.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use ferrohealth_smart::client::assertion::AssertionKey;
use ferrohealth_smart::client::keys::{KeyRing, KeyRingError};

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
    /// The store names no active key.
    #[error("no signing key is active")]
    NoActive,
    /// The store's keys repeat one another.
    #[error("the signing keys repeat one another")]
    Ring(#[from] KeyRingError),
}

/// The pool of signing keys, the schedule they rotate on, and the ring
/// every token is signed with now.
///
/// `Debug` shows each key's algorithm and `kid`, never a key.
#[derive(Debug)]
pub struct SigningKeys {
    /// The keys the configuration names, in the order they take over.
    pool: Vec<AssertionKey>,
    /// When the keys move on.
    schedule: Schedule,
    /// The ring the store last decided on.
    ring: ArcSwap<KeyRing>,
}

impl SigningKeys {
    /// Returns the keys of `pool` rotating on `schedule`, signing with the
    /// first until the store is read.
    ///
    /// # Errors
    /// Returns [`SigningError::NoActive`] when `pool` is empty.
    pub fn new(pool: Vec<AssertionKey>, schedule: Schedule) -> Result<Self, SigningError> {
        let first = pool.first().cloned().ok_or(SigningError::NoActive)?;
        Ok(Self {
            pool,
            schedule,
            ring: ArcSwap::from_pointee(KeyRing::new(first)),
        })
    }

    /// Returns the ring every token is signed with now.
    #[must_use]
    pub fn ring(&self) -> Arc<KeyRing> {
        self.ring.load_full()
    }

    /// Returns the schedule the keys rotate on.
    #[must_use]
    pub const fn schedule(&self) -> &Schedule {
        &self.schedule
    }

    /// Returns every key of the pool, published or not.
    #[must_use]
    pub fn pool(&self) -> &[AssertionKey] {
        &self.pool
    }

    /// Moves the keys on in `store` at `now`, in seconds since the Unix
    /// epoch, and signs with the ring it decides on; returns the keys that
    /// are not retired.
    ///
    /// # Errors
    /// Returns [`SigningError`] when the store fails or names a ring this
    /// replica cannot build; the ring it signed with stays.
    pub async fn refresh(&self, store: &Store, now: i64) -> Result<Vec<KeyRow>, SigningError> {
        let kids: Vec<&str> = self.pool.iter().map(AssertionKey::kid).collect();
        let rows = store.rotate_keys(&kids, &self.schedule, now).await?;
        self.adopt(&rows)?;
        Ok(rows)
    }

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

    /// Moves the keys on every [`REFRESH_INTERVAL`]; a failed refresh is
    /// logged and the ring stays until the next one succeeds.
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
