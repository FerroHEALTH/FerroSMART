// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The memory store behind [`crate::sessions::Sessions`].
//!
//! It keeps two bounded pools in the process. The pending sign-in pool
//! drops its oldest entry to admit a new one, so a flood of sign-in starts
//! costs at most its bound; the session pool refuses a new session at its
//! bound and never evicts a live one, so no sign-in traffic signs anyone
//! out. No specification governs the store: our own design.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::record::Record;
use crate::sessions::{Occupancy, Pending, SessionError};

/// How many random bytes an id carries: 256 bits.
const ID_BYTES: usize = 32;

/// An opaque id of the memory store, the value of a cookie.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Id(String);

impl Id {
    /// The id a browser sent.
    pub(crate) const fn from_cookie(value: String) -> Self {
        Self(value)
    }

    /// The id as the cookie carries it.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// A fresh random id.
    fn mint() -> Result<Self, SessionError> {
        let mut bytes = [0_u8; ID_BYTES];
        aws_lc_rs::rand::fill(&mut bytes).map_err(|_unspecified| SessionError::Random)?;
        Ok(Self(URL_SAFE_NO_PAD.encode(bytes)))
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Id(..)")
    }
}

/// One pending sign-in of the memory store.
struct Waiting {
    sequence: u64,
    created: i64,
    pending: Pending,
}

/// One session of the memory store, with the gate its one refresh holds.
pub(crate) struct Entry {
    pub(crate) record: Record,
    pub(crate) gate: Arc<tokio::sync::Mutex<()>>,
    /// The access tokens for other resource servers, by resource.
    pub(crate) resources: BTreeMap<String, crate::resource::Held>,
    pub(crate) justifications: BTreeMap<String, crate::justification::Justification>,
}

/// Both pools, under one lock.
#[derive(Default)]
struct Pools {
    pending: BTreeMap<Id, Waiting>,
    order: BTreeMap<u64, Id>,
    next: u64,
    sessions: BTreeMap<Id, Entry>,
}

impl Pools {
    fn remove_pending(&mut self, id: &Id) -> Option<Waiting> {
        let waiting = self.pending.remove(id)?;
        self.order.remove(&waiting.sequence);
        Some(waiting)
    }
}

/// The memory store.
#[derive(Clone)]
pub(crate) struct Memory {
    pools: Arc<Mutex<Pools>>,
    max_sign_ins: usize,
    max_sessions: usize,
}

impl fmt::Debug for Memory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Memory")
            .field("max_sign_ins", &self.max_sign_ins)
            .field("max_sessions", &self.max_sessions)
            .finish_non_exhaustive()
    }
}

impl Memory {
    pub(crate) fn new(max_sign_ins: usize, max_sessions: usize) -> Self {
        Self {
            pools: Arc::default(),
            max_sign_ins,
            max_sessions,
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, Pools>, SessionError> {
        self.pools
            .lock()
            .map_err(|_poisoned| SessionError::Poisoned)
    }

    /// Keeps `pending` begun at `now`, dropping expired sign-ins first and
    /// then the oldest while the pool is full.
    pub(crate) fn begin(
        &self,
        pending: Pending,
        now: i64,
        timeout: i64,
    ) -> Result<Id, SessionError> {
        let id = Id::mint()?;
        let mut pools = self.lock()?;
        while let Some(oldest) = pools.order.first_key_value().map(|(_, id)| id.clone()) {
            let expired = pools
                .pending
                .get(&oldest)
                .is_none_or(|waiting| now.saturating_sub(waiting.created) >= timeout);
            if !expired {
                break;
            }
            pools.remove_pending(&oldest);
        }
        while pools.pending.len() >= self.max_sign_ins {
            let Some((_, oldest)) = pools.order.pop_first() else {
                break;
            };
            pools.pending.remove(&oldest);
        }
        let sequence = pools.next;
        pools.next = sequence.saturating_add(1);
        pools.order.insert(sequence, id.clone());
        pools.pending.insert(
            id.clone(),
            Waiting {
                sequence,
                created: now,
                pending,
            },
        );
        Ok(id)
    }

    /// Takes the pending sign-in `id` once; `None` for an unknown, dropped
    /// or expired one.
    pub(crate) fn take(
        &self,
        id: &Id,
        now: i64,
        timeout: i64,
    ) -> Result<Option<Pending>, SessionError> {
        let mut pools = self.lock()?;
        Ok(pools
            .remove_pending(id)
            .filter(|waiting| now.saturating_sub(waiting.created) < timeout)
            .map(|waiting| waiting.pending))
    }

    /// Keeps `record`, dropping the sessions `live` no longer admits first;
    /// a pool still full refuses it.
    pub(crate) fn establish(
        &self,
        record: Record,
        live: impl Fn(&Record) -> bool,
    ) -> Result<Id, SessionError> {
        let id = Id::mint()?;
        let mut pools = self.lock()?;
        pools.sessions.retain(|_, entry| live(&entry.record));
        if pools.sessions.len() >= self.max_sessions {
            return Err(SessionError::Full);
        }
        pools.sessions.insert(
            id.clone(),
            Entry {
                record,
                gate: Arc::default(),
                resources: BTreeMap::new(),
                justifications: BTreeMap::new(),
            },
        );
        Ok(id)
    }

    /// Runs `read` on the session `id` while `live` admits it; a session it
    /// no longer admits is dropped and answers `Ok(None)`.
    pub(crate) fn with<T>(
        &self,
        id: &Id,
        live: impl Fn(&Record) -> bool,
        read: impl FnOnce(&mut Entry) -> T,
    ) -> Result<Option<T>, SessionError> {
        let mut pools = self.lock()?;
        let Some(entry) = pools.sessions.get_mut(id) else {
            return Ok(None);
        };
        if live(&entry.record) {
            Ok(Some(read(entry)))
        } else {
            pools.sessions.remove(id);
            Ok(None)
        }
    }

    /// Removes the session `id` and returns its record.
    pub(crate) fn end(&self, id: &Id) -> Result<Option<Record>, SessionError> {
        Ok(self.lock()?.sessions.remove(id).map(|entry| entry.record))
    }

    pub(crate) fn occupancy(&self) -> Result<Occupancy, SessionError> {
        let pools = self.lock()?;
        Ok(Occupancy {
            sign_ins: pools.pending.len(),
            sessions: pools.sessions.len(),
        })
    }

    #[cfg(test)]
    pub(crate) fn poison(&self) {
        let pools = Arc::clone(&self.pools);
        let joined = std::thread::spawn(move || {
            let _held = pools.lock();
            panic!("a thread panics holding the store");
        })
        .join();
        assert!(joined.is_err(), "the poisoning thread panics");
    }
}
