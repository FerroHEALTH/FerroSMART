// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The two stores behind [`crate::sessions::Sessions`].
//!
//! - **memory** keeps two bounded pools in the process. A pending sign-in
//!   pool drops its oldest entry to admit a new one, so a flood of sign-in
//!   starts costs at most its bound; the session pool refuses a new session
//!   at its bound and never evicts a live one, so no sign-in traffic signs
//!   anyone out.
//! - **sealed** keeps each record whole in one cookie, encrypted and
//!   authenticated with AES-256-GCM by the `cookie` crate's private jar, so
//!   every instance holding the key opens it. A cookie that does not open,
//!   or does not read as a record, is no session.
//!
//! No specification governs either store: our own design.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::record::Record;
use crate::sessions::{Occupancy, Pending, SessionError};

/// How many random bytes an id carries: 256 bits.
const ID_BYTES: usize = 32;

/// The most bytes one `Set-Cookie` value may take: the 4096 bytes a browser
/// keeps at the least (RFC 6265 §6.1).
pub(crate) const COOKIE_LIMIT: usize = 4096;

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

/// `value` sealed under `key` as the cookie `name`'s value.
pub(crate) fn seal(
    key: &cookie::Key,
    name: &str,
    value: &impl Serialize,
) -> Result<String, SessionError> {
    let payload = serde_json::to_string(value).map_err(SessionError::Seal)?;
    let mut jar = cookie::CookieJar::new();
    jar.private_mut(key)
        .add(cookie::Cookie::new(name.to_owned(), payload));
    jar.get(name)
        .map(|sealed| sealed.value().to_owned())
        .ok_or(SessionError::Unsealed)
}

/// The value sealed in `sealed` under `key` as the cookie `name`'s.
///
/// A value that does not open, or does not read as a `T`, is `None`: on
/// this seam every defect means the same thing, no session.
pub(crate) fn open<T: DeserializeOwned>(
    key: &cookie::Key,
    name: &str,
    sealed: String,
) -> Option<T> {
    let mut jar = cookie::CookieJar::new();
    jar.add_original(cookie::Cookie::new(name.to_owned(), sealed));
    let opened = jar.private(key).get(name)?;
    // NOTE: no specification governs this: our own design; a payload that opens but does not
    // read is a cookie from another version of the store, which is no session.
    serde_json::from_str(opened.value()).ok()
}
