// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A justification the operator stated for one object, kept with the
//! memory-store session until it ends.
//!
//! A console whose server asks why an operator opens a record outside their
//! usual access (a purpose of use and a reason in their own words) keeps
//! the answer here, so each later call about that object carries it. The
//! reason may hold health data, so it is kept on the server alone: a sealed
//! store, which keeps the session in the browser, keeps none (GDPR Art.
//! 5(1)(c) and (f)). A justification ends at its end time, when the
//! operator ends it, or with the session. No specification governs this:
//! our own design.

use std::fmt;
use std::time::Duration;

use ferrohealth_secret::secret::Secret;
use http::HeaderMap;

use crate::lifetime::millis;
use crate::sessions::{SessionError, Sessions};

/// The most justifications one session keeps; stating one more drops the
/// one that ends first.
pub const MAX_JUSTIFICATIONS: usize = 16;

/// A justification stated for one object: the purpose of use it declares,
/// the reason in the operator's words, and when it ends.
#[derive(Clone)]
pub struct Justification {
    purpose: String,
    reason: Secret,
    ends: i64,
}

impl fmt::Debug for Justification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Justification")
            .field("purpose", &self.purpose)
            .field("ends", &self.ends)
            .finish_non_exhaustive()
    }
}

impl Justification {
    /// The purpose of use the justification declares.
    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// The reason the operator stated.
    #[must_use]
    pub const fn reason(&self) -> &Secret {
        &self.reason
    }

    /// When it ends, in whole seconds since the Unix epoch, rounded down.
    #[must_use]
    pub const fn ends_at(&self) -> i64 {
        self.ends.div_euclid(1000)
    }
}

/// What [`Sessions::justify`] answered.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Justified {
    /// The justification is kept until the instant it names, in whole
    /// seconds since the Unix epoch.
    Kept(i64),
    /// The request holds no live memory-store session, so nothing is kept:
    /// no session, or a sealed store, which keeps the session in the
    /// browser.
    Unavailable,
}

impl Sessions {
    /// Keeps the justification of `purpose` and `reason` for the object
    /// `object` with the request's session for `lifetime`, in place of any
    /// it held for that object.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Poisoned`] for an unusable memory store.
    pub fn justify(
        &self,
        headers: &HeaderMap,
        object: &str,
        purpose: &str,
        reason: Secret,
        lifetime: Duration,
    ) -> Result<Justified, SessionError> {
        let (Some(memory), Some(id)) = (self.memory(), self.session_id(headers)) else {
            return Ok(Justified::Unavailable);
        };
        let now = self.now();
        let ends = now.saturating_add(millis(lifetime));
        let kept = memory.with(
            &id,
            |record| self.live_at(record),
            |entry| {
                entry.justifications.retain(|_, held| held.ends > now);
                entry.justifications.remove(object);
                while entry.justifications.len() >= MAX_JUSTIFICATIONS {
                    let first = entry
                        .justifications
                        .iter()
                        .min_by_key(|(_, held)| held.ends)
                        .map(|(key, _)| key.clone());
                    let Some(key) = first else { break };
                    entry.justifications.remove(&key);
                }
                entry.justifications.insert(
                    object.to_owned(),
                    Justification {
                        purpose: purpose.to_owned(),
                        reason,
                        ends,
                    },
                );
            },
        )?;
        Ok(match kept {
            Some(()) => Justified::Kept(ends.div_euclid(1000)),
            None => Justified::Unavailable,
        })
    }

    /// The justification the request's session holds for `object` and that
    /// has not ended; `None` without one.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Poisoned`] for an unusable memory store.
    pub fn justification(
        &self,
        headers: &HeaderMap,
        object: &str,
    ) -> Result<Option<Justification>, SessionError> {
        let (Some(memory), Some(id)) = (self.memory(), self.session_id(headers)) else {
            return Ok(None);
        };
        let now = self.now();
        Ok(memory
            .with(
                &id,
                |record| self.live_at(record),
                |entry| {
                    entry.justifications.retain(|_, held| held.ends > now);
                    entry.justifications.get(object).cloned()
                },
            )?
            .flatten())
    }

    /// Ends the justification the request's session holds for `object`, if
    /// it holds one.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Poisoned`] for an unusable memory store.
    pub fn end_justification(&self, headers: &HeaderMap, object: &str) -> Result<(), SessionError> {
        let (Some(memory), Some(id)) = (self.memory(), self.session_id(headers)) else {
            return Ok(());
        };
        memory.with(
            &id,
            |record| self.live_at(record),
            |entry| entry.justifications.remove(object),
        )?;
        Ok(())
    }
}
