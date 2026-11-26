// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The clock every lifetime is counted on: wall-clock milliseconds, so a
//! timeout of T lasts at least T.
//!
//! A store runs on [`Clock::system`] unless it is built with
//! [`Sessions::with_clock`](crate::sessions::Sessions::with_clock). Behind the
//! `test-clock` feature, `ManualClock` is a time a test sets and moves, so a
//! console's session tests reach a timeout without waiting for it.

#[cfg(any(test, feature = "test-clock"))]
use std::sync::Arc;
#[cfg(any(test, feature = "test-clock"))]
use std::sync::atomic::{AtomicI64, Ordering};

/// Milliseconds in a second.
#[cfg(any(test, feature = "test-clock"))]
const MILLIS: i64 = 1000;

/// Where a store reads the current time from; the default is the wall clock.
#[derive(Debug, Clone, Default)]
pub struct Clock(Source);

#[derive(Debug, Clone, Default)]
enum Source {
    #[default]
    System,
    #[cfg(any(test, feature = "test-clock"))]
    Manual(ManualClock),
}

impl Clock {
    /// The system's wall clock.
    #[must_use]
    pub fn system() -> Self {
        Self(Source::System)
    }

    /// The current time in milliseconds since the Unix epoch.
    pub(crate) fn millis(&self) -> i64 {
        match &self.0 {
            Source::System => jiff::Timestamp::now().as_millisecond(),
            #[cfg(any(test, feature = "test-clock"))]
            Source::Manual(manual) => manual.now_millis(),
        }
    }
}

/// A time a test sets and moves, kept in milliseconds since the Unix epoch.
///
/// Every clone, and every [`Clock`] taken from it, reads the same time. The
/// whole-second methods (`new`, `now`, `set`, `advance`) sit beside the
/// millisecond ones, so a test reaches either side of a second boundary.
///
/// ```
/// use ferrohealth_session::clock::ManualClock;
///
/// let time = ManualClock::new(1_800_000_000);
/// let clock = time.clock();
/// time.advance(61);
/// assert_eq!(time.now(), 1_800_000_061);
/// time.advance_millis(999);
/// assert_eq!(time.now(), 1_800_000_061);
/// assert_eq!(time.now_millis(), 1_800_000_061_999);
/// ```
#[cfg(any(test, feature = "test-clock"))]
#[derive(Debug, Clone)]
pub struct ManualClock(Arc<AtomicI64>);

#[cfg(any(test, feature = "test-clock"))]
impl ManualClock {
    /// A manual time at `start` seconds since the Unix epoch.
    #[must_use]
    pub fn new(start: i64) -> Self {
        Self(Arc::new(AtomicI64::new(start.saturating_mul(MILLIS))))
    }

    /// The clock a store reads this time from.
    #[must_use]
    pub fn clock(&self) -> Clock {
        Clock(Source::Manual(self.clone()))
    }

    /// The current manual time in whole seconds, rounded down.
    #[must_use]
    pub fn now(&self) -> i64 {
        self.now_millis().div_euclid(MILLIS)
    }

    /// The current manual time in milliseconds since the Unix epoch.
    #[must_use]
    pub fn now_millis(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }

    /// Sets the time to `seconds` since the Unix epoch.
    pub fn set(&self, seconds: i64) {
        self.set_millis(seconds.saturating_mul(MILLIS));
    }

    /// Sets the time to `millis` milliseconds since the Unix epoch.
    pub fn set_millis(&self, millis: i64) {
        self.0.store(millis, Ordering::SeqCst);
    }

    /// Moves the time by `seconds`, saturating at the ends of `i64`.
    pub fn advance(&self, seconds: i64) {
        self.advance_millis(seconds.saturating_mul(MILLIS));
    }

    /// Moves the time by `millis` milliseconds, saturating at the ends of
    /// `i64`.
    pub fn advance_millis(&self, millis: i64) {
        let mut now = self.now_millis();
        while let Err(seen) = self.0.compare_exchange_weak(
            now,
            now.saturating_add(millis),
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            now = seen;
        }
    }
}
