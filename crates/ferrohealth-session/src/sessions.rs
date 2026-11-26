// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The session store every request of a console shares.
//!
//! [`Sessions`] keeps the pending sign-ins between `GET /login` and the
//! provider's redirect back, and the sessions once a sign-in completes, in
//! the console's process. The cookie carries an opaque id, so a restart
//! signs every operator out, and a console that runs as several instances
//! routes each session to one of them. Every method reads the request's
//! cookies and answers the `Set-Cookie` values its response must carry.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use ferrohealth_smart::oidc::PendingSignIn;
use ferrohealth_ui::view::session::Left;
use http::{HeaderMap, HeaderValue};

use crate::clock::Clock;
use crate::config::SessionSettings;
use crate::cookies::{CookieNames, Jar, header};
use crate::lifetime::{millis, seconds};
use crate::record::{Ended, Held, Record, SignedIn};
use crate::return_path::ReturnPath;
use crate::store::{Id, Memory};

/// Why a sign-in or a session could not be begun, read or ended.
///
/// No variant carries a token, a key or an id.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SessionError {
    /// The system random source failed.
    #[error("the system random source failed")]
    Random,
    /// The memory store holds as many sessions as it may.
    #[error("the session pool is full")]
    Full,
    /// A thread panicked while it held the memory store.
    #[error("the session store is unusable after a panic")]
    Poisoned,
    /// A cookie could not be written as a header value.
    #[error("a cookie could not be written as a header")]
    Header,
}

/// A pending sign-in: what the callback checks the provider's redirect
/// against, and the page to come back to.
pub struct Pending {
    /// The `state`, the `nonce` and the PKCE verifier.
    pub sign_in: PendingSignIn,
    /// The page the operator comes back to; `None` leads to the console's
    /// home.
    pub back: Option<ReturnPath>,
}

impl fmt::Debug for Pending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pending")
            .field("back", &self.back)
            .finish_non_exhaustive()
    }
}

/// How many entries each pool of the store holds, expired ones not yet
/// dropped included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Occupancy {
    /// Pending sign-ins.
    pub sign_ins: usize,
    /// Sessions.
    pub sessions: usize,
}

/// An answer with the `Set-Cookie` values its response must carry.
#[derive(Debug)]
pub struct WithCookies<T> {
    /// The answer.
    pub value: T,
    /// The `Set-Cookie` values, in order.
    pub cookies: Vec<HeaderValue>,
}

impl<T> WithCookies<T> {
    fn new(value: T, cookies: Vec<HeaderValue>) -> Self {
        Self { value, cookies }
    }
}

/// The store and what it is configured with.
struct Inner {
    settings: SessionSettings,
    jar: Jar,
    clock: Clock,
    memory: Memory,
}

/// The session store, shared by every request; cloning it shares it.
#[derive(Clone)]
pub struct Sessions {
    inner: Arc<Inner>,
}

impl fmt::Debug for Sessions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sessions")
            .field("settings", &self.inner.settings)
            .field("names", &self.inner.jar.names)
            .finish_non_exhaustive()
    }
}

impl Sessions {
    /// An empty store under `settings`, with the cookie names `names`.
    #[must_use]
    pub fn new(settings: SessionSettings, names: CookieNames) -> Self {
        Self::with_clock(settings, names, Clock::system())
    }

    /// An empty store under `settings`, with the cookie names `names`, that
    /// counts every lifetime on `clock`.
    #[must_use]
    pub fn with_clock(settings: SessionSettings, names: CookieNames, clock: Clock) -> Self {
        let memory = Memory::new(settings.max_sign_ins, settings.max_sessions);
        let jar = Jar {
            names,
            secure: settings.secure_cookie,
        };
        Self {
            inner: Arc::new(Inner {
                settings,
                jar,
                clock,
                memory,
            }),
        }
    }

    /// The checked `[session]` the store runs under.
    #[must_use]
    pub fn settings(&self) -> &SessionSettings {
        &self.inner.settings
    }

    pub(crate) fn now(&self) -> i64 {
        self.inner.clock.millis()
    }

    fn timeout(&self) -> i64 {
        millis(self.inner.settings.sign_in_timeout)
    }

    fn jar(&self) -> &Jar {
        &self.inner.jar
    }

    fn live(&self, record: &Record, now: i64) -> bool {
        self.inner
            .settings
            .lifetimes
            .left(record.times(), now)
            .is_some()
    }

    /// Keeps `sign_in`, begun now, and answers the cookie that names it,
    /// which expires with the sign-in.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Random`] when no id could be minted,
    /// [`SessionError::Poisoned`] for an unusable store, and
    /// [`SessionError::Header`] when the cookie cannot be written.
    pub fn begin(
        &self,
        sign_in: PendingSignIn,
        back: Option<ReturnPath>,
    ) -> Result<HeaderValue, SessionError> {
        let now = self.now();
        let name = self.jar().names.sign_in();
        let id = self
            .memory()
            .begin(Pending { sign_in, back }, now, self.timeout())?;
        self.set(
            &name,
            id.as_str().to_owned(),
            Some(seconds(self.inner.settings.sign_in_timeout)),
        )
    }

    /// Takes the pending sign-in the request's cookie names, once, and
    /// answers the removal of that cookie beside it; `None` for no cookie,
    /// or a sign-in unknown, dropped or expired.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Poisoned`] for an unusable store and
    /// [`SessionError::Header`] when the removal cannot be written.
    pub fn take_pending(
        &self,
        headers: &HeaderMap,
    ) -> Result<WithCookies<Option<Pending>>, SessionError> {
        let now = self.now();
        let name = self.jar().names.sign_in();
        let removal = header(&self.jar().removal(&name))?;
        let Some(value) = self.jar().read(headers, &name) else {
            return Ok(WithCookies::new(None, Vec::new()));
        };
        let pending = self
            .memory()
            .take(&Id::from_cookie(value), now, self.timeout())?;
        Ok(WithCookies::new(pending, vec![removal]))
    }

    /// Begins the session of a completed sign-in and answers its cookie; the
    /// session the request held before is ended first, so signing in again
    /// never fills the store.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Full`] when the store is at its bound, and
    /// the errors of [`Self::begin`].
    pub fn establish(
        &self,
        headers: &HeaderMap,
        signed_in: SignedIn,
    ) -> Result<HeaderValue, SessionError> {
        let now = self.now();
        let record = Record::begin(signed_in, now);
        let name = self.jar().names.session();
        let memory = self.memory();
        if let Some(held) = self.jar().read(headers, &name) {
            memory.end(&Id::from_cookie(held))?;
        }
        let id = memory.establish(record, |record| self.live(record, now))?;
        self.set(&name, id.as_str().to_owned(), None)
    }

    /// What the request carries, its activity counted: a live session's idle
    /// lifetime starts again; a cookie that names no live session is
    /// answered with its removal.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Poisoned`] for an unusable store and
    /// [`SessionError::Header`] when the removal cannot be written.
    pub fn held(&self, headers: &HeaderMap) -> Result<WithCookies<Held>, SessionError> {
        let now = self.now();
        let name = self.jar().names.session();
        let Some(value) = self.jar().read(headers, &name) else {
            return Ok(WithCookies::new(Held::Absent, Vec::new()));
        };
        let lifetimes = self.inner.settings.lifetimes;
        let held = self.memory().with(
            &Id::from_cookie(value),
            |record| self.live(record, now),
            |entry| {
                entry.record.touched = now;
                match lifetimes.left(entry.record.times(), now) {
                    Some(left) if entry.record.token_valid(now) => {
                        Held::SignedIn(entry.record.session(left))
                    }
                    _ => Held::TokenExpired,
                }
            },
        )?;
        match held {
            Some(held) => Ok(WithCookies::new(held, Vec::new())),
            None => self.ended(&name),
        }
    }

    /// What the request's session has left, for the session watch: with
    /// `extend` the request counts as activity and starts the idle lifetime
    /// again, which never reaches past the absolute one; without it nothing
    /// moves. `None` for no live session, with the cookie's removal.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::held`].
    pub fn left(
        &self,
        headers: &HeaderMap,
        extend: bool,
    ) -> Result<WithCookies<Option<Left>>, SessionError> {
        let now = self.now();
        let name = self.jar().names.session();
        let Some(value) = self.jar().read(headers, &name) else {
            return Ok(WithCookies::new(None, Vec::new()));
        };
        let lifetimes = self.inner.settings.lifetimes;
        let gone = |this: &Self| -> Result<WithCookies<Option<Left>>, SessionError> {
            let removal = header(&this.jar().removal(&name))?;
            Ok(WithCookies::new(None, vec![removal]))
        };
        let left = self.memory().with(
            &Id::from_cookie(value),
            |record| self.live(record, now),
            |entry| {
                if extend {
                    entry.record.touched = now;
                }
                lifetimes.left(entry.record.times(), now)
            },
        )?;
        match left.flatten() {
            Some(left) => Ok(WithCookies::new(Some(left), Vec::new())),
            None => gone(self),
        }
    }

    /// Ends the request's session and answers what the provider is told,
    /// beside the removal of its cookie; `None` when the request held none.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Poisoned`] for an unusable store and
    /// [`SessionError::Header`] when the removal cannot be written.
    pub fn end(&self, headers: &HeaderMap) -> Result<WithCookies<Option<Ended>>, SessionError> {
        let name = self.jar().names.session();
        let removal = header(&self.jar().removal(&name))?;
        let Some(value) = self.jar().read(headers, &name) else {
            return Ok(WithCookies::new(None, vec![removal]));
        };
        let record = self.memory().end(&Id::from_cookie(value))?;
        Ok(WithCookies::new(record.map(Record::ended), vec![removal]))
    }

    /// How many entries each pool of the store holds.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Poisoned`] for an unusable store.
    pub fn occupancy(&self) -> Result<Occupancy, SessionError> {
        self.memory().occupancy()
    }

    /// The `Set-Cookie` value that keeps the operator's preference `name` at
    /// `value` for `max_age`, with the attributes of every other cookie.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Header`] when the cookie cannot be written.
    pub fn preference(
        &self,
        name: &str,
        value: &str,
        max_age: Duration,
    ) -> Result<HeaderValue, SessionError> {
        self.set(
            &self.jar().names.preference(name),
            value.to_owned(),
            Some(seconds(max_age)),
        )
    }

    /// The `Set-Cookie` value that keeps the operator's preference `name` at
    /// `value` until the browser session ends: the attributes of every other
    /// cookie and no `Max-Age`, which makes it a session cookie
    /// (RFC 6265 §4.1.2.2, §5.3).
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Header`] when the cookie cannot be written.
    pub fn session_preference(&self, name: &str, value: &str) -> Result<HeaderValue, SessionError> {
        self.set(&self.jar().names.preference(name), value.to_owned(), None)
    }

    /// The `Set-Cookie` value that clears the operator's preference `name`.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Header`] when the cookie cannot be written.
    pub fn preference_removal(&self, name: &str) -> Result<HeaderValue, SessionError> {
        header(&self.jar().removal(&self.jar().names.preference(name)))
    }

    /// The operator's preference `name` the request carries.
    #[must_use]
    pub fn preference_in(&self, headers: &HeaderMap, name: &str) -> Option<String> {
        self.jar().read(headers, &self.jar().names.preference(name))
    }

    pub(crate) fn memory(&self) -> &Memory {
        &self.inner.memory
    }

    pub(crate) fn session_id(&self, headers: &HeaderMap) -> Option<Id> {
        self.jar()
            .read(headers, &self.jar().names.session())
            .map(Id::from_cookie)
    }

    pub(crate) fn live_at(&self, record: &Record) -> bool {
        self.live(record, self.now())
    }

    fn ended(&self, name: &str) -> Result<WithCookies<Held>, SessionError> {
        Ok(WithCookies::new(
            Held::Ended,
            vec![header(&self.jar().removal(name))?],
        ))
    }

    fn set(
        &self,
        base: &str,
        value: String,
        max_age: Option<i64>,
    ) -> Result<HeaderValue, SessionError> {
        header(&self.jar().cookie(base, value, max_age))
    }
}

#[cfg(test)]
mod tests;
