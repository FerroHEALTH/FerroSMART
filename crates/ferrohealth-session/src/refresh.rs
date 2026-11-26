// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The refresh of a session's access token before it expires (RFC 6749 §6).
//!
//! A session that holds a refresh token outlives its
//! access token; a request that finds the token within [`MARGIN`] of its
//! expiry renews it first. One refresh per session runs at a time, so a
//! refresh token the provider rotates is never spent twice. No specification
//! governs when to refresh: our own design.

use std::fmt;
use std::time::Duration;

use ferrohealth_smart::oidc::{OidcError, RelyingParty};
use http::HeaderMap;

use crate::lifetime::millis;
use crate::record::Record;
use crate::sessions::{SessionError, Sessions};

/// How long before its expiry an access token is renewed, at most half its
/// lifetime.
pub const MARGIN: Duration = Duration::from_secs(60);

/// What [`Sessions::keep_fresh`] did.
#[non_exhaustive]
pub enum Freshness {
    /// Nothing was due: no session, no refresh token, or a token not near
    /// its expiry.
    Current,
    /// The access token was renewed.
    Refreshed,
    /// The provider refused the refresh, so the session is ended.
    Ended(OidcError),
    /// The provider could not be reached or answered no token; the session
    /// keeps its access token until it expires, and the next request tries
    /// again.
    Unreached(OidcError),
}

impl fmt::Debug for Freshness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Current => f.write_str("Current"),
            Self::Refreshed => f.write_str("Refreshed"),
            Self::Ended(error) => f.debug_tuple("Ended").field(error).finish(),
            Self::Unreached(error) => f.debug_tuple("Unreached").field(error).finish(),
        }
    }
}

/// Whether `record`'s access token is due for renewal at `now`, in
/// milliseconds since the Unix epoch.
fn due(record: &Record, now: i64) -> bool {
    let margin = record.lifetime.map_or(millis(MARGIN), |lifetime| {
        millis(MARGIN).min(millis(lifetime).div_euclid(2))
    });
    record.refresh_token.is_some()
        && record
            .expires
            .is_some_and(|expires| expires.saturating_sub(now) <= margin)
}

impl Sessions {
    /// Renews the access token of the request's session at `party` when it
    /// is due.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Poisoned`] for an unusable store. A
    /// provider's refusal or failure is a [`Freshness`], never an error.
    pub async fn keep_fresh(
        &self,
        party: &RelyingParty,
        headers: &HeaderMap,
    ) -> Result<Freshness, SessionError> {
        let Some(id) = self.session_id(headers) else {
            return Ok(Freshness::Current);
        };
        let memory = self.memory();
        let now = self.now();
        let gate = memory.with(
            &id,
            |record| self.live_at(record),
            |entry| due(&entry.record, now).then(|| std::sync::Arc::clone(&entry.gate)),
        )?;
        let Some(gate) = gate.flatten() else {
            return Ok(Freshness::Current);
        };
        let _refreshing = gate.lock().await;
        let now = self.now();
        let grant = memory.with(
            &id,
            |record| self.live_at(record),
            |entry| {
                due(&entry.record, now)
                    .then(|| entry.record.refresh_token.clone())
                    .flatten()
            },
        )?;
        let Some(refresh_token) = grant.flatten() else {
            return Ok(Freshness::Current);
        };
        match party.refresh(&refresh_token).await {
            Ok(refreshed) => {
                let now = self.now();
                memory.with(
                    &id,
                    |record| self.live_at(record),
                    |entry| {
                        let record = &mut entry.record;
                        record.credential =
                            crate::record::Credential::Bearer(refreshed.access_token);
                        record.token_issued(refreshed.expires_in, now);
                        if let Some(rotated) = refreshed.refresh_token {
                            record.refresh_token = Some(rotated);
                        }
                        if let Some(scopes) = refreshed.scopes {
                            record.scopes = scopes;
                        }
                    },
                )?;
                Ok(Freshness::Refreshed)
            }
            Err(error) if error.is_answered_refusal() => {
                memory.end(&id)?;
                Ok(Freshness::Ended(error))
            }
            Err(error) => Ok(Freshness::Unreached(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ferrohealth_secret::secret::Secret;

    use super::due;
    use crate::record::{Credential, Record, SignedIn};

    /// The last millisecond of a second, where a clock counted in whole
    /// seconds lies the furthest behind the time.
    const LATE: i64 = 1_800_000_000_999;

    fn refreshable(expires_in: Duration) -> SignedIn {
        SignedIn {
            operator: None,
            subject: Some(String::from("synthetic-subject")),
            scopes: Vec::new(),
            credential: Credential::Bearer(Secret::new("synthetic-access-token")),
            expires_in: Some(expires_in),
            refresh_token: Some(Secret::new("synthetic-refresh-token")),
            id_token: None,
        }
    }

    #[test]
    fn a_refreshed_token_is_not_due_before_half_its_life_has_passed() {
        let mut record = Record::begin(refreshable(Duration::ZERO), LATE);
        assert!(due(&record, LATE), "an expired token is due");
        record.token_issued(Some(Duration::from_secs(2)), LATE);
        assert!(
            !due(&record, LATE + 999),
            "999 ms into a 2 s token renewed at half its life"
        );
        assert!(due(&record, LATE + 1000), "half of its 2 s life has passed");
    }

    #[test]
    fn a_long_lived_token_is_due_within_the_margin_of_its_expiry() {
        let record = Record::begin(refreshable(Duration::from_secs(3600)), LATE);
        assert!(
            !due(&record, LATE + 3_540_000 - 1),
            "a millisecond before the margin"
        );
        assert!(
            due(&record, LATE + 3_540_000),
            "sixty seconds before expiry"
        );
    }

    #[test]
    fn a_token_without_a_refresh_token_is_never_due() {
        let record = Record::begin(
            SignedIn {
                refresh_token: None,
                ..refreshable(Duration::ZERO)
            },
            LATE,
        );
        assert!(!due(&record, LATE + 1000), "nothing can renew it");
    }
}
