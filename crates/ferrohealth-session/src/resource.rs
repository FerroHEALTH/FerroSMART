// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! An access token for another resource server on the session's grant
//! (RFC 8707 §2.2).
//!
//! A session signed in for one resource server may need a token for a
//! second one of the same grant, such as the FHIR server paired with an
//! openEHR server. The refresh grant names it as `resource`, and the
//! provider audience-restricts the token to it, so each resource server
//! gets its own token (RFC 9068 §3, RFC 9700 §4.10.2). The token is kept
//! with the session until it is due, and the refresh token the
//! provider rotates replaces the session's (RFC 9700 §4.14.2). Keeping it is
//! our own design.

use std::fmt;
use std::time::Duration;

use ferrohealth_secret::secret::Secret;
use ferrohealth_smart::oidc::{OidcError, RelyingParty};
use http::HeaderMap;

use crate::lifetime::millis;
use crate::refresh::MARGIN;
use crate::sessions::{SessionError, Sessions};

/// A token for one resource server, kept with its session.
#[derive(Clone)]
pub(crate) struct Held {
    token: Secret,
    expires: Option<i64>,
    lifetime: Option<Duration>,
}

impl Held {
    /// Whether the token is due for renewal at `now`, as the session's own
    /// token is.
    fn due(&self, now: i64) -> bool {
        let margin = self.lifetime.map_or(millis(MARGIN), |lifetime| {
            millis(MARGIN).min(millis(lifetime).div_euclid(2))
        });
        self.expires
            .is_some_and(|expires| expires.saturating_sub(now) <= margin)
    }
}

/// What [`Sessions::token_for`] answered.
#[non_exhaustive]
pub enum ForResource {
    /// An access token for the resource.
    Issued(Secret),
    /// The request holds no session that can be refreshed: no session, a
    /// Basic sign-in, or no refresh token.
    Unavailable,
    /// The provider refused the resource (`invalid_target`, `invalid_scope`
    /// or another refusal but `invalid_grant`); the session stays.
    Refused(OidcError),
    /// The provider refused the refresh token itself (`invalid_grant`), so
    /// the session is ended.
    Ended(OidcError),
    /// The provider could not be reached or answered no token.
    Unreached(OidcError),
}

impl fmt::Debug for ForResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (name, error) = match self {
            Self::Issued(_) => return f.write_str("Issued(..)"),
            Self::Unavailable => return f.write_str("Unavailable"),
            Self::Refused(error) => ("Refused", error),
            Self::Ended(error) => ("Ended", error),
            Self::Unreached(error) => ("Unreached", error),
        };
        f.debug_tuple(name).field(error).finish()
    }
}

impl Sessions {
    /// Returns an access token for the resource server `resource` on the
    /// grant of the request's session at `party`: the one kept while it is
    /// not due, else a new one from a refresh that names `resource` (RFC
    /// 8707 §2.2), one per session at a time.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Poisoned`] for an unusable store. A
    /// provider's refusal or failure is a [`ForResource`], never an error.
    pub async fn token_for(
        &self,
        party: &RelyingParty,
        headers: &HeaderMap,
        resource: &str,
    ) -> Result<ForResource, SessionError> {
        let Some(id) = self.session_id(headers) else {
            return Ok(ForResource::Unavailable);
        };
        let memory = self.memory();
        let now = self.now();
        let found = memory.with(
            &id,
            |record| self.live_at(record),
            |entry| {
                let kept = entry
                    .resources
                    .get(resource)
                    .filter(|held| !held.due(now))
                    .map(|held| held.token.clone());
                (kept, std::sync::Arc::clone(&entry.gate))
            },
        )?;
        let Some((kept, gate)) = found else {
            return Ok(ForResource::Unavailable);
        };
        if let Some(token) = kept {
            return Ok(ForResource::Issued(token));
        }
        let _refreshing = gate.lock().await;
        let now = self.now();
        let read = memory.with(
            &id,
            |record| self.live_at(record),
            |entry| match entry.resources.get(resource).filter(|held| !held.due(now)) {
                Some(held) => Ok(held.token.clone()),
                None => Err(entry.record.refresh_token.clone()),
            },
        )?;
        let refresh_token = match read {
            None | Some(Err(None)) => return Ok(ForResource::Unavailable),
            Some(Ok(token)) => return Ok(ForResource::Issued(token)),
            Some(Err(Some(refresh_token))) => refresh_token,
        };
        match party.refresh_for(&refresh_token, resource).await {
            Ok(refreshed) => {
                let now = self.now();
                let token = refreshed.access_token.clone();
                memory.with(
                    &id,
                    |record| self.live_at(record),
                    |entry| {
                        if let Some(rotated) = refreshed.refresh_token {
                            entry.record.refresh_token = Some(rotated);
                        }
                        entry.resources.insert(
                            resource.to_owned(),
                            Held {
                                token: refreshed.access_token,
                                expires: refreshed
                                    .expires_in
                                    .map(|lifetime| now.saturating_add(millis(lifetime))),
                                lifetime: refreshed.expires_in,
                            },
                        );
                    },
                )?;
                Ok(ForResource::Issued(token))
            }
            // NOTE: RFC 6749 §5.2, `invalid_grant` is the refresh token itself being
            // invalid; any other refusal is about the request, so the session stays.
            Err(error) if error.oauth_error() == Some("invalid_grant") => {
                memory.end(&id)?;
                Ok(ForResource::Ended(error))
            }
            Err(error) if error.is_answered_refusal() => Ok(ForResource::Refused(error)),
            Err(error) => Ok(ForResource::Unreached(error)),
        }
    }
}
