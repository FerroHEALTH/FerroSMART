// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! A person's grants, consents and sessions as an administrator reads and
//! ends them (`docs/architecture.md` §13.8).

use sqlx::Row as _;

use crate::store::grant::revoke_in;
use crate::store::{Store, StoreError, Transaction};

/// A grant that still holds live access: a refresh token neither used,
/// revoked nor lapsed, or an access token neither revoked nor expired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveGrant {
    /// The grant's id.
    pub id: String,
    /// The client it was issued to.
    pub client_id: String,
    /// The resource server its tokens name in `aud`.
    pub audience: String,
    /// Its scope.
    pub scope: String,
    /// Why it was issued without or with a page: `page`, `remembered`,
    /// `administrative` or `first-party`; none for a grant from before the
    /// basis was recorded.
    pub basis: Option<String>,
    /// `offline` or `online`, when its refresh tokens are issued with one.
    pub access: Option<String>,
    /// When it was issued, in seconds since the epoch.
    pub issued_at: i64,
    /// When a token was last issued under it, in seconds since the epoch.
    pub last_used_at: Option<i64>,
}

/// A consent a person chose to remember.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RememberedConsent {
    /// The client.
    pub client_id: String,
    /// The resource server.
    pub audience: String,
    /// The scopes remembered.
    pub scope: String,
    /// When it was given, in seconds since the epoch.
    pub granted_at: i64,
}

/// What ending a person's sessions ended ([`Transaction::end_sessions`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndedSessions {
    /// How many upstream sessions ended.
    pub sessions: u64,
    /// How many `online_access` grants were revoked, with their tokens.
    pub grants: u64,
}

impl Store {
    /// Returns the grants of `subject` that still hold live access, newest
    /// first.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails.
    pub async fn live_grants(&self, subject: &str) -> Result<Vec<LiveGrant>, StoreError> {
        let rows = sqlx::query(
            "SELECT g.id, g.client_id, g.audience, g.scope, g.basis, g.access, \
             extract(epoch FROM g.created_at)::bigint AS issued_at, \
             extract(epoch FROM GREATEST( \
               (SELECT max(r.issued_at) FROM refresh_token r WHERE r.grant_id = g.id), \
               (SELECT max(a.issued_at) FROM access_token a WHERE a.grant_id = g.id)))::bigint \
               AS last_used_at \
             FROM authorization_grant g \
             WHERE g.subject = $1 AND g.revoked_at IS NULL AND ( \
               EXISTS (SELECT 1 FROM refresh_token r WHERE r.grant_id = g.id \
                 AND r.used_at IS NULL AND r.revoked_at IS NULL AND r.expires_at > now()) \
               OR EXISTS (SELECT 1 FROM access_token a WHERE a.grant_id = g.id \
                 AND a.revoked_at IS NULL AND a.expires_at > now())) \
             ORDER BY g.created_at DESC, g.id",
        )
        .bind(subject)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(LiveGrant {
                    id: row.try_get("id")?,
                    client_id: row.try_get("client_id")?,
                    audience: row.try_get("audience")?,
                    scope: row.try_get("scope")?,
                    basis: row.try_get("basis")?,
                    access: row.try_get("access")?,
                    issued_at: row.try_get("issued_at")?,
                    last_used_at: row.try_get("last_used_at")?,
                })
            })
            .collect()
    }

    /// Returns every consent `subject` remembered, by client and resource
    /// server.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails.
    pub async fn remembered_consents(
        &self,
        subject: &str,
    ) -> Result<Vec<RememberedConsent>, StoreError> {
        let rows = sqlx::query(
            "SELECT client_id, audience, scope, extract(epoch FROM granted_at)::bigint AS granted_at \
             FROM consent WHERE subject = $1 ORDER BY client_id, audience",
        )
        .bind(subject)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(RememberedConsent {
                    client_id: row.try_get("client_id")?,
                    audience: row.try_get("audience")?,
                    scope: row.try_get("scope")?,
                    granted_at: row.try_get("granted_at")?,
                })
            })
            .collect()
    }
}

impl Transaction {
    /// Revokes the live grant `grant_id` of `subject` with every token under
    /// it, and returns the client it was issued to; none when `subject` holds
    /// no such live grant.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails; nothing is
    /// changed then.
    pub async fn revoke_subject_grant(
        &mut self,
        subject: &str,
        grant_id: &str,
    ) -> Result<Option<String>, StoreError> {
        let client: Option<String> = sqlx::query_scalar(
            "SELECT client_id FROM authorization_grant \
             WHERE id = $1 AND subject = $2 AND revoked_at IS NULL FOR UPDATE",
        )
        .bind(grant_id)
        .bind(subject)
        .fetch_optional(&mut *self.tx)
        .await?;
        if client.is_some() {
            revoke_in(&mut self.tx, grant_id).await?;
        }
        Ok(client)
    }

    /// Ends every live upstream session `subject`'s grants were issued in,
    /// revoking the `online_access` grants in them with every token under
    /// them, as a logout at the provider would (`docs/architecture.md`
    /// §13.6 item 7).
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails; nothing is
    /// changed then.
    pub async fn end_sessions(&mut self, subject: &str) -> Result<EndedSessions, StoreError> {
        let ended: Vec<String> = sqlx::query_scalar(
            "UPDATE upstream_session SET ended_at = now() WHERE ended_at IS NULL AND id IN \
             (SELECT upstream_session FROM authorization_grant WHERE subject = $1) \
             RETURNING id",
        )
        .bind(subject)
        .fetch_all(&mut *self.tx)
        .await?;
        let grants: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM authorization_grant WHERE subject = $1 AND access = 'online' \
             AND revoked_at IS NULL AND upstream_session = ANY($2)",
        )
        .bind(subject)
        .bind(&ended)
        .fetch_all(&mut *self.tx)
        .await?;
        let mut revoked: u64 = 0;
        for grant in &grants {
            if revoke_in(&mut self.tx, grant).await? {
                revoked = revoked.saturating_add(1);
            }
        }
        Ok(EndedSessions {
            sessions: ended.iter().fold(0_u64, |count, _| count.saturating_add(1)),
            grants: revoked,
        })
    }
}
