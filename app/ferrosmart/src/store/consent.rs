// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The consents people chose to remember (`docs/architecture.md` §13.6
//! item 6, §13.9).

use sqlx::Row as _;

use crate::store::grant::Access;
use crate::store::{Store, StoreError, Transaction};

impl Store {
    /// Returns the scopes `subject` chose to remember for `client_id` at
    /// the resource server `audience`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails.
    pub async fn remembered(
        &self,
        subject: &str,
        client_id: &str,
        audience: &str,
    ) -> Result<Option<String>, StoreError> {
        let row = sqlx::query(
            "SELECT scope FROM consent WHERE subject = $1 AND client_id = $2 AND audience = $3",
        )
        .bind(subject)
        .bind(client_id)
        .bind(audience)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| row.try_get("scope").map_err(StoreError::from))
            .transpose()
    }

    /// Returns every consent `subject` remembered, by client, one row per
    /// resource server.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails.
    pub async fn consents(&self, subject: &str) -> Result<Vec<(String, String)>, StoreError> {
        self.scopes_by_client(
            "SELECT client_id, scope FROM consent WHERE subject = $1 ORDER BY client_id, audience",
            subject,
        )
        .await
    }

    /// Returns the `client_id` and `scope` of each row `query` answers for
    /// `subject`, its one parameter.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails.
    pub(crate) async fn scopes_by_client(
        &self,
        query: &'static str,
        subject: &str,
    ) -> Result<Vec<(String, String)>, StoreError> {
        let rows = sqlx::query(query)
            .bind(subject)
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| Ok((row.try_get("client_id")?, row.try_get("scope")?)))
            .collect()
    }

    /// Returns each client that holds live access to `subject`'s data: a
    /// grant not revoked with a refresh token neither used, revoked nor
    /// lapsed, or with an access token neither revoked nor expired.
    ///
    /// Each app carries the scope of its newest such grant, the refresh
    /// access of its newest grant that can still refresh, and whether any
    /// of its grants was issued with no page on its registration, and on its
    /// first-party mark.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails, or
    /// [`StoreError::Corrupt`] for an access the server never writes.
    pub async fn connected_apps(&self, subject: &str) -> Result<Vec<ConnectedApp>, StoreError> {
        let rows = sqlx::query(
            "SELECT g.client_id, g.scope, g.access, \
             COALESCE(g.basis IN ('administrative', 'first-party'), false) AS organisation, \
             COALESCE(g.basis = 'first-party', false) AS first_party, \
             EXISTS (SELECT 1 FROM refresh_token r WHERE r.grant_id = g.id \
               AND r.used_at IS NULL AND r.revoked_at IS NULL AND r.expires_at > now()) \
               AS refreshable, \
             EXISTS (SELECT 1 FROM access_token a WHERE a.grant_id = g.id \
               AND a.revoked_at IS NULL AND a.expires_at > now()) AS bearer \
             FROM authorization_grant g \
             WHERE g.subject = $1 AND g.revoked_at IS NULL \
             ORDER BY g.client_id, g.created_at DESC",
        )
        .bind(subject)
        .fetch_all(&self.pool)
        .await?;
        let mut apps: Vec<ConnectedApp> = Vec::new();
        for row in &rows {
            let refreshable: bool = row.try_get("refreshable")?;
            if !refreshable && !row.try_get::<bool, _>("bearer")? {
                continue;
            }
            let client_id: String = row.try_get("client_id")?;
            let access = if refreshable {
                match row.try_get::<Option<String>, _>("access")?.as_deref() {
                    Some("offline") => Some(Access::Offline),
                    Some("online") => Some(Access::Online),
                    None => None,
                    Some(_) => return Err(StoreError::Corrupt { client_id }),
                }
            } else {
                None
            };
            let organisation: bool = row.try_get("organisation")?;
            let first_party: bool = row.try_get("first_party")?;
            match apps.last_mut() {
                Some(app) if app.client_id == client_id => {
                    app.access = app.access.or(access);
                    app.organisation |= organisation;
                    app.first_party |= first_party;
                }
                _ => apps.push(ConnectedApp {
                    client_id,
                    scope: row.try_get("scope")?,
                    access,
                    organisation,
                    first_party,
                }),
            }
        }
        Ok(apps)
    }
}

/// An app that holds live access to a person's data, as
/// [`Store::connected_apps`] reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectedApp {
    /// The client.
    pub client_id: String,
    /// The scope of its newest live grant.
    pub scope: String,
    /// The refresh access it holds, if any.
    pub access: Option<Access>,
    /// Whether it holds access on its registration, the organisation's
    /// administrative consent, with no page.
    pub organisation: bool,
    /// Whether that registration marks it first party.
    pub first_party: bool,
}

/// What disconnecting an app from a person ended
/// ([`Transaction::revoke_consent`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disconnected {
    /// Whether a remembered consent was forgotten.
    pub remembered: bool,
    /// How many grants were revoked, with their tokens.
    pub grants: u64,
}

impl Transaction {
    /// Remembers that `subject` gave `client_id` the scopes `scope` at the
    /// resource server `audience`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn remember(
        &mut self,
        subject: &str,
        client_id: &str,
        audience: &str,
        scope: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO consent (subject, client_id, audience, scope) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (subject, client_id, audience) DO UPDATE SET scope = $4, granted_at = now()",
        )
        .bind(subject)
        .bind(client_id)
        .bind(audience)
        .bind(scope)
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Disconnects `client_id` from `subject`: forgets the consent they
    /// remembered for it, if any, and revokes every grant, refresh token
    /// and access token issued to the client about them, whatever basis
    /// issued it (SMART App Launch 2.2.0, Conformance,
    /// `management_endpoint`). The client's registration is left as it
    /// stands.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails; nothing is
    /// changed then.
    pub async fn revoke_consent(
        &mut self,
        subject: &str,
        client_id: &str,
    ) -> Result<Disconnected, StoreError> {
        let forgotten = sqlx::query("DELETE FROM consent WHERE subject = $1 AND client_id = $2")
            .bind(subject)
            .bind(client_id)
            .execute(&mut *self.tx)
            .await?;
        sqlx::query(
            "UPDATE access_token SET revoked_at = now() \
             WHERE subject = $1 AND client_id = $2 AND revoked_at IS NULL",
        )
        .bind(subject)
        .bind(client_id)
        .execute(&mut *self.tx)
        .await?;
        sqlx::query(
            "UPDATE refresh_token SET revoked_at = now() WHERE revoked_at IS NULL AND grant_id IN \
             (SELECT id FROM authorization_grant WHERE subject = $1 AND client_id = $2)",
        )
        .bind(subject)
        .bind(client_id)
        .execute(&mut *self.tx)
        .await?;
        let grants = sqlx::query(
            "UPDATE authorization_grant SET revoked_at = now() \
             WHERE subject = $1 AND client_id = $2 AND revoked_at IS NULL",
        )
        .bind(subject)
        .bind(client_id)
        .execute(&mut *self.tx)
        .await?;
        Ok(Disconnected {
            remembered: forgotten.rows_affected() == 1,
            grants: grants.rows_affected(),
        })
    }
}
