// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The admin API's reads and writes of the client registry
//! (`docs/architecture.md` §13.8).
//!
//! Every write runs in an audited [`Transaction`]. No specification governs
//! the registry's storage: our own design.

use sqlx::Row as _;

use crate::clients::Client;
use crate::store::{
    CLIENT_COLUMNS, RegisteredBy, Store, StoreError, Transaction, read_client, write_client,
};

/// A client as the registry holds it, disabled or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    /// The client.
    pub client: Client,
    /// Who registered it.
    pub by: RegisteredBy,
    /// When it was disabled, in seconds since the epoch; none while it is
    /// enabled.
    pub disabled_at: Option<i64>,
}

/// What disabling a client ended.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ended {
    /// The grants revoked, each with its refresh tokens.
    pub grants: u64,
    /// The access tokens revoked, with or without a grant.
    pub access_tokens: u64,
    /// The remembered consents forgotten.
    pub consents: u64,
}

/// The query of every registered client's row.
fn select(filter: &str) -> String {
    format!(
        "SELECT {CLIENT_COLUMNS}, extract(epoch FROM disabled_at)::bigint AS disabled_at \
         FROM client {filter}"
    )
}

/// Reads a `client` row with its disabled time.
fn read_registered(row: &sqlx::postgres::PgRow) -> Result<Registered, StoreError> {
    let client = read_client(row)?;
    Ok(Registered {
        disabled_at: row.try_get("disabled_at")?,
        by: RegisteredBy::of(&client),
        client,
    })
}

impl Store {
    /// Returns every registered client, disabled ones included, by id.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails and
    /// [`StoreError::Corrupt`] for a row the server never writes.
    pub async fn registered(&self) -> Result<Vec<Registered>, StoreError> {
        let rows = sqlx::query(sqlx::AssertSqlSafe(select("ORDER BY client_id")))
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(read_registered).collect()
    }

    /// Returns the client registered as `client_id`, disabled or not.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails and
    /// [`StoreError::Corrupt`] for a row the server never writes.
    pub async fn registered_client(
        &self,
        client_id: &str,
    ) -> Result<Option<Registered>, StoreError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(select("WHERE client_id = $1")))
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(read_registered).transpose()
    }
}

impl Store {
    /// Returns whether the enabled client `client_id` holds the registration
    /// access token whose SHA-256 is `hash`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails.
    pub async fn holds_registration_token(
        &self,
        client_id: &str,
        hash: &str,
    ) -> Result<bool, StoreError> {
        let held: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM client WHERE client_id = $1 AND registration_token_hash = $2 \
             AND disabled_at IS NULL",
        )
        .bind(client_id)
        .bind(hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(held.is_some())
    }
}

impl Transaction {
    /// Returns the client registered as `client_id`, its row locked until
    /// the transaction ends, so two changes of one client queue.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails and
    /// [`StoreError::Corrupt`] for a row the server never writes.
    pub async fn lock_client(&mut self, client_id: &str) -> Result<Option<Registered>, StoreError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(select(
            "WHERE client_id = $1 FOR UPDATE",
        )))
        .bind(client_id)
        .fetch_optional(&mut *self.tx)
        .await?;
        row.as_ref().map(read_registered).transpose()
    }

    /// Registers `client`; `false` when its id is registered already, and
    /// nothing is written then.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails, a launch URL
    /// another client registers included.
    pub async fn create_client(&mut self, client: &Client) -> Result<bool, StoreError> {
        let claimed = sqlx::query(
            "INSERT INTO client (client_id, client_name, token_endpoint_auth_method, registered_by) VALUES ($1, $1, 'none', $2) \
             ON CONFLICT (client_id) DO NOTHING",
        )
        .bind(&client.client_id)
        .bind(RegisteredBy::of(client).as_str())
        .execute(&mut *self.tx)
        .await?;
        if claimed.rows_affected() == 0 {
            return Ok(false);
        }
        write_client(&mut self.tx, client).await?;
        Ok(true)
    }

    /// Writes `client` over its row, which keeps its disabled time.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails, a launch URL
    /// another client registers included.
    pub async fn update_client(&mut self, client: &Client) -> Result<(), StoreError> {
        write_client(&mut self.tx, client).await
    }

    /// Replaces the registration access token of `client_id` with the one
    /// whose SHA-256 is `hash` (RFC 7592 §3).
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn set_registration_token(
        &mut self,
        client_id: &str,
        hash: &str,
    ) -> Result<(), StoreError> {
        sqlx::query("UPDATE client SET registration_token_hash = $2 WHERE client_id = $1")
            .bind(client_id)
            .bind(hash)
            .execute(&mut *self.tx)
            .await?;
        Ok(())
    }

    /// Deletes `client_id` once [`Transaction::disable_client`] ended
    /// everything it held (RFC 7592 §2.3).
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn delete_client(&mut self, client_id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM client WHERE client_id = $1")
            .bind(client_id)
            .execute(&mut *self.tx)
            .await?;
        Ok(())
    }

    /// Replaces the secret hash of `client_id` with `hash`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn set_secret(
        &mut self,
        client_id: &str,
        hash: &crate::clients::SecretHash,
    ) -> Result<(), StoreError> {
        sqlx::query("UPDATE client SET secret_hash = $2, updated_at = now() WHERE client_id = $1")
            .bind(client_id)
            .bind(hash.phc())
            .execute(&mut *self.tx)
            .await?;
        Ok(())
    }

    /// Disables `client_id`: no request finds it again, every grant and
    /// access token it holds is revoked with its refresh tokens, and its
    /// codes, launches, pending requests and remembered consents are
    /// dropped.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails.
    pub async fn disable_client(&mut self, client_id: &str) -> Result<Ended, StoreError> {
        sqlx::query(
            "UPDATE client SET disabled_at = now(), updated_at = now() \
             WHERE client_id = $1 AND disabled_at IS NULL",
        )
        .bind(client_id)
        .execute(&mut *self.tx)
        .await?;
        let access_tokens = sqlx::query(
            "UPDATE access_token SET revoked_at = now() WHERE client_id = $1 AND revoked_at IS NULL",
        )
        .bind(client_id)
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        sqlx::query(
            "UPDATE refresh_token SET revoked_at = now() WHERE revoked_at IS NULL AND grant_id IN \
             (SELECT id FROM authorization_grant WHERE client_id = $1)",
        )
        .bind(client_id)
        .execute(&mut *self.tx)
        .await?;
        let grants = sqlx::query(
            "UPDATE authorization_grant SET revoked_at = now() WHERE client_id = $1 AND revoked_at IS NULL",
        )
        .bind(client_id)
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        for statement in [
            "DELETE FROM authorization_code WHERE client_id = $1 AND redeemed_at IS NULL",
            "DELETE FROM launch WHERE client_id = $1 AND used_at IS NULL",
            "DELETE FROM pending_authorization WHERE client_id = $1",
            "DELETE FROM pushed_request WHERE client_id = $1",
        ] {
            sqlx::query(statement)
                .bind(client_id)
                .execute(&mut *self.tx)
                .await?;
        }
        let consents = sqlx::query("DELETE FROM consent WHERE client_id = $1")
            .bind(client_id)
            .execute(&mut *self.tx)
            .await?
            .rows_affected();
        Ok(Ended {
            grants,
            access_tokens,
            consents,
        })
    }

    /// Enables the disabled client `client_id`; `false` when it was not
    /// disabled.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn enable_client(&mut self, client_id: &str) -> Result<bool, StoreError> {
        let enabled = sqlx::query(
            "UPDATE client SET disabled_at = NULL, updated_at = now() \
             WHERE client_id = $1 AND disabled_at IS NOT NULL",
        )
        .bind(client_id)
        .execute(&mut *self.tx)
        .await?;
        Ok(enabled.rows_affected() == 1)
    }
}
