// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The pushed authorization requests (RFC 9126): each kept as the SHA-256
//! of its `request_uri`, bound to the client that pushed it and taken once.

use sqlx::Row as _;

use crate::store::{Store, StoreError};

impl Store {
    /// Records the authorization request `parameters`, form-encoded, that
    /// the client `client_id` pushed, under the SHA-256 `request_uri_hash`
    /// of its `request_uri`, until `expires_at` in seconds since the epoch.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn push_request(
        &self,
        request_uri_hash: &str,
        client_id: &str,
        parameters: &str,
        expires_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO pushed_request (request_uri_hash, client_id, parameters, expires_at) \
             VALUES ($1, $2, $3, to_timestamp($4))",
        )
        .bind(request_uri_hash)
        .bind(client_id)
        .bind(parameters)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Takes the pushed request whose `request_uri` hashes to
    /// `request_uri_hash` for the client `client_id`, in one statement so
    /// two replicas never both take it: none when it is unknown, taken,
    /// lapsed or another client's (RFC 9126 §2.2, §4).
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn take_pushed(
        &self,
        request_uri_hash: &str,
        client_id: &str,
    ) -> Result<Option<String>, StoreError> {
        let row = sqlx::query(
            "DELETE FROM pushed_request WHERE request_uri_hash = $1 \
             RETURNING client_id, parameters, expires_at > now() AS live",
        )
        .bind(request_uri_hash)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let live: bool = row.try_get("live")?;
        let owner: String = row.try_get("client_id")?;
        Ok((live && owner == client_id)
            .then(|| row.try_get("parameters"))
            .transpose()?)
    }
}
