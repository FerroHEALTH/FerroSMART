// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The organisation approvals of the clients and what was issued on them
//! (`docs/architecture.md` §13.6 item 6, §13.9).

use crate::store::{StoreError, Transaction};

impl Transaction {
    /// Withdraws the organisation approval of `client_id` given at
    /// `approved_at` (seconds since the epoch): every grant issued on it is
    /// revoked with its access and refresh tokens, and every code issued on
    /// it and not yet redeemed is dropped. Returns the grants revoked.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails.
    pub async fn withdraw_approval(
        &mut self,
        client_id: &str,
        approved_at: i64,
    ) -> Result<u64, StoreError> {
        sqlx::query(
            "UPDATE access_token SET revoked_at = now() WHERE revoked_at IS NULL AND grant_id IN \
             (SELECT id FROM authorization_grant WHERE client_id = $1 AND approved_at = to_timestamp($2))",
        )
        .bind(client_id)
        .bind(approved_at)
        .execute(&mut *self.tx)
        .await?;
        sqlx::query(
            "UPDATE refresh_token SET revoked_at = now() WHERE revoked_at IS NULL AND grant_id IN \
             (SELECT id FROM authorization_grant WHERE client_id = $1 AND approved_at = to_timestamp($2))",
        )
        .bind(client_id)
        .bind(approved_at)
        .execute(&mut *self.tx)
        .await?;
        let revoked = sqlx::query(
            "UPDATE authorization_grant SET revoked_at = now() \
             WHERE client_id = $1 AND approved_at = to_timestamp($2) AND revoked_at IS NULL",
        )
        .bind(client_id)
        .bind(approved_at)
        .execute(&mut *self.tx)
        .await?;
        sqlx::query(
            "DELETE FROM authorization_code \
             WHERE client_id = $1 AND approved_at = to_timestamp($2) AND redeemed_at IS NULL",
        )
        .bind(client_id)
        .bind(approved_at)
        .execute(&mut *self.tx)
        .await?;
        Ok(revoked.rows_affected())
    }
}
