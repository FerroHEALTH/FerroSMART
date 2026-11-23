// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! What was issued on a client's first-party mark (`docs/architecture.md`
//! §13.6 item 6).

use crate::store::{StoreError, Transaction};

impl Transaction {
    /// Revokes every grant of `client_id` issued with no page on its
    /// first-party mark, with its access and refresh tokens, and drops its
    /// unredeemed codes of that basis. Returns the grants revoked.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails.
    pub async fn revoke_first_party(&mut self, client_id: &str) -> Result<u64, StoreError> {
        for statement in [
            "UPDATE access_token SET revoked_at = now() WHERE revoked_at IS NULL AND grant_id IN \
             (SELECT id FROM authorization_grant WHERE client_id = $1 AND basis = 'first-party')",
            "UPDATE refresh_token SET revoked_at = now() WHERE revoked_at IS NULL AND grant_id IN \
             (SELECT id FROM authorization_grant WHERE client_id = $1 AND basis = 'first-party')",
            "DELETE FROM authorization_code \
             WHERE client_id = $1 AND basis = 'first-party' AND redeemed_at IS NULL",
        ] {
            sqlx::query(statement)
                .bind(client_id)
                .execute(&mut *self.tx)
                .await?;
        }
        let revoked = sqlx::query(
            "UPDATE authorization_grant SET revoked_at = now() \
             WHERE client_id = $1 AND basis = 'first-party' AND revoked_at IS NULL",
        )
        .bind(client_id)
        .execute(&mut *self.tx)
        .await?;
        Ok(revoked.rows_affected())
    }
}
