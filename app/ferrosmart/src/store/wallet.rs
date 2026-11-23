// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The wallet's accepted presentations between the response URI and the
//! browser.
//!
//! An answer is kept under its request's nonce, so the nonce is answered
//! once (OpenID4VP 1.0 §14.1.2), and under the SHA-256 of the response code
//! the browser brings back, so only that browser takes it (§14.2). It is
//! taken once, and the row stays until its request lapses so the nonce
//! cannot be answered again. No specification governs the storage: our own
//! design.

use sqlx::Row as _;
use sqlx::types::Json;

use crate::store::{Store, StoreError};

/// What the wallet answered for one request.
#[derive(Clone, PartialEq, Eq)]
pub struct Answer {
    /// The pending authorization request it answers.
    pub pending_id: String,
    /// The person the presentation names.
    pub identity: serde_json::Value,
}

impl std::fmt::Debug for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Answer").finish_non_exhaustive()
    }
}

impl Store {
    /// Records the answer `answer` to the request whose nonce is `nonce`,
    /// to be taken with the response code whose SHA-256 is `code_hash` until
    /// `expires_at` (seconds since the epoch), and returns whether the nonce
    /// was unanswered: a `false` is a replay.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn first_answer(
        &self,
        nonce: &str,
        code_hash: &str,
        answer: &Answer,
        expires_at: i64,
    ) -> Result<bool, StoreError> {
        let inserted = sqlx::query(
            "INSERT INTO wallet_answer (nonce, pending_id, response_code_hash, identity, expires_at) \
             VALUES ($1, $2, $3, $4, to_timestamp($5)) ON CONFLICT (nonce) DO NOTHING",
        )
        .bind(nonce)
        .bind(&answer.pending_id)
        .bind(code_hash)
        .bind(Json(&answer.identity))
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(inserted.rows_affected() == 1)
    }

    /// Takes the answer the response code whose SHA-256 is `code_hash`
    /// names, once, while it lives.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn take_answer(&self, code_hash: &str) -> Result<Option<Answer>, StoreError> {
        let row = sqlx::query(
            "UPDATE wallet_answer SET taken_at = now() \
             WHERE response_code_hash = $1 AND taken_at IS NULL AND expires_at > now() \
             RETURNING pending_id, identity",
        )
        .bind(code_hash)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            let Json(identity) = row.try_get("identity")?;
            Ok(Answer {
                pending_id: row.try_get("pending_id")?,
                identity,
            })
        })
        .transpose()
    }
}
