// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The patients a person chose on the picker, kept for the configured
//! retention so the picker can list them again (`docs/architecture.md`
//! §13.6 item 4). No specification governs the list: our own design.

use std::time::Duration;

use crate::store::{Store, StoreError, Transaction};

/// The most patients kept for one person at one resource server; the
/// oldest goes first. No specification governs the value: our own design.
pub const KEPT: i64 = 10;

impl Store {
    /// Records that `subject` chose `patient` at `audience` now, keeping
    /// their [`KEPT`] latest choices there.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails.
    pub async fn remember_patient(
        &self,
        subject: &str,
        audience: &str,
        patient: &str,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO recent_patient (subject, audience, patient, chosen_at) \
             VALUES ($1, $2, $3, now()) \
             ON CONFLICT (subject, audience, patient) DO UPDATE SET chosen_at = now()",
        )
        .bind(subject)
        .bind(audience)
        .bind(patient)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM recent_patient WHERE subject = $1 AND audience = $2 AND patient NOT IN \
             (SELECT patient FROM recent_patient WHERE subject = $1 AND audience = $2 \
              ORDER BY chosen_at DESC, patient LIMIT $3)",
        )
        .bind(subject)
        .bind(audience)
        .bind(KEPT)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Returns the patients `subject` chose at `audience` within
    /// `retention`, the latest first.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails.
    pub async fn recent_patients(
        &self,
        subject: &str,
        audience: &str,
        retention: Duration,
    ) -> Result<Vec<String>, StoreError> {
        Ok(sqlx::query_scalar(
            "SELECT patient FROM recent_patient WHERE subject = $1 AND audience = $2 \
             AND chosen_at > now() - make_interval(secs => $3) \
             ORDER BY chosen_at DESC, patient",
        )
        .bind(subject)
        .bind(audience)
        .bind(retention.as_secs_f64())
        .fetch_all(&self.pool)
        .await?)
    }

    /// Returns how many patients `subject` chose that the store keeps.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails.
    pub async fn recent_count(&self, subject: &str) -> Result<i32, StoreError> {
        Ok(
            sqlx::query_scalar("SELECT count(*)::integer FROM recent_patient WHERE subject = $1")
                .bind(subject)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    /// Deletes every choice older than `retention`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn sweep_recent(&self, retention: Duration) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM recent_patient WHERE chosen_at <= now() - make_interval(secs => $1)",
        )
        .bind(retention.as_secs_f64())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

impl Transaction {
    /// Forgets every patient `subject` chose, and returns how many.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn forget_recent(&mut self, subject: &str) -> Result<u64, StoreError> {
        Ok(sqlx::query("DELETE FROM recent_patient WHERE subject = $1")
            .bind(subject)
            .execute(&mut *self.tx)
            .await?
            .rows_affected())
    }
}
