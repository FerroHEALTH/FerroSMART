// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! FerroSMART's own audit records (`docs/architecture.md` §13.2): written in
//! the transaction of the action they record, read back by subject and time,
//! and the outbox the ITI-20 FHIR Feed delivers from.

use serde_json::Value;
use sqlx::Row as _;

use crate::store::{Store, StoreError};

/// One audit record to store.
#[derive(Debug, Clone)]
pub struct AuditRow {
    /// When the action ended, as RFC 3339.
    pub recorded_at: String,
    /// What was recorded, such as `token` or `login`.
    pub kind: &'static str,
    /// The `AuditEvent.outcome` code.
    pub outcome: &'static str,
    /// The person the record names, by their pairwise subject.
    pub subject: Option<String>,
    /// The client the record names.
    pub client_id: Option<String>,
    /// The `AuditEvent` as FHIR JSON.
    pub document: String,
}

/// Which records a reader asks for, newest first.
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    /// Only the records naming this person.
    pub subject: Option<String>,
    /// Only the records naming this client.
    pub client: Option<String>,
    /// Only the records of this event, such as `token` or `grant-revoked`.
    pub event: Option<String>,
    /// Only the records with this `AuditEvent.outcome` code.
    pub outcome: Option<String>,
    /// Only the records after this one in the order read, for the next
    /// page.
    pub after: Option<AuditCursor>,
    /// Only the records from this instant on, as RFC 3339.
    pub since: Option<String>,
    /// Only the records before this instant, as RFC 3339.
    pub until: Option<String>,
    /// The most records returned.
    pub limit: i64,
}

/// Where a page of records ends: the last record's time, in microseconds
/// since the epoch, and its sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditCursor {
    /// The record's time, in microseconds since the epoch.
    pub micros: i64,
    /// The record's sequence number.
    pub seq: i64,
}

impl std::fmt::Display for AuditCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.micros, self.seq)
    }
}

impl std::str::FromStr for AuditCursor {
    type Err = std::num::ParseIntError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (micros, seq) = text.split_once('.').unwrap_or((text, ""));
        Ok(Self {
            micros: micros.parse()?,
            seq: seq.parse()?,
        })
    }
}

/// One page of records, newest first, with where the next page starts.
#[derive(Debug, Clone)]
pub struct AuditPage {
    /// The records, each an `AuditEvent`.
    pub records: Vec<Value>,
    /// Where the next page starts, when more records match.
    pub next: Option<AuditCursor>,
}

impl Store {
    /// Stores `row` alone: for an action that writes nothing else.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn record_audit(&self, row: &AuditRow) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        insert(&mut tx, row).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Returns the records `query` asks for, newest first, each an
    /// `AuditEvent`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn audit_records(&self, query: &AuditQuery) -> Result<Vec<Value>, StoreError> {
        Ok(self.audit_page(query).await?.records)
    }

    /// Returns the page of records `query` asks for, newest first, and
    /// where the next page starts.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn audit_page(&self, query: &AuditQuery) -> Result<AuditPage, StoreError> {
        let rows = sqlx::query(
            "SELECT document, seq, (extract(epoch FROM recorded_at) * 1000000)::bigint AS micros \
             FROM audit_record \
             WHERE ($1::text IS NULL OR subject = $1) \
               AND ($2::timestamptz IS NULL OR recorded_at >= $2::timestamptz) \
               AND ($3::timestamptz IS NULL OR recorded_at < $3::timestamptz) \
               AND ($4::text IS NULL OR client_id = $4) \
               AND ($5::text IS NULL OR kind = $5) \
               AND ($6::text IS NULL OR outcome = $6) \
               AND ($7::bigint IS NULL OR (recorded_at, seq) < \
                 ('epoch'::timestamptz + $7::bigint * interval '1 microsecond', $8::bigint)) \
             ORDER BY recorded_at DESC, seq DESC LIMIT $9",
        )
        .bind(query.subject.as_deref())
        .bind(query.since.as_deref())
        .bind(query.until.as_deref())
        .bind(query.client.as_deref())
        .bind(query.event.as_deref())
        .bind(query.outcome.as_deref())
        .bind(query.after.map(|cursor| cursor.micros))
        .bind(query.after.map(|cursor| cursor.seq))
        .bind(query.limit.saturating_add(1))
        .fetch_all(&self.pool)
        .await?;
        let mut records = Vec::with_capacity(rows.len());
        let mut last = None;
        let mut more = false;
        for (index, row) in rows.iter().enumerate() {
            if i64::try_from(index).is_ok_and(|index| index >= query.limit) {
                more = true;
                break;
            }
            records.push(row.try_get::<Value, _>("document")?);
            last = Some(AuditCursor {
                micros: row.try_get("micros")?,
                seq: row.try_get("seq")?,
            });
        }
        Ok(AuditPage {
            records,
            next: last.filter(|_| more),
        })
    }

    /// Returns the oldest record the feed has not delivered nor seen
    /// refused, with how many wait.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails.
    pub async fn oldest_undelivered(&self) -> Result<(Option<(i64, Value)>, i64), StoreError> {
        let oldest = sqlx::query(
            "SELECT seq, document FROM audit_record \
             WHERE delivered_at IS NULL AND refused_at IS NULL ORDER BY seq LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?
        .map(|row| Ok::<_, sqlx::Error>((row.try_get("seq")?, row.try_get("document")?)))
        .transpose()?;
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_record WHERE delivered_at IS NULL AND refused_at IS NULL",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok((oldest, waiting))
    }

    /// Stamps the record `seq` delivered.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn audit_delivered(&self, seq: i64) -> Result<(), StoreError> {
        sqlx::query("UPDATE audit_record SET delivered_at = now() WHERE seq = $1")
            .bind(seq)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Stamps the record `seq` refused by the repository, keeping it for an
    /// operator.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn audit_refused(&self, seq: i64) -> Result<(), StoreError> {
        sqlx::query("UPDATE audit_record SET refused_at = now() WHERE seq = $1")
            .bind(seq)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Returns how many records the repository refused.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn audit_refused_count(&self) -> Result<i64, StoreError> {
        Ok(
            sqlx::query_scalar("SELECT count(*) FROM audit_record WHERE refused_at IS NOT NULL")
                .fetch_one(&self.pool)
                .await?,
        )
    }
}

/// Inserts `row` in `tx`.
pub(crate) async fn insert(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &AuditRow,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO audit_record (recorded_at, kind, outcome, subject, client_id, document) \
         VALUES ($1::timestamptz, $2, $3, $4, $5, $6::jsonb)",
    )
    .bind(&row.recorded_at)
    .bind(row.kind)
    .bind(row.outcome)
    .bind(row.subject.as_deref())
    .bind(row.client_id.as_deref())
    .bind(&row.document)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
