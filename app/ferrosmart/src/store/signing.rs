// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The state of each token signing key, which the replicas share so they
//! agree on the key that signs (`docs/architecture.md` §13.11).
//!
//! A key is `next` from the moment it is published, `active` while it
//! signs, `retiring` while the tokens it signed may still be presented, and
//! `retired` for good after that. No specification governs the schedule:
//! our own design over RFC 7517 §5 and OpenID Connect Core 1.0 §10.1.1.

use std::collections::BTreeMap;
use std::time::Duration;

use sqlx::Row as _;

use crate::store::{Store, StoreError};

/// Where a key stands in the rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// Published ahead of the rotation that makes it sign.
    Next,
    /// Signing every token.
    Active,
    /// Published, never signing, until every token it signed has expired.
    Retiring,
    /// Neither published nor signing, ever again.
    Retired,
}

impl KeyState {
    /// Returns the state as the store writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Next => "next",
            Self::Active => "active",
            Self::Retiring => "retiring",
            Self::Retired => "retired",
        }
    }

    /// Returns the state the store wrote as `text`.
    fn parse(text: &str) -> Option<Self> {
        match text {
            "next" => Some(Self::Next),
            "active" => Some(Self::Active),
            "retiring" => Some(Self::Retiring),
            "retired" => Some(Self::Retired),
            _ => None,
        }
    }
}

/// One key's row: its state and when it reached each one, in seconds
/// since the Unix epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRow {
    /// The key's `kid`.
    pub kid: String,
    /// Where it stands.
    pub state: KeyState,
    /// When it was first published.
    pub published_at: i64,
    /// When it began to sign.
    pub active_at: Option<i64>,
    /// When it stopped signing.
    pub retiring_at: Option<i64>,
    /// When it stopped being published.
    pub retired_at: Option<i64>,
}

/// When the keys move from one state to the next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schedule {
    /// How long a key signs before the next one takes over.
    pub period: Duration,
    /// How long a key is published before it may sign.
    pub lead: Duration,
    /// How long a key stays published after it stops signing.
    pub retirement: Duration,
}

/// Returns `at` plus `span` in seconds, saturating at the clock's end.
fn after(at: i64, span: Duration) -> i64 {
    at.saturating_add(i64::try_from(span.as_secs()).unwrap_or(i64::MAX))
}

/// Returns the rows `rows` become at `now` under `schedule`, with `pool`
/// the `kid`s this replica can sign with, in the order they take over.
///
/// A retiring key past its retirement retires. With no active key, the
/// next key (or else the first key of `pool` the store has never seen)
/// signs at once. The active key hands over to the next once its period
/// has passed, the next has been published for the lead, the next is in
/// `pool`, and no key is still retiring. With no next key, the first unseen
/// key of `pool` becomes it. Only the changed rows are returned.
#[must_use]
pub fn plan(rows: &[KeyRow], pool: &[&str], schedule: &Schedule, now: i64) -> Vec<KeyRow> {
    let mut plan = Plan {
        rows: rows
            .iter()
            .map(|row| (row.kid.clone(), row.clone()))
            .collect(),
        changed: BTreeMap::new(),
        pool,
        now,
    };
    let lapsed: Vec<KeyRow> = plan
        .rows
        .values()
        .filter(|row| row.state == KeyState::Retiring)
        .filter(|row| {
            row.retiring_at
                .is_none_or(|at| after(at, schedule.retirement) <= now)
        })
        .cloned()
        .collect();
    for row in lapsed {
        plan.set(KeyRow {
            state: KeyState::Retired,
            retired_at: Some(now),
            ..row
        });
    }
    if plan.find(KeyState::Active).is_none()
        && let Some(row) = plan.find(KeyState::Next).or_else(|| plan.unseen())
    {
        plan.set(KeyRow {
            state: KeyState::Active,
            active_at: Some(now),
            ..row
        });
    }
    let handover = (
        plan.find(KeyState::Active),
        plan.find(KeyState::Next),
        plan.find(KeyState::Retiring),
    );
    if let (Some(active), Some(next), None) = handover {
        let due = active
            .active_at
            .is_none_or(|at| after(at, schedule.period) <= now);
        let announced = after(next.published_at, schedule.lead) <= now;
        if due && announced && pool.contains(&next.kid.as_str()) {
            plan.set(KeyRow {
                state: KeyState::Retiring,
                retiring_at: Some(now),
                ..active
            });
            plan.set(KeyRow {
                state: KeyState::Active,
                active_at: Some(now),
                ..next
            });
        }
    }
    if plan.find(KeyState::Next).is_none()
        && let Some(row) = plan.unseen()
    {
        plan.set(row);
    }
    plan.changed.into_values().collect()
}

/// The rows as [`plan`] moves them, and the ones it changed.
struct Plan<'a> {
    /// Every row by `kid`.
    rows: BTreeMap<String, KeyRow>,
    /// The rows changed, by `kid`.
    changed: BTreeMap<String, KeyRow>,
    /// The `kid`s this replica can sign with, in order.
    pool: &'a [&'a str],
    /// The moment of the plan.
    now: i64,
}

impl Plan<'_> {
    /// Returns the key in `state`.
    fn find(&self, state: KeyState) -> Option<KeyRow> {
        self.rows.values().find(|row| row.state == state).cloned()
    }

    /// Returns the first key of the pool the store has never seen, as a
    /// next key published now.
    fn unseen(&self) -> Option<KeyRow> {
        self.pool
            .iter()
            .find(|kid| !self.rows.contains_key(**kid))
            .map(|kid| KeyRow {
                kid: (*kid).to_owned(),
                state: KeyState::Next,
                published_at: self.now,
                active_at: None,
                retiring_at: None,
                retired_at: None,
            })
    }

    /// Records `row`.
    fn set(&mut self, row: KeyRow) {
        self.rows.insert(row.kid.clone(), row.clone());
        self.changed.insert(row.kid.clone(), row);
    }
}

impl Store {
    /// Moves the signing keys on as [`plan`] says at `now` and returns
    /// every key that is not retired. One replica moves them at a time.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails, and
    /// [`StoreError::CorruptKey`] for a row the server never writes.
    pub async fn rotate_keys(
        &self,
        pool: &[&str],
        schedule: &Schedule,
        now: i64,
    ) -> Result<Vec<KeyRow>, StoreError> {
        let mut tx = self.pool.begin().await?;
        // NOTE: no specification governs this: our own design; the lock is the
        // table's own, so replicas move the keys one after another.
        sqlx::query("LOCK TABLE signing_key IN EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await?;
        let rows = read_keys(&mut tx).await?;
        let changed = plan(&rows, pool, schedule, now);
        // NOTE: no specification governs this: our own design; the rows leave the
        // states they hold first, so the one-active and one-next indexes hold.
        let mut ordered = changed.clone();
        ordered.sort_by_key(|row| match row.state {
            KeyState::Retiring | KeyState::Retired => 0,
            KeyState::Active => 1,
            KeyState::Next => 2,
        });
        for row in &ordered {
            sqlx::query(
                "INSERT INTO signing_key (kid, state, published_at, active_at, retiring_at, retired_at) \
                 VALUES ($1, $2, to_timestamp($3), to_timestamp($4), to_timestamp($5), to_timestamp($6)) \
                 ON CONFLICT (kid) DO UPDATE SET state = EXCLUDED.state, \
                 active_at = EXCLUDED.active_at, retiring_at = EXCLUDED.retiring_at, \
                 retired_at = EXCLUDED.retired_at",
            )
            .bind(&row.kid)
            .bind(row.state.as_str())
            .bind(row.published_at)
            .bind(row.active_at)
            .bind(row.retiring_at)
            .bind(row.retired_at)
            .execute(&mut *tx)
            .await?;
        }
        let rows = read_keys(&mut tx).await?;
        tx.commit().await?;
        Ok(rows
            .into_iter()
            .filter(|row| row.state != KeyState::Retired)
            .collect())
    }
}

/// Reads every key's row.
async fn read_keys(tx: &mut sqlx::PgConnection) -> Result<Vec<KeyRow>, StoreError> {
    let rows = sqlx::query(
        "SELECT kid, state, extract(epoch FROM published_at)::bigint AS published_at, \
         extract(epoch FROM active_at)::bigint AS active_at, \
         extract(epoch FROM retiring_at)::bigint AS retiring_at, \
         extract(epoch FROM retired_at)::bigint AS retired_at \
         FROM signing_key ORDER BY published_at, kid",
    )
    .fetch_all(tx)
    .await?;
    rows.iter()
        .map(|row| {
            let kid: String = row.try_get("kid")?;
            let state: String = row.try_get("state")?;
            let state = KeyState::parse(&state)
                .ok_or_else(|| StoreError::CorruptKey { kid: kid.clone() })?;
            Ok(KeyRow {
                kid,
                state,
                published_at: row.try_get("published_at")?,
                active_at: row.try_get("active_at")?,
                retiring_at: row.try_get("retiring_at")?,
                retired_at: row.try_get("retired_at")?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: i64 = 3600;
    const DAY: i64 = 24 * HOUR;

    const SCHEDULE: Schedule = Schedule {
        period: Duration::from_hours(720),
        lead: Duration::from_mins(61),
        retirement: Duration::from_mins(66),
    };

    /// Applies [`plan`] to `rows` and returns every row after it.
    fn step(rows: &[KeyRow], pool: &[&str], now: i64) -> Vec<KeyRow> {
        let mut by_kid: BTreeMap<String, KeyRow> = rows
            .iter()
            .map(|row| (row.kid.clone(), row.clone()))
            .collect();
        for row in plan(rows, pool, &SCHEDULE, now) {
            by_kid.insert(row.kid.clone(), row);
        }
        by_kid.into_values().collect()
    }

    fn state(rows: &[KeyRow], kid: &str) -> Option<KeyState> {
        rows.iter().find(|row| row.kid == kid).map(|row| row.state)
    }

    #[test]
    fn the_first_key_signs_at_once_and_the_second_is_published_next() {
        let rows = step(&[], &["a", "b", "c"], 0);
        assert_eq!(Some(KeyState::Active), state(&rows, "a"));
        assert_eq!(Some(KeyState::Next), state(&rows, "b"));
        assert_eq!(None, state(&rows, "c"));
    }

    #[test]
    fn the_next_key_takes_over_after_the_period_and_the_old_one_retires_after_its_tokens() {
        let rows = step(&[], &["a", "b", "c"], 0);
        let early = step(&rows, &["a", "b", "c"], 30 * DAY - 1);
        assert_eq!(rows, early, "nothing moves before the period");
        let rotated = step(&rows, &["a", "b", "c"], 30 * DAY);
        assert_eq!(Some(KeyState::Retiring), state(&rotated, "a"));
        assert_eq!(Some(KeyState::Active), state(&rotated, "b"));
        assert_eq!(Some(KeyState::Next), state(&rotated, "c"));
        let held = step(&rotated, &["a", "b", "c"], 30 * DAY + 3959);
        assert_eq!(
            rotated, held,
            "the old key stays published for its retirement"
        );
        let retired = step(&rotated, &["a", "b", "c"], 30 * DAY + 3960);
        assert_eq!(Some(KeyState::Retired), state(&retired, "a"));
    }

    #[test]
    fn a_next_key_added_late_waits_for_its_lead() {
        let rows = step(&[], &["a"], 0);
        assert_eq!(None, state(&rows, "b"));
        let added = step(&rows, &["a", "b"], 40 * DAY);
        assert_eq!(Some(KeyState::Next), state(&added, "b"));
        assert_eq!(
            Some(KeyState::Active),
            state(&added, "a"),
            "the key stays past its period"
        );
        let waiting = step(&added, &["a", "b"], 40 * DAY + HOUR);
        assert_eq!(Some(KeyState::Active), state(&waiting, "a"));
        let rotated = step(&added, &["a", "b"], 40 * DAY + 3660);
        assert_eq!(Some(KeyState::Active), state(&rotated, "b"));
    }

    #[test]
    fn a_next_key_this_replica_lacks_never_takes_over_here() {
        let rows = step(&[], &["a", "b"], 0);
        let rows = step(&rows, &["a"], 30 * DAY);
        assert_eq!(Some(KeyState::Active), state(&rows, "a"));
        assert_eq!(Some(KeyState::Next), state(&rows, "b"));
    }

    #[test]
    fn a_retired_key_never_comes_back() {
        let rows = step(&[], &["a", "b"], 0);
        let rows = step(&rows, &["a", "b"], 30 * DAY);
        let rows = step(&rows, &["a", "b"], 31 * DAY);
        assert_eq!(Some(KeyState::Retired), state(&rows, "a"));
        let rows = step(&rows, &["a", "b"], 90 * DAY);
        assert_eq!(Some(KeyState::Active), state(&rows, "b"));
        assert_eq!(Some(KeyState::Retired), state(&rows, "a"));
        assert!(rows.iter().all(|row| row.state != KeyState::Next));
    }

    #[test]
    fn a_rotation_waits_while_a_key_is_still_retiring() {
        let rows = vec![
            KeyRow {
                kid: String::from("a"),
                state: KeyState::Retiring,
                published_at: 0,
                active_at: Some(0),
                retiring_at: Some(100 * DAY),
                retired_at: None,
            },
            KeyRow {
                kid: String::from("b"),
                state: KeyState::Active,
                published_at: 0,
                active_at: Some(0),
                retiring_at: None,
                retired_at: None,
            },
            KeyRow {
                kid: String::from("c"),
                state: KeyState::Next,
                published_at: 0,
                active_at: None,
                retiring_at: None,
                retired_at: None,
            },
        ];
        assert_eq!(
            Vec::<KeyRow>::new(),
            plan(&rows, &["a", "b", "c"], &SCHEDULE, 100 * DAY + 1)
        );
    }
}
