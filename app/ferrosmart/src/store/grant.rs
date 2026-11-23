// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The grants, their refresh tokens and the upstream sessions an
//! `online_access` grant lives in (`docs/architecture.md` §13.9).
//!
//! A grant is what a person gave a client; every token issued under it
//! names it, so revoking the grant revokes them all in one transaction
//! (RFC 7009 §2.1). A refresh token is stored as its SHA-256.

use ferrohealth_smart::assurance::AssuranceLevel;
use serde_json::Value;
use sqlx::Row as _;

use crate::store::{Store, StoreError, Transaction};

/// How long a grant's refresh tokens may outlive the person's presence
/// (SMART App Launch 2.2.0, Scopes for requesting a refresh token).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// `offline_access`: refresh tokens last without the person.
    Offline,
    /// `online_access`: refresh tokens last while the person's upstream
    /// login does (`docs/architecture.md` §13.6 item 7).
    Online,
}

impl Access {
    /// Returns the access as the store writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Online => "online",
        }
    }
}

/// A grant to record.
#[derive(Debug, Clone, Copy)]
pub struct NewGrant<'a> {
    /// Its id, drawn at random.
    pub id: &'a str,
    /// The client it was given to.
    pub client_id: &'a str,
    /// The person's FerroSMART `sub`.
    pub subject: &'a str,
    /// The person's `fhirUser`, when granted.
    pub fhir_user: Option<&'a str>,
    /// The resource server its tokens are for.
    pub audience: &'a str,
    /// The scope granted.
    pub scope: &'a str,
    /// The launch context parameters of the token response, as one JSON
    /// object.
    pub context: &'a Value,
    /// When the person logged in, in seconds since the epoch.
    pub auth_time: Option<i64>,
    /// The refresh access granted, if any.
    pub access: Option<Access>,
    /// The upstream session an `online_access` grant lives in.
    pub upstream_session: Option<&'a str>,
    /// What its consent rests on: `page`, `remembered`, `administrative` or
    /// `first-party`, which clearing a first-party mark revokes it by.
    pub basis: Option<&'a str>,
    /// The person's mapped roles, which every access token issued under
    /// the grant carries (RFC 9068 §2.2.3.1).
    pub roles: &'a [String],
    /// The eIDAS level the person's login reached.
    pub acr: Option<AssuranceLevel>,
    /// The `DPoP` key a public client's refresh tokens are bound to (RFC
    /// 9449 §5).
    pub dpop_jkt: Option<&'a str>,
}

/// What introspection reads of a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRecord {
    /// Its id.
    pub id: String,
    /// The client it was given to.
    pub client_id: String,
    /// The person's FerroSMART `sub`.
    pub subject: String,
    /// The person's `fhirUser`, when granted.
    pub fhir_user: Option<String>,
    /// The resource server its tokens are for.
    pub audience: String,
    /// The scope granted.
    pub scope: String,
    /// The launch context parameters, one JSON object.
    pub context: Value,
    /// The refresh access granted, if any.
    pub access: Option<Access>,
    /// The person's mapped roles.
    pub roles: Vec<String>,
    /// When the person logged in, in seconds since the epoch.
    pub auth_time: Option<i64>,
    /// The eIDAS level their login reached.
    pub acr: Option<AssuranceLevel>,
    /// The `DPoP` key its refresh tokens are bound to (RFC 9449 §5).
    pub dpop_jkt: Option<String>,
}

/// The outcome of redeeming a refresh token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rotation {
    /// The token was live: it is used now, and its successor recorded.
    Rotated(Box<GrantRecord>),
    /// The token was rotated within [`REPEAT_WINDOW`] by the same client
    /// and its successor is still live: the request is a retry or a race,
    /// answered with the same successor, derived again with `salt`.
    Repeated {
        /// The grant the successor is under.
        grant: Box<GrantRecord>,
        /// The salt the successor was derived with.
        salt: String,
    },
    /// The token was rotated before: its grant is revoked now, with every
    /// token under it (RFC 9700 §4.14.2).
    Reused {
        /// The grant revoked.
        grant_id: String,
    },
    /// The token was issued to another client.
    OtherClient,
    /// The token is unknown, lapsed or revoked, or its grant or session
    /// ended.
    Invalid,
}

/// How long a rotated refresh token repeated by its client gets the same
/// successor.
///
/// Within it a repeat is a retry or a race, not a replay
/// (`docs/architecture.md` §13.6 item 11; no specification governs this: our
/// own design).
pub const REPEAT_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);

/// A refresh token's successor as the store records it.
#[derive(Debug, Clone, Copy)]
pub struct Successor<'a> {
    /// The successor's SHA-256.
    pub hash: &'a str,
    /// The salt it was derived from the presented token with.
    pub salt: &'a str,
}

/// When a refresh token issued now lapses unused, by the access of its
/// grant, in seconds since the epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdleUntil {
    /// For an `offline_access` grant.
    pub offline: i64,
    /// For an `online_access` grant.
    pub online: i64,
}

/// A recorded access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRecord {
    /// The client it was issued to.
    pub client_id: String,
    /// Its `sub`.
    pub subject: String,
    /// Its `aud`.
    pub audience: String,
    /// Its `scope`.
    pub scope: String,
    /// Its `iat`, in seconds since the epoch.
    pub issued_at: i64,
    /// Its `exp`, in seconds since the epoch.
    pub expires_at: i64,
    /// Whether it is unexpired and neither it nor its grant is revoked.
    pub active: bool,
    /// The grant it was issued under; none for a client credentials token.
    pub grant: Option<GrantRecord>,
}

/// A recorded refresh token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshRecord {
    /// The grant it was issued under.
    pub grant: GrantRecord,
    /// When it lapses unused, in seconds since the epoch.
    pub expires_at: i64,
    /// Whether it can be redeemed now: unexpired, unused, neither it nor
    /// its grant revoked, and, for `online_access`, its session not ended.
    pub active: bool,
}

/// The grant columns a joined query reads, prefixed `g_`.
const GRANT_COLUMNS: &str = "g.id AS g_id, g.client_id AS g_client_id, g.subject AS g_subject, \
    g.fhir_user AS g_fhir_user, g.audience AS g_audience, g.scope AS g_scope, g.context AS g_context, \
    g.access AS g_access, g.roles AS g_roles, g.auth_time AS g_auth_time, g.acr AS g_acr, \
    g.dpop_jkt AS g_dpop_jkt";

impl Store {
    /// Records the grant `grant`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn create_grant(&self, grant: &NewGrant<'_>) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO authorization_grant (id, client_id, subject, fhir_user, audience, scope, \
             context, auth_time, access, upstream_session, roles, basis, acr, dpop_jkt) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(grant.id)
        .bind(grant.client_id)
        .bind(grant.subject)
        .bind(grant.fhir_user)
        .bind(grant.audience)
        .bind(grant.scope)
        .bind(grant.context)
        .bind(grant.auth_time)
        .bind(grant.access.map(Access::as_str))
        .bind(grant.upstream_session)
        .bind(grant.roles)
        .bind(grant.basis)
        .bind(grant.acr.map(AssuranceLevel::as_str))
        .bind(grant.dpop_jkt)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Records the refresh token whose SHA-256 is `hash` under the grant
    /// `grant_id`, lapsing unused at `expires_at` (seconds since the epoch).
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn issue_refresh(
        &self,
        hash: &str,
        grant_id: &str,
        expires_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO refresh_token (token_hash, grant_id, expires_at) \
             VALUES ($1, $2, to_timestamp($3))",
        )
        .bind(hash)
        .bind(grant_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Returns the access token `jti`, with its grant.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails and
    /// [`StoreError::Corrupt`] for a row the server never writes.
    pub async fn access_token(&self, jti: &str) -> Result<Option<AccessRecord>, StoreError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT t.client_id, t.subject, t.audience, t.scope, \
             extract(epoch FROM t.issued_at)::bigint AS issued, \
             extract(epoch FROM t.expires_at)::bigint AS expires, \
             (t.revoked_at IS NULL AND t.expires_at > now() AND g.revoked_at IS NULL) AS active, \
             {GRANT_COLUMNS} \
             FROM access_token t LEFT JOIN authorization_grant g ON g.id = t.grant_id \
             WHERE t.jti = $1"
        )))
        .bind(jti)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let grant = match row.try_get::<Option<String>, _>("g_id")? {
            Some(_) => Some(read_grant(&row)?),
            None => None,
        };
        Ok(Some(AccessRecord {
            client_id: row.try_get("client_id")?,
            subject: row.try_get("subject")?,
            audience: row.try_get("audience")?,
            scope: row.try_get("scope")?,
            issued_at: row.try_get("issued")?,
            expires_at: row.try_get("expires")?,
            active: row.try_get("active")?,
            grant,
        }))
    }

    /// Returns the refresh token whose SHA-256 is `hash`, with its grant.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails and
    /// [`StoreError::Corrupt`] for a row the server never writes.
    pub async fn refresh_token(&self, hash: &str) -> Result<Option<RefreshRecord>, StoreError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT extract(epoch FROM r.expires_at)::bigint AS expires, \
             ({LIVE_REFRESH}) AS active, {GRANT_COLUMNS} \
             FROM refresh_token r JOIN authorization_grant g ON g.id = r.grant_id \
             LEFT JOIN upstream_session s ON s.id = g.upstream_session \
             WHERE r.token_hash = $1"
        )))
        .bind(hash)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(RefreshRecord {
                grant: read_grant(&row)?,
                expires_at: row.try_get("expires")?,
                active: row.try_get("active")?,
            })
        })
        .transpose()
    }

    /// Records the upstream login `session` of the person `subject` at the
    /// provider `issuer`, with the provider's session id `sid` when its ID
    /// Token carried one.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn begin_session(
        &self,
        session: &str,
        issuer: &str,
        subject: &str,
        sid: Option<&str>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO upstream_session (id, issuer, subject, sid) VALUES ($1, $2, $3, $4)",
        )
        .bind(session)
        .bind(issuer)
        .bind(subject)
        .bind(sid)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

/// The condition under which the refresh token `r` of grant `g`, in the
/// session `s`, can be redeemed.
const LIVE_REFRESH: &str = "r.revoked_at IS NULL AND r.used_at IS NULL AND r.expires_at > now() \
    AND g.revoked_at IS NULL \
    AND (g.access = 'offline' OR (g.access = 'online' AND s.id IS NOT NULL AND s.ended_at IS NULL))";

/// The condition under which the used refresh token `r` of grant `g`, in
/// the session `s`, is answered as a repeat: used less than `$2` seconds
/// ago, and its successor neither used nor revoked nor lapsed, in a grant
/// still live.
const REPEATABLE: &str = "r.used_at > now() - make_interval(secs => $2) \
    AND EXISTS (SELECT 1 FROM refresh_token n WHERE n.predecessor = r.token_hash \
    AND n.revoked_at IS NULL AND n.used_at IS NULL AND n.expires_at > now()) \
    AND g.revoked_at IS NULL \
    AND (g.access = 'offline' OR (g.access = 'online' AND s.id IS NOT NULL AND s.ended_at IS NULL))";

/// Reads the `g_` columns of a joined row.
fn read_grant(row: &sqlx::postgres::PgRow) -> Result<GrantRecord, StoreError> {
    let id: String = row.try_get("g_id")?;
    let context: Value = row.try_get("g_context")?;
    if !context.is_object() {
        return Err(StoreError::Corrupt { client_id: id });
    }
    let access = match row.try_get::<Option<String>, _>("g_access")?.as_deref() {
        Some("offline") => Some(Access::Offline),
        Some("online") => Some(Access::Online),
        None => None,
        Some(_) => return Err(StoreError::Corrupt { client_id: id }),
    };
    Ok(GrantRecord {
        access,
        client_id: row.try_get("g_client_id")?,
        subject: row.try_get("g_subject")?,
        fhir_user: row.try_get("g_fhir_user")?,
        audience: row.try_get("g_audience")?,
        scope: row.try_get("g_scope")?,
        context,
        roles: row.try_get("g_roles")?,
        auth_time: row.try_get("g_auth_time")?,
        acr: crate::store::read_level(row, "g_acr", &|| StoreError::Corrupt {
            client_id: id.clone(),
        })?,
        dpop_jkt: row.try_get("g_dpop_jkt")?,
        id,
    })
}

/// Revokes the grant `grant_id` with every token under it inside `tx`, and
/// returns whether the grant was live.
pub(super) async fn revoke_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    grant_id: &str,
) -> Result<bool, StoreError> {
    let revoked = sqlx::query(
        "UPDATE authorization_grant SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(grant_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE refresh_token SET revoked_at = now() WHERE grant_id = $1 AND revoked_at IS NULL",
    )
    .bind(grant_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE access_token SET revoked_at = now() WHERE grant_id = $1 AND revoked_at IS NULL",
    )
    .bind(grant_id)
    .execute(&mut **tx)
    .await?;
    Ok(revoked.rows_affected() == 1)
}

impl Transaction {
    /// Ends the live upstream sessions of the provider `issuer` that a
    /// Logout Token names: the one whose `sid` is `sid`, or with no `sid`
    /// every session of the person `subject` there (OpenID Connect
    /// Back-Channel Logout 1.0 §2.4, §2.7). It revokes the `online_access`
    /// grants in them with every token under them, and returns the ids of
    /// the sessions that ended.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails; nothing is
    /// changed then.
    pub async fn log_out(
        &mut self,
        issuer: &str,
        subject: Option<&str>,
        sid: Option<&str>,
    ) -> Result<Vec<String>, StoreError> {
        let ended: Vec<String> = sqlx::query_scalar(
            "UPDATE upstream_session SET ended_at = now() WHERE issuer = $1 AND ended_at IS NULL \
             AND (($3::text IS NOT NULL AND sid = $3) OR ($3::text IS NULL AND subject = $2)) \
             RETURNING id",
        )
        .bind(issuer)
        .bind(subject)
        .bind(sid)
        .fetch_all(&mut *self.tx)
        .await?;
        let grants: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM authorization_grant WHERE access = 'online' AND revoked_at IS NULL \
             AND upstream_session = ANY($1)",
        )
        .bind(&ended)
        .fetch_all(&mut *self.tx)
        .await?;
        for grant in &grants {
            revoke_in(&mut self.tx, grant).await?;
        }
        Ok(ended)
    }

    /// Redeems the refresh token whose SHA-256 is `hash` for `client_id`,
    /// in one transaction that holds the token's row: a live token is
    /// marked used and its successor recorded under the same grant with the
    /// salt it was derived with, lapsing as `idle` says; a token used within
    /// [`REPEAT_WINDOW`] whose successor is still live is a repeat; any
    /// other token used before revokes its grant (RFC 9700 §4.14.2; OAuth
    /// 2.1 draft §4.3.1).
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails; nothing is
    /// changed then, and [`StoreError::Corrupt`] for a row the server never
    /// writes.
    pub async fn rotate(
        &mut self,
        hash: &str,
        client_id: &str,
        successor: Successor<'_>,
        idle: IdleUntil,
    ) -> Result<Rotation, StoreError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT r.used_at IS NOT NULL AS used, ({LIVE_REFRESH}) AS active, \
             {GRANT_COLUMNS} \
             FROM refresh_token r JOIN authorization_grant g ON g.id = r.grant_id \
             LEFT JOIN upstream_session s ON s.id = g.upstream_session \
             WHERE r.token_hash = $1 FOR UPDATE OF r"
        )))
        .bind(hash)
        .fetch_optional(&mut *self.tx)
        .await?;
        let Some(row) = row else {
            return Ok(Rotation::Invalid);
        };
        let grant = read_grant(&row)?;
        if grant.client_id != client_id {
            return Ok(Rotation::OtherClient);
        }
        if row.try_get::<bool, _>("used")? {
            if let Some(salt) = self.repeatable(hash).await? {
                return Ok(Rotation::Repeated {
                    grant: Box::new(grant),
                    salt,
                });
            }
            revoke_in(&mut self.tx, &grant.id).await?;
            return Ok(Rotation::Reused { grant_id: grant.id });
        }
        let expires_at = match grant.access {
            Some(Access::Offline) => idle.offline,
            Some(Access::Online) => idle.online,
            None => return Ok(Rotation::Invalid),
        };
        if !row.try_get::<bool, _>("active")? {
            return Ok(Rotation::Invalid);
        }
        sqlx::query(
            "UPDATE refresh_token SET used_at = now(), successor_salt = $2 WHERE token_hash = $1",
        )
        .bind(hash)
        .bind(successor.salt)
        .execute(&mut *self.tx)
        .await?;
        sqlx::query(
            "INSERT INTO refresh_token (token_hash, grant_id, predecessor, expires_at) \
             VALUES ($1, $2, $3, to_timestamp($4))",
        )
        .bind(successor.hash)
        .bind(&grant.id)
        .bind(hash)
        .bind(expires_at)
        .execute(&mut *self.tx)
        .await?;
        Ok(Rotation::Rotated(Box::new(grant)))
    }
    /// Returns the successor salt of the used refresh token whose SHA-256 is
    /// `hash` when [`REPEATABLE`] holds for it.
    ///
    /// It runs after [`Self::rotate`] holds the token's row, as a statement
    /// of its own: a statement that waited for the lock sees under READ
    /// COMMITTED only what was committed when it began, so the successor a
    /// racing rotation just committed is read by a new statement alone
    /// (PostgreSQL 18, 13.2.1 Read Committed Isolation Level).
    async fn repeatable(&mut self, hash: &str) -> Result<Option<String>, StoreError> {
        let salt = sqlx::query_scalar::<_, Option<String>>(sqlx::AssertSqlSafe(format!(
            "SELECT r.successor_salt \
             FROM refresh_token r JOIN authorization_grant g ON g.id = r.grant_id \
             LEFT JOIN upstream_session s ON s.id = g.upstream_session \
             WHERE r.token_hash = $1 AND ({REPEATABLE})"
        )))
        .bind(hash)
        .bind(REPEAT_WINDOW.as_secs_f64())
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(salt.flatten())
    }
    /// Revokes the grant `grant_id` with every refresh and access token
    /// issued under it, in one transaction, and returns whether the grant
    /// was live.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails; nothing is
    /// changed then.
    pub async fn revoke_grant(&mut self, grant_id: &str) -> Result<bool, StoreError> {
        let revoked = revoke_in(&mut self.tx, grant_id).await?;
        Ok(revoked)
    }
    /// Ends the upstream session `session`, and returns whether it was
    /// live; the `online_access` grants in it refresh no more.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn end_session(&mut self, session: &str) -> Result<bool, StoreError> {
        let ended = sqlx::query(
            "UPDATE upstream_session SET ended_at = now() WHERE id = $1 AND ended_at IS NULL",
        )
        .bind(session)
        .execute(&mut *self.tx)
        .await?;
        Ok(ended.rows_affected() == 1)
    }
    /// Revokes the access token `jti` alone, and returns whether it was
    /// unrevoked.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn revoke_access_token(&mut self, jti: &str) -> Result<bool, StoreError> {
        let revoked = sqlx::query(
            "UPDATE access_token SET revoked_at = now() WHERE jti = $1 AND revoked_at IS NULL",
        )
        .bind(jti)
        .execute(&mut *self.tx)
        .await?;
        Ok(revoked.rows_affected() == 1)
    }
}
