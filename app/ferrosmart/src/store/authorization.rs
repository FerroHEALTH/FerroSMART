// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The authorization requests between the endpoint and the code, and the
//! codes they issue (`docs/architecture.md` §13.9).

use ferrohealth_smart::assurance::AssuranceLevel;
use sqlx::Row as _;
use sqlx::types::Json;

use crate::launch::context::Context;

use crate::store::{
    Asking, Code, Login, Pending, PersonClaims, Prompt, Purpose, Store, StoreError, Transaction,
};

/// The columns of a pending authorization, as [`read_pending`] reads them.
const PENDING: &str = "SELECT id, client_id, redirect_uri, scope, state, nonce, code_challenge, \
    audience, upstream_state, upstream_nonce, upstream_verifier, form_token, subject, fhir_user, \
    display_name, offered_scope, auth_time, extract(epoch FROM expires_at)::bigint AS expires, purpose, \
    upstream_session, launch_context, roles, prompt, max_age, ui_locales, reauthenticated, \
    upstream_provider, person_claims, purpose_of_use, asked_acr, acr FROM pending_authorization";

impl Store {
    /// Records the authorization request `pending`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn begin_authorization(&self, pending: &Pending) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO pending_authorization (id, client_id, redirect_uri, scope, state, nonce, \
             code_challenge, audience, upstream_state, upstream_nonce, upstream_verifier, form_token, \
             expires_at, purpose, launch_context, prompt, max_age, ui_locales, upstream_provider, asked_acr) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, to_timestamp($13), $14, $15, \
             $16, $17, $18, $19, $20)",
        )
        .bind(&pending.id)
        .bind(&pending.client_id)
        .bind(&pending.redirect_uri)
        .bind(&pending.scope)
        .bind(&pending.state)
        .bind(&pending.nonce)
        .bind(&pending.code_challenge)
        .bind(&pending.audience)
        .bind(&pending.upstream_state)
        .bind(&pending.upstream_nonce)
        .bind(&pending.upstream_verifier)
        .bind(&pending.form_token)
        .bind(pending.expires_at)
        .bind(pending.purpose.as_str())
        .bind(pending.launch_context.as_ref().map(Json))
        .bind(pending.asking.prompt.values())
        .bind(pending.asking.max_age)
        .bind(&pending.asking.ui_locales)
        .bind(&pending.upstream_provider)
        .bind(pending.asking.acr.map(AssuranceLevel::as_str))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Begins the upstream login of the request `id` again under the
    /// upstream `state`, `nonce` and PKCE `verifier`, as the authentication
    /// was older than the request's `max_age`, and marks it so.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn reauthenticate(
        &self,
        id: &str,
        state: &str,
        nonce: &str,
        verifier: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE pending_authorization SET upstream_state = $2, upstream_nonce = $3, \
             upstream_verifier = $4, reauthenticated = true WHERE id = $1",
        )
        .bind(id)
        .bind(state)
        .bind(nonce)
        .bind(verifier)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Sends the request `id` to the provider `provider` the person chose,
    /// under the upstream `state`, `nonce` and PKCE `verifier`, while no
    /// provider is chosen yet.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn choose_upstream(
        &self,
        id: &str,
        provider: &str,
        sign_in: [&str; 3],
    ) -> Result<bool, StoreError> {
        let [state, nonce, verifier] = sign_in;
        let chosen = sqlx::query(
            "UPDATE pending_authorization SET upstream_provider = $2, upstream_state = $3, \
             upstream_nonce = $4, upstream_verifier = $5 \
             WHERE id = $1 AND upstream_provider IS NULL AND expires_at > now()",
        )
        .bind(id)
        .bind(provider)
        .bind(state)
        .bind(nonce)
        .bind(verifier)
        .execute(&self.pool)
        .await?;
        Ok(chosen.rows_affected() == 1)
    }

    /// Returns the live authorization request `id`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails.
    pub async fn pending(&self, id: &str) -> Result<Option<Pending>, StoreError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "{PENDING} WHERE id = $1 AND expires_at > now()"
        )))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| read_pending(&row)).transpose()
    }

    /// Returns the live authorization request whose upstream login carried
    /// `upstream_state`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails.
    pub async fn pending_by_upstream(
        &self,
        upstream_state: &str,
    ) -> Result<Option<Pending>, StoreError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "{PENDING} WHERE upstream_state = $1 AND expires_at > now()"
        )))
        .bind(upstream_state)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| read_pending(&row)).transpose()
    }

    /// Puts `context` in the launch context of the pending request `id`,
    /// as the patient picker chose it.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn set_launch_context(&self, id: &str, context: &Context) -> Result<(), StoreError> {
        sqlx::query("UPDATE pending_authorization SET launch_context = $2 WHERE id = $1")
            .bind(id)
            .bind(Json(context))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Keeps `code` as the purpose of use the picker declares for the
    /// pending request `id`, and returns whether it is the request's one: a
    /// request that kept another code is left as it is.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn keep_purpose_of_use(&self, id: &str, code: &str) -> Result<bool, StoreError> {
        let done = sqlx::query(
            "UPDATE pending_authorization SET purpose_of_use = $2 WHERE id = $1 \
             AND (purpose_of_use IS NULL OR purpose_of_use = $2)",
        )
        .bind(id)
        .bind(code)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Puts `context` in the launch context of the pending request `id` and
    /// narrows what the consent page offers to `offered`, as the picker
    /// chose a patient and no encounter.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn set_launch_context_offering(
        &self,
        id: &str,
        context: &Context,
        offered: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE pending_authorization SET launch_context = $2, offered_scope = $3 WHERE id = $1",
        )
        .bind(id)
        .bind(Json(context))
        .bind(offered)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Records who logged in for the request `id` and what the consent
    /// page offers them.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn logged_in(&self, id: &str, login: &Login) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE pending_authorization SET subject = $2, fhir_user = $3, display_name = $4, \
             offered_scope = $5, auth_time = $6, upstream_session = $7, roles = $8, person_claims = $9, \
             acr = $10 WHERE id = $1",
        )
        .bind(id)
        .bind(&login.subject)
        .bind(&login.fhir_user)
        .bind(&login.display_name)
        .bind(&login.offered_scope)
        .bind(login.auth_time)
        .bind(&login.upstream_session)
        .bind(&login.roles)
        .bind(Json(&login.person_claims))
        .bind(login.acr.map(AssuranceLevel::as_str))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Ends the request `id`, whatever its outcome, and returns it when it
    /// was still live, so it is decided once.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn finish(&self, id: &str) -> Result<Option<Pending>, StoreError> {
        let row = sqlx::query(
            "DELETE FROM pending_authorization WHERE id = $1 AND expires_at > now() \
             RETURNING id, client_id, redirect_uri, scope, state, nonce, code_challenge, audience, \
             upstream_state, upstream_nonce, upstream_verifier, form_token, subject, fhir_user, \
             display_name, offered_scope, auth_time, extract(epoch FROM expires_at)::bigint AS expires, purpose, \
             upstream_session, launch_context, roles, prompt, max_age, ui_locales, reauthenticated, \
             upstream_provider, person_claims, purpose_of_use, asked_acr, acr",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| read_pending(&row)).transpose()
    }

    /// Returns the code whose SHA-256 is `hash`, with whether it was
    /// redeemed before, while it lives.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails.
    pub async fn code(&self, hash: &str) -> Result<Option<(Code, bool)>, StoreError> {
        let row = sqlx::query(
            "SELECT client_id, redirect_uri, code_challenge, audience, subject, fhir_user, scope, \
             nonce, auth_time, extract(epoch FROM expires_at)::bigint AS expires, upstream_session, \
             redeemed_at IS NOT NULL AS redeemed, launch_context, roles, \
             basis, person_claims, acr FROM authorization_code \
             WHERE code_hash = $1 AND expires_at > now()",
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| -> Result<(Code, bool), StoreError> {
            Ok((
                Code {
                    client_id: row.try_get("client_id")?,
                    redirect_uri: row.try_get("redirect_uri")?,
                    code_challenge: row.try_get("code_challenge")?,
                    audience: row.try_get("audience")?,
                    subject: row.try_get("subject")?,
                    fhir_user: row.try_get("fhir_user")?,
                    scope: row.try_get("scope")?,
                    nonce: row.try_get("nonce")?,
                    auth_time: row.try_get("auth_time")?,
                    expires_at: row.try_get("expires")?,
                    upstream_session: row.try_get("upstream_session")?,
                    launch_context: launch_context(&row)?,
                    basis: row.try_get("basis")?,
                    roles: row.try_get("roles")?,
                    person_claims: person_claims(&row)?,
                    acr: level(&row, "acr")?,
                },
                row.try_get("redeemed")?,
            ))
        })
        .transpose()
    }

    /// Marks the code whose SHA-256 is `hash` redeemed, and returns whether
    /// this call redeemed it: `false` when another request did first.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn redeem(&self, hash: &str) -> Result<bool, StoreError> {
        let done = sqlx::query(
            "UPDATE authorization_code SET redeemed_at = now() \
             WHERE code_hash = $1 AND redeemed_at IS NULL",
        )
        .bind(hash)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }
}

impl Transaction {
    /// Records the authorization code `code`, by the SHA-256 `hash` of its
    /// value.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn issue_code(&mut self, hash: &str, code: &Code) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO authorization_code (code_hash, client_id, redirect_uri, code_challenge, \
             audience, subject, fhir_user, scope, nonce, auth_time, expires_at, upstream_session, \
             launch_context, roles, basis, person_claims, acr) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, to_timestamp($11), $12, $13, \
             $14, $15, $16, $17)",
        )
        .bind(hash)
        .bind(&code.client_id)
        .bind(&code.redirect_uri)
        .bind(&code.code_challenge)
        .bind(&code.audience)
        .bind(&code.subject)
        .bind(&code.fhir_user)
        .bind(&code.scope)
        .bind(&code.nonce)
        .bind(code.auth_time)
        .bind(code.expires_at)
        .bind(&code.upstream_session)
        .bind(code.launch_context.as_ref().map(Json))
        .bind(&code.roles)
        .bind(&code.basis)
        .bind(Json(&code.person_claims))
        .bind(code.acr.map(AssuranceLevel::as_str))
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }
    /// Revokes every access token issued for the code whose SHA-256 is
    /// `hash` ("SHOULD revoke (when possible) all access tokens and refresh
    /// tokens previously issued based on that authorization code", OAuth 2.1
    /// draft §4.1.3).
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn revoke_code(&mut self, hash: &str) -> Result<u64, StoreError> {
        let done = sqlx::query(
            "UPDATE access_token SET revoked_at = now() WHERE code_hash = $1 AND revoked_at IS NULL",
        )
        .bind(hash)
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected())
    }
}

/// Reads a pending authorization row.
fn read_pending(row: &sqlx::postgres::PgRow) -> Result<Pending, StoreError> {
    let id: String = row.try_get("id")?;
    let purpose = match row.try_get::<String, _>("purpose")?.as_str() {
        "manage" => Purpose::Manage,
        "authorize" => Purpose::Authorize,
        _ => return Err(StoreError::Corrupt { client_id: id }),
    };
    Ok(Pending {
        id,
        client_id: row.try_get("client_id")?,
        redirect_uri: row.try_get("redirect_uri")?,
        scope: row.try_get("scope")?,
        state: row.try_get("state")?,
        nonce: row.try_get("nonce")?,
        code_challenge: row.try_get("code_challenge")?,
        audience: row.try_get("audience")?,
        upstream_state: row.try_get("upstream_state")?,
        upstream_nonce: row.try_get("upstream_nonce")?,
        upstream_verifier: row.try_get("upstream_verifier")?,
        upstream_provider: row.try_get("upstream_provider")?,
        form_token: row.try_get("form_token")?,
        subject: row.try_get("subject")?,
        fhir_user: row.try_get("fhir_user")?,
        display_name: row.try_get("display_name")?,
        offered_scope: row.try_get("offered_scope")?,
        auth_time: row.try_get("auth_time")?,
        expires_at: row.try_get("expires")?,
        purpose,
        upstream_session: row.try_get("upstream_session")?,
        launch_context: launch_context(row)?,
        roles: row.try_get("roles")?,
        person_claims: person_claims(row)?,
        purpose_of_use: row.try_get("purpose_of_use")?,
        acr: level(row, "acr")?,
        asking: Asking {
            prompt: Prompt::of(&row.try_get::<String, _>("prompt")?),
            max_age: row.try_get("max_age")?,
            ui_locales: row.try_get("ui_locales")?,
            reauthenticated: row.try_get("reauthenticated")?,
            acr: level(row, "asked_acr")?,
        },
    })
}

/// Reads the eIDAS level in `column` of `row`.
fn level(row: &sqlx::postgres::PgRow, column: &str) -> Result<Option<AssuranceLevel>, StoreError> {
    crate::store::read_level(row, column, &|| StoreError::Corrupt {
        client_id: String::new(),
    })
}

/// Reads the `person_claims` column of `row`, empty when null.
fn person_claims(row: &sqlx::postgres::PgRow) -> Result<PersonClaims, StoreError> {
    Ok(row
        .try_get::<Option<Json<PersonClaims>>, _>("person_claims")?
        .map(|claims| claims.0)
        .unwrap_or_default())
}

/// Reads the `launch_context` column of `row`.
fn launch_context(row: &sqlx::postgres::PgRow) -> Result<Option<Context>, StoreError> {
    Ok(row
        .try_get::<Option<Json<Context>>, _>("launch_context")?
        .map(|context| context.0))
}
