// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The PostgreSQL store, which holds every piece of FerroSMART's state so
//! any replica answers any request (`docs/architecture.md` §13.9).
//!
//! The migrations ship in the binary and run at start; `sqlx` takes a
//! PostgreSQL advisory lock around them, so replicas starting together
//! migrate once. No specification governs the storage: our own design.

pub mod admin;
pub mod audit;
pub mod authorization;
pub mod consent;
pub mod first_party;
pub mod grant;
pub mod launch;
pub mod logout;
pub mod pushed;
pub mod recent;
pub mod signing;
pub mod subjects;
pub mod wallet;

use std::collections::BTreeMap;
use std::time::Duration;

use ferrohealth_smart::assurance::AssuranceLevel;
use secrecy::ExposeSecret as _;
use serde_json::Value;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Postgres, Row as _};
use url::Url;

use crate::clients::{About, AuthMethod, Client, ClientKeys, GrantType, Registration, SecretHash};
use crate::launch::context::Context;

/// How long a request waits for a connection before the store answers that
/// it is unavailable. No specification governs the value: our own design.
pub const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// The oldest PostgreSQL the store runs on, as a `server_version_num`.
///
/// The setting is described in PostgreSQL 19 docs, "Preset Options". No
/// specification governs the minimum: our own design, the release every
/// product of the family pins.
pub const MINIMUM_SERVER_VERSION: i32 = 190_000;

/// Why the store failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database refused or failed a statement, or cannot be reached.
    #[error("the database failed")]
    Database(#[from] sqlx::Error),
    /// A migration failed.
    #[error("the database could not be migrated")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// The database runs a PostgreSQL older than the store supports.
    #[error(
        "the database runs PostgreSQL server_version_num {found}, and FerroSMART needs {required} or newer"
    )]
    UnsupportedServer {
        /// The `server_version_num` the database reported.
        found: i32,
        /// [`MINIMUM_SERVER_VERSION`].
        required: i32,
    },
    /// An audited write was to commit without its audit record.
    #[error("an audited write has no audit record")]
    Unrecorded,
    /// A signing key's row holds a state the server never writes.
    #[error("the signing key `{kid}` holds a state the server never writes")]
    CorruptKey {
        /// The key's `kid`.
        kid: String,
    },
    /// A stored row holds a value the server never writes.
    #[error("the stored row `{client_id}` holds a value the server never writes")]
    Corrupt {
        /// The client.
        client_id: String,
    },
}

/// The store: a pool of connections to one database.
#[derive(Debug, Clone)]
pub struct Store {
    /// The pool.
    pool: PgPool,
}

impl Store {
    /// Connects to the database `url` names with at most `max_connections`
    /// and refuses a server older than [`MINIMUM_SERVER_VERSION`].
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the database cannot be reached
    /// and [`StoreError::UnsupportedServer`] when it runs an older
    /// PostgreSQL.
    pub async fn connect(
        url: &secrecy::SecretString,
        max_connections: u32,
    ) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(ACQUIRE_TIMEOUT)
            .connect(url.expose_secret())
            .await?;
        let found: i32 = sqlx::query_scalar("SELECT current_setting('server_version_num')::int")
            .fetch_one(&pool)
            .await?;
        supported(found)?;
        Ok(Self { pool })
    }

    /// Returns a store over the database `url` names that connects on first
    /// use, for a server whose routes may never reach it.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when `url` does not parse.
    pub fn connect_lazy(
        url: &secrecy::SecretString,
        max_connections: u32,
    ) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(ACQUIRE_TIMEOUT)
            .connect_lazy(url.expose_secret())?;
        Ok(Self { pool })
    }

    /// Runs the migrations the binary carries.
    ///
    /// # Errors
    /// Returns [`StoreError::Migrate`] when a migration fails.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }

    /// Returns the client registered as `client_id`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails and
    /// [`StoreError::Corrupt`] for a row the server never writes.
    pub async fn client(&self, client_id: &str) -> Result<Option<Client>, StoreError> {
        self.client_by(ClientKey::ClientId, client_id).await
    }

    /// Returns the client whose normalized launch URL is `launch_uri`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails and
    /// [`StoreError::Corrupt`] for a row the server never writes.
    pub async fn client_launched_at(&self, launch_uri: &str) -> Result<Option<Client>, StoreError> {
        self.client_by(ClientKey::LaunchUri, launch_uri).await
    }

    /// Returns the client whose column `key` holds `value`.
    async fn client_by(&self, key: ClientKey, value: &str) -> Result<Option<Client>, StoreError> {
        let column = match key {
            ClientKey::ClientId => "client_id",
            ClientKey::LaunchUri => "launch_uri",
        };
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {CLIENT_COLUMNS} FROM client WHERE {column} = $1 AND disabled_at IS NULL"
        )))
        .bind(value)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| read_client(&row)).transpose()
    }

    /// Records the assertion `jti` of `issuer`, kept until `expires_at`
    /// (seconds since the epoch), and returns whether it was unseen: a
    /// `false` is a replay.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn first_use(
        &self,
        issuer: &str,
        jti: &str,
        expires_at: i64,
    ) -> Result<bool, StoreError> {
        insert_jti(&self.pool, issuer, jti, expires_at).await
    }

    /// Records the SAML assertion `assertion_id` of the identity provider
    /// `identity_provider`, kept until `expires_at` (seconds since the
    /// epoch), and returns whether it was unseen: a `false` is a replay
    /// (saml-profiles-2.0-os §4.1.4.5).
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn first_assertion(
        &self,
        identity_provider: &str,
        assertion_id: &str,
        expires_at: i64,
    ) -> Result<bool, StoreError> {
        let inserted = sqlx::query(
            "INSERT INTO seen_saml_assertion (identity_provider, assertion_id, expires_at) \
             VALUES ($1, $2, to_timestamp($3)) ON CONFLICT (identity_provider, assertion_id) DO NOTHING",
        )
        .bind(identity_provider)
        .bind(assertion_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(inserted.rows_affected() == 1)
    }

    /// Returns whether the access token `jti` was revoked.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the query fails.
    pub async fn revoked(&self, jti: &str) -> Result<bool, StoreError> {
        let row = sqlx::query(
            "SELECT revoked_at IS NOT NULL AS revoked FROM access_token WHERE jti = $1",
        )
        .bind(jti)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(row) => row.try_get("revoked")?,
            None => false,
        })
    }

    /// Records the access token `token` describes.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn record_token(&self, token: &IssuedToken<'_>) -> Result<(), StoreError> {
        insert_token(&self.pool, token).await
    }

    /// Deletes the assertion ids, the SAML assertion ids, the wallet answers,
    /// the access and refresh tokens, the launches and the pushed requests
    /// past their expiry, and the grants an hour old with no token left.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails.
    pub async fn sweep(&self) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM seen_jti WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM seen_saml_assertion WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM wallet_answer WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM access_token WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM refresh_token WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        // NOTE: no specification governs this: our own design, an hour's margin so
        // a grant recorded just before its first token is never swept between them.
        sqlx::query(
            "DELETE FROM authorization_grant g WHERE g.created_at < now() - interval '1 hour' \
             AND NOT EXISTS (SELECT 1 FROM refresh_token r WHERE r.grant_id = g.id) \
             AND NOT EXISTS (SELECT 1 FROM access_token t WHERE t.grant_id = g.id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("DELETE FROM pending_authorization WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM authorization_code WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM pending_logout WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM launch WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM pushed_request WHERE expires_at < now()")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Returns whether the database answers a statement, for readiness.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when it does not.
    pub async fn ping(&self) -> Result<(), StoreError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    /// Records the `digests` of the Brands Bundle, one for its contents and
    /// one per resource, and returns when each last changed, in milliseconds
    /// since the epoch: now where a digest differs from the one stored or is
    /// new, the stored instant otherwise, so every replica serving the same
    /// contents names the same instants. A resource `digests` no longer
    /// names is forgotten.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when a statement fails.
    pub async fn brands_changed(
        &self,
        digests: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, i64>, StoreError> {
        let resources: Vec<&str> = digests.keys().map(String::as_str).collect();
        let values: Vec<&str> = digests.values().map(String::as_str).collect();
        let mut tx = self.pool.begin().await?;
        // NOTE: no specification governs this: our own design, one lock so two
        // replicas starting together record one instant between them.
        sqlx::query("LOCK TABLE brand_bundle IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM brand_bundle WHERE resource <> ALL($1)")
            .bind(&resources)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO brand_bundle (resource, digest, changed_at) \
             SELECT resource, digest, now() \
             FROM unnest($1::text[], $2::text[]) AS given (resource, digest) \
             ON CONFLICT (resource) DO UPDATE SET digest = EXCLUDED.digest, \
             changed_at = EXCLUDED.changed_at WHERE brand_bundle.digest <> EXCLUDED.digest",
        )
        .bind(&resources)
        .bind(&values)
        .execute(&mut *tx)
        .await?;
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT resource, floor(extract(epoch FROM changed_at) * 1000)::bigint \
             FROM brand_bundle",
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows.into_iter().collect())
    }
}

/// The unique column a client is looked up by.
#[derive(Debug, Clone, Copy)]
enum ClientKey {
    /// `client_id`.
    ClientId,
    /// The normalized `launch_uri`.
    LaunchUri,
}

/// Who registered a client: an administrator, or the app itself (RFC 7591
/// §5 keeps its metadata self-asserted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisteredBy {
    /// An administrator, through the admin API or `ferrosmart client apply`.
    Admin,
    /// The app's own registration (RFC 7591).
    Itself,
}

impl RegisteredBy {
    /// Returns the value the store writes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Itself => "self",
        }
    }

    /// Returns who the store wrote as `text`.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        match text {
            "admin" => Some(Self::Admin),
            "self" => Some(Self::Itself),
            _ => None,
        }
    }

    /// Returns who registered `client`.
    #[must_use]
    pub const fn of(client: &Client) -> Self {
        if client.registered_itself() {
            Self::Itself
        } else {
            Self::Admin
        }
    }
}

/// Writes `client` over any row of its id.
pub(crate) async fn write_client(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    client: &Client,
) -> Result<(), StoreError> {
    let (jwks_uri, jwks) = match &client.keys {
        Some(ClientKeys::Uri(url)) => (Some(url.as_str().to_owned()), None),
        Some(ClientKeys::Set(set)) => (None, Some(set.clone())),
        None => (None, None),
    };
    let grants: Vec<&str> = client
        .grant_types
        .iter()
        .map(|grant| grant.as_str())
        .collect();
    sqlx::query(
        "INSERT INTO client (client_id, client_name, token_endpoint_auth_method, jwks_uri, jwks, redirect_uris, scope, grant_types, secret_hash, \
         launch_uri, first_party, client_uri, logo_uri, policy_uri, tos_uri, \
         post_logout_redirect_uris, upstreams, registered_by, resources, default_acr_values, \
         require_pushed_authorization_requests, dpop_bound_access_tokens, \
         tls_client_certificate_bound_access_tokens, id_token_signed_response_alg) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, \
         $22, $23, $24) \
         ON CONFLICT (client_id) DO UPDATE SET client_name = $2, token_endpoint_auth_method = $3, jwks_uri = $4, jwks = $5, \
         redirect_uris = $6, scope = $7, grant_types = $8, secret_hash = $9, launch_uri = $10, first_party = $11, \
         client_uri = $12, logo_uri = $13, policy_uri = $14, tos_uri = $15, post_logout_redirect_uris = $16, upstreams = $17, \
         registered_by = $18, resources = $19, default_acr_values = $20, \
         require_pushed_authorization_requests = $21, dpop_bound_access_tokens = $22, \
         tls_client_certificate_bound_access_tokens = $23, id_token_signed_response_alg = $24, \
         updated_at = now()",
    )
    .bind(&client.client_id)
    .bind(&client.name)
    .bind(client.auth_method.as_str())
    .bind(jwks_uri)
    .bind(jwks)
    .bind(&client.redirect_uris)
    .bind(&client.scopes)
    .bind(&grants)
    .bind(client.secret_hash.as_ref().map(SecretHash::phc))
    .bind(&client.launch_uri)
    .bind(client.first_party())
    .bind(client.about.home.as_ref().map(Url::as_str))
    .bind(client.about.logo.as_ref().map(Url::as_str))
    .bind(client.about.policy.as_ref().map(Url::as_str))
    .bind(client.about.terms.as_ref().map(Url::as_str))
    .bind(&client.post_logout_redirect_uris)
    .bind(&client.upstreams)
    .bind(RegisteredBy::of(client).as_str())
    .bind(&client.resources)
    .bind(&client.default_acr_values)
    .bind(client.require_pushed_authorization_requests)
    .bind(client.dpop_bound_access_tokens)
    .bind(client.tls_client_certificate_bound_access_tokens)
    .bind(client.id_token_signed_response_alg.name())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The columns [`read_client`] reads.
pub(crate) const CLIENT_COLUMNS: &str = "client_id, client_name, token_endpoint_auth_method, jwks_uri, jwks, secret_hash, redirect_uris, \
     post_logout_redirect_uris, upstreams, resources, scope, grant_types, launch_uri, first_party, client_uri, logo_uri, policy_uri, tos_uri, \
     default_acr_values, registered_by, require_pushed_authorization_requests, dpop_bound_access_tokens, \
     tls_client_certificate_bound_access_tokens, id_token_signed_response_alg";

/// Reads a `client` row.
pub(crate) fn read_client(row: &sqlx::postgres::PgRow) -> Result<Client, StoreError> {
    let client_id: String = row.try_get("client_id")?;
    let corrupt = || StoreError::Corrupt {
        client_id: client_id.clone(),
    };
    let auth_method = AuthMethod::parse(&row.try_get::<String, _>("token_endpoint_auth_method")?)
        .ok_or_else(corrupt)?;
    let secret_hash = row
        .try_get::<Option<String>, _>("secret_hash")?
        .map(SecretHash::from);
    let keys = match (
        row.try_get::<Option<String>, _>("jwks_uri")?,
        row.try_get::<Option<Value>, _>("jwks")?,
    ) {
        (Some(uri), None) => Some(ClientKeys::Uri(uri.parse().map_err(|_unparsed| corrupt())?)),
        (None, Some(set)) => Some(ClientKeys::Set(set)),
        (None, None) => None,
        (Some(_), Some(_)) => return Err(corrupt()),
    };
    let grant_types = row
        .try_get::<Vec<String>, _>("grant_types")?
        .iter()
        .map(|grant| match grant.as_str() {
            "authorization_code" => Ok(GrantType::AuthorizationCode),
            "client_credentials" => Ok(GrantType::ClientCredentials),
            "refresh_token" => Ok(GrantType::RefreshToken),
            crate::token::exchange::TOKEN_EXCHANGE => Ok(GrantType::TokenExchange),
            _ => Err(corrupt()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let registered_by =
        RegisteredBy::parse(&row.try_get::<String, _>("registered_by")?).ok_or_else(corrupt)?;
    let first_party: bool = row.try_get("first_party")?;
    // NOTE: RFC 7591 §5, an app's own registration is self-asserted, so a row of
    // one that holds the first-party mark is refused.
    let registration = match registered_by {
        RegisteredBy::Itself if first_party => return Err(corrupt()),
        RegisteredBy::Itself => Registration::Dynamic,
        RegisteredBy::Admin => Registration::Administered { first_party },
    };
    Ok(Client {
        name: row.try_get("client_name")?,
        auth_method,
        keys,
        secret_hash,
        redirect_uris: row.try_get("redirect_uris")?,
        post_logout_redirect_uris: row.try_get("post_logout_redirect_uris")?,
        upstreams: row.try_get("upstreams")?,
        default_acr_values: row.try_get("default_acr_values")?,
        resources: row.try_get("resources")?,
        scopes: row.try_get("scope")?,
        grant_types,
        launch_uri: row.try_get("launch_uri")?,
        registration,
        about: About {
            home: read_url(row, "client_uri", &corrupt)?,
            logo: read_url(row, "logo_uri", &corrupt)?,
            policy: read_url(row, "policy_uri", &corrupt)?,
            terms: read_url(row, "tos_uri", &corrupt)?,
        },
        require_pushed_authorization_requests: row
            .try_get("require_pushed_authorization_requests")?,
        dpop_bound_access_tokens: row.try_get("dpop_bound_access_tokens")?,
        tls_client_certificate_bound_access_tokens: row
            .try_get("tls_client_certificate_bound_access_tokens")?,
        id_token_signed_response_alg: match row
            .try_get::<String, _>("id_token_signed_response_alg")?
            .as_str()
        {
            "RS256" => ferrohealth_smart::jws::algorithm::Algorithm::Rs256,
            "PS256" => ferrohealth_smart::jws::algorithm::Algorithm::Ps256,
            "ES256" => ferrohealth_smart::jws::algorithm::Algorithm::Es256,
            "EdDSA" => ferrohealth_smart::jws::algorithm::Algorithm::EdDsa,
            "ML-DSA-65" => ferrohealth_smart::jws::algorithm::Algorithm::MlDsa65,
            _ => return Err(corrupt()),
        },
        client_id,
    })
}

/// Reads the URL column `column` of a `client` row, none when it is null.
fn read_url(
    row: &sqlx::postgres::PgRow,
    column: &str,
    corrupt: &dyn Fn() -> StoreError,
) -> Result<Option<Url>, StoreError> {
    row.try_get::<Option<String>, _>(column)?
        .map(|url| url.parse().map_err(|_unparsed| corrupt()))
        .transpose()
}

/// Reads the eIDAS level in `column` of `row`.
pub(crate) fn read_level(
    row: &sqlx::postgres::PgRow,
    column: &str,
    corrupt: &dyn Fn() -> StoreError,
) -> Result<Option<AssuranceLevel>, StoreError> {
    row.try_get::<Option<String>, _>(column)?
        .map(|level| crate::assurance::parse(&level).ok_or_else(corrupt))
        .transpose()
}

/// What the store records of an issued access token.
#[derive(Debug, Clone, Copy)]
pub struct IssuedToken<'a> {
    /// Its `jti`.
    pub jti: &'a str,
    /// The client it was issued to.
    pub client_id: &'a str,
    /// Its `sub`.
    pub subject: &'a str,
    /// Its `aud`.
    pub audience: &'a str,
    /// Its `scope`.
    pub scope: &'a str,
    /// Its `iat`, in seconds since the epoch.
    pub issued_at: i64,
    /// Its `exp`, in seconds since the epoch.
    pub expires_at: i64,
    /// The grant it was issued under; none for a client credentials token.
    pub grant_id: Option<&'a str>,
    /// The SHA-256 of the authorization code it was issued for, if any.
    pub code_hash: Option<&'a str>,
}

/// An authorization request between the authorization endpoint and the
/// code.
#[derive(Clone, PartialEq, Eq)]
pub struct Pending {
    /// Its id, the browser's cookie.
    pub id: String,
    /// The client; none on a management visit.
    pub client_id: Option<String>,
    /// The client's redirect URI.
    pub redirect_uri: String,
    /// The scope the client requested.
    pub scope: String,
    /// The client's `state`.
    pub state: String,
    /// The client's OpenID Connect `nonce`.
    pub nonce: Option<String>,
    /// The client's PKCE challenge.
    pub code_challenge: String,
    /// The JWK thumbprint of the `DPoP` key the code is bound to (RFC 9449
    /// §10).
    pub dpop_jkt: Option<String>,
    /// The resource server the token is for.
    pub audience: String,
    /// The upstream login's `state`.
    pub upstream_state: String,
    /// The upstream login's `nonce`.
    pub upstream_nonce: String,
    /// The upstream login's PKCE verifier, a secret.
    pub upstream_verifier: String,
    /// The `[[ferrosmart.upstream]]` provider the person logs in at, once
    /// it is chosen.
    pub upstream_provider: Option<String>,
    /// The token the consent form carries, against cross-site posts.
    pub form_token: String,
    /// The person's FerroSMART `sub`, once they logged in.
    pub subject: Option<String>,
    /// Their `fhirUser`, when the provider carries one.
    pub fhir_user: Option<String>,
    /// The name the consent page greets them by.
    pub display_name: Option<String>,
    /// The scopes the consent page offers.
    pub offered_scope: Option<String>,
    /// When they logged in, in seconds since the epoch.
    pub auth_time: Option<i64>,
    /// When the request lapses, in seconds since the epoch.
    pub expires_at: i64,
    /// What the login is for.
    pub purpose: Purpose,
    /// The upstream session the person logged in under.
    pub upstream_session: Option<String>,
    /// The launch context of an EHR launch.
    pub launch_context: Option<Context>,
    /// The roles of the person, mapped from the upstream identity provider
    /// (`docs/architecture.md` §13.6 item 5), which the access token's
    /// `roles` claim carries (RFC 9068 §2.2.3.1).
    pub roles: Vec<String>,
    /// The upstream ID Token's standard claims, once they logged in.
    pub person_claims: PersonClaims,
    /// The code of the purpose of use a professional chose on the patient
    /// picker of an openEHR base, once a lookup declared it.
    pub purpose_of_use: Option<String>,
    /// The eIDAS level the person's login reached, once they logged in.
    pub acr: Option<AssuranceLevel>,
    /// What the app asked of the login under OpenID Connect Core 1.0
    /// §3.1.2.1.
    pub asking: Asking,
}

/// What an app's authorization request asks of the person's login and the
/// pages under OpenID Connect Core 1.0 §3.1.2.1, beside SMART App Launch
/// 2.2.0's own parameters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Asking {
    /// The `prompt` values the request carries.
    pub prompt: Prompt,
    /// `max_age`: the most seconds since the person last authenticated.
    pub max_age: Option<i64>,
    /// `ui_locales`: the languages the pages are wanted in, most preferred
    /// first, space separated.
    pub ui_locales: Option<String>,
    /// Whether the upstream login was begun again because its
    /// authentication was older than `max_age`.
    pub reauthenticated: bool,
    /// The eIDAS level the login must reach for the request: the lowest the
    /// app's `acr_values` names, raised to the client's minimum.
    pub acr: Option<AssuranceLevel>,
}

/// The `prompt` values of an authorization request FerroSMART acts on
/// (OpenID Connect Core 1.0 §3.1.2.1); `none` never reaches the login.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Prompt {
    /// `login`, or `max_age=0`: the upstream login authenticates the person
    /// again.
    pub login: bool,
    /// `consent`: the consent page is shown even when a remembered consent
    /// or the registration would answer.
    pub consent: bool,
    /// `select_account`: the upstream login offers its accounts.
    pub select_account: bool,
}

impl Prompt {
    /// Returns the values, space separated, as the store writes them.
    #[must_use]
    pub fn values(self) -> String {
        [
            (self.login, "login"),
            (self.consent, "consent"),
            (self.select_account, "select_account"),
        ]
        .iter()
        .filter(|(asked, _)| *asked)
        .map(|(_, value)| *value)
        .collect::<Vec<_>>()
        .join(" ")
    }

    /// Returns the values of the space-separated `prompt`; a value it does
    /// not act on is left out.
    #[must_use]
    pub fn of(prompt: &str) -> Self {
        let values: Vec<&str> = prompt.split(' ').collect();
        Self {
            login: values.contains(&"login"),
            consent: values.contains(&"consent"),
            select_account: values.contains(&"select_account"),
        }
    }
}

/// What a login is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// An app's authorization request.
    Authorize,
    /// The person's own visit to the management page.
    Manage,
}

impl Purpose {
    /// Returns the purpose as the store writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authorize => "authorize",
            Self::Manage => "manage",
        }
    }
}

impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// The standard claims of the upstream ID Token that FerroSMART's ID Token
/// passes on when `profile` or `email` is granted (OpenID Connect Core 1.0
/// §5.1, §5.4); never rendered by `Debug`.
#[derive(Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersonClaims {
    /// `name`, under `profile`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `preferred_username`, under `profile`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    /// `given_name`, under `profile`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// `family_name`, under `profile`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    /// `birthdate`, under `profile`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birthdate: Option<String>,
    /// `place_of_birth`, an object of `country`, `region` and `locality`,
    /// under `profile`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub place_of_birth: Option<Value>,
    /// `nationalities`, ISO 3166-1 alpha-2 codes, under `profile`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nationalities: Option<Value>,
    /// `email`, under `email`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// `email_verified`, under `email`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

impl PersonClaims {
    /// Reads the claims from the upstream login `identity`, each kept only
    /// in the type OpenID Connect Core 1.0 §5.1 gives it.
    #[must_use]
    pub fn from_identity(identity: &crate::upstream::Identity) -> Self {
        let text = |value: Option<&str>| {
            value
                .filter(|text| !text.trim().is_empty())
                .map(str::to_owned)
        };
        let claim = |name: &str| text(identity.claims.get(name).and_then(Value::as_str));
        let shaped = |name: &str| {
            identity
                .claims
                .get(name)
                .filter(|value| crate::wallet::pid::shaped(name, value))
                .cloned()
        };
        Self {
            name: text(identity.name.as_deref()),
            preferred_username: text(identity.preferred_username.as_deref()),
            given_name: claim("given_name"),
            family_name: claim("family_name"),
            birthdate: claim("birthdate"),
            place_of_birth: shaped("place_of_birth"),
            nationalities: shaped("nationalities"),
            email: text(identity.claims.get("email").and_then(Value::as_str)),
            email_verified: identity
                .claims
                .get("email_verified")
                .and_then(Value::as_bool),
        }
    }

    /// Returns the claims the granted `scope` passes on: the person's names,
    /// birth and nationalities under `profile`, `email` and
    /// `email_verified` under `email`.
    #[must_use]
    pub fn granted(&self, scope: &str) -> Self {
        let holds = |wanted: &str| scope.split(' ').any(|held| held == wanted);
        let (profile, email) = (holds("profile"), holds("email"));
        Self {
            name: self.name.clone().filter(|_| profile),
            preferred_username: self.preferred_username.clone().filter(|_| profile),
            given_name: self.given_name.clone().filter(|_| profile),
            family_name: self.family_name.clone().filter(|_| profile),
            birthdate: self.birthdate.clone().filter(|_| profile),
            place_of_birth: self.place_of_birth.clone().filter(|_| profile),
            nationalities: self.nationalities.clone().filter(|_| profile),
            email: self.email.clone().filter(|_| email),
            email_verified: self.email_verified.filter(|_| email),
        }
    }
}

impl std::fmt::Debug for PersonClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PersonClaims(..)")
    }
}

/// Who logged in for a pending request, and what they are offered.
#[derive(Debug, Clone)]
pub struct Login {
    /// The FerroSMART `sub`.
    pub subject: String,
    /// The `fhirUser`, if any.
    pub fhir_user: Option<String>,
    /// The name to greet them by, if any.
    pub display_name: Option<String>,
    /// The scopes the consent page offers.
    pub offered_scope: String,
    /// When they logged in.
    pub auth_time: i64,
    /// The upstream session they logged in under.
    pub upstream_session: Option<String>,
    /// Their roles a `[[ferrosmart.role]]` names, sorted.
    pub roles: Vec<String>,
    /// The upstream ID Token's standard claims.
    pub person_claims: PersonClaims,
    /// The eIDAS level the login reached.
    pub acr: Option<AssuranceLevel>,
}

/// An authorization code's grant.
#[expect(
    clippy::struct_field_names,
    reason = "`code_challenge` is the parameter's name in RFC 7636 §4.3"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code {
    /// The client.
    pub client_id: String,
    /// The redirect URI of the request.
    pub redirect_uri: String,
    /// The PKCE challenge.
    pub code_challenge: String,
    /// The JWK thumbprint of the `DPoP` key the code is bound to (RFC 9449
    /// §10).
    pub dpop_jkt: Option<String>,
    /// The resource server.
    pub audience: String,
    /// The person's `sub`.
    pub subject: String,
    /// Their `fhirUser`.
    pub fhir_user: Option<String>,
    /// The scope granted.
    pub scope: String,
    /// The client's `nonce`.
    pub nonce: Option<String>,
    /// When the person logged in.
    pub auth_time: i64,
    /// When the code lapses.
    pub expires_at: i64,
    /// The upstream session the person logged in under, which an
    /// `online_access` grant ends with.
    pub upstream_session: Option<String>,
    /// The launch context of an EHR launch.
    pub launch_context: Option<Context>,
    /// What the consent rests on: `page`, `remembered`, `administrative` or
    /// `first-party` (`docs/architecture.md` §13.6 item 6).
    pub basis: Option<String>,
    /// The roles of the person, mapped from the upstream identity provider
    /// (`docs/architecture.md` §13.6 item 5), which the access token's
    /// `roles` claim carries (RFC 9068 §2.2.3.1).
    pub roles: Vec<String>,
    /// The upstream ID Token's standard claims.
    pub person_claims: PersonClaims,
    /// The eIDAS level the login reached.
    pub acr: Option<AssuranceLevel>,
}

/// Inserts the access token `token` through `executor`, a pool or a
/// transaction.
pub(crate) async fn insert_token<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    token: &IssuedToken<'_>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO access_token (jti, client_id, subject, audience, scope, issued_at, expires_at, code_hash, grant_id) \
         VALUES ($1, $2, $3, $4, $5, to_timestamp($6), to_timestamp($7), $8, $9)",
    )
    .bind(token.jti)
    .bind(token.client_id)
    .bind(token.subject)
    .bind(token.audience)
    .bind(token.scope)
    .bind(token.issued_at)
    .bind(token.expires_at)
    .bind(token.code_hash)
    .bind(token.grant_id)
    .execute(executor)
    .await?;
    Ok(())
}

/// Records the `jti` of `issuer` through `executor`, kept until `expires_at`
/// (seconds since the epoch), and returns whether it was unseen.
pub(crate) async fn insert_jti<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    issuer: &str,
    jti: &str,
    expires_at: i64,
) -> Result<bool, StoreError> {
    let inserted = sqlx::query(
        "INSERT INTO seen_jti (issuer, jti, expires_at) VALUES ($1, $2, to_timestamp($3)) \
         ON CONFLICT (issuer, jti) DO NOTHING",
    )
    .bind(issuer)
    .bind(jti)
    .bind(expires_at)
    .execute(executor)
    .await?;
    Ok(inserted.rows_affected() == 1)
}

/// One transaction of the store: an audited write and its audit record,
/// committed together or not at all.
///
/// [`Transaction::commit`] refuses a transaction that wrote no record, so
/// no audited write commits without one. No specification governs this:
/// our own design (`docs/architecture.md` §13.2).
#[derive(Debug)]
pub struct Transaction {
    /// The open transaction.
    tx: sqlx::Transaction<'static, Postgres>,
    /// Whether an audit record was written in it.
    recorded: bool,
}

impl Store {
    /// Opens a transaction for an audited write.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when no connection can be had.
    pub async fn begin(&self) -> Result<Transaction, StoreError> {
        Ok(Transaction {
            tx: self.pool.begin().await?,
            recorded: false,
        })
    }
}

impl Transaction {
    /// Writes the audit record `row` in this transaction.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn record(&mut self, row: &audit::AuditRow) -> Result<(), StoreError> {
        audit::insert(&mut self.tx, row).await?;
        self.recorded = true;
        Ok(())
    }

    /// Commits the write with its record.
    ///
    /// # Errors
    /// Returns [`StoreError::Unrecorded`] when no record was written, and
    /// [`StoreError::Database`] when the commit fails; nothing is kept then.
    pub async fn commit(self) -> Result<(), StoreError> {
        if !self.recorded {
            return Err(StoreError::Unrecorded);
        }
        self.tx.commit().await?;
        Ok(())
    }

    /// Records the access token `token`.
    ///
    /// # Errors
    /// Returns [`StoreError::Database`] when the statement fails.
    pub async fn insert_token(&mut self, token: &IssuedToken<'_>) -> Result<(), StoreError> {
        insert_token(&mut *self.tx, token).await
    }
}

/// Refuses a `server_version_num` older than [`MINIMUM_SERVER_VERSION`].
fn supported(found: i32) -> Result<(), StoreError> {
    if found < MINIMUM_SERVER_VERSION {
        return Err(StoreError::UnsupportedServer {
            found,
            required: MINIMUM_SERVER_VERSION,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{StoreError, supported};

    #[test]
    fn a_server_older_than_postgresql_19_is_refused_with_both_versions() {
        let refused = supported(180_007).expect_err("PostgreSQL 18.7 is refused");
        assert!(matches!(
            refused,
            StoreError::UnsupportedServer {
                found: 180_007,
                required: 190_000
            }
        ));
        assert_eq!(
            "the database runs PostgreSQL server_version_num 180007, and FerroSMART needs 190000 or newer",
            refused.to_string()
        );
    }

    #[test]
    fn postgresql_19_and_newer_are_accepted() {
        for found in [190_000, 190_003, 200_000] {
            assert!(supported(found).is_ok(), "{found}");
        }
    }
}
