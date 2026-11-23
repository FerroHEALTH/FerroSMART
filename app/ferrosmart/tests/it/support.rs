// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! What the cases share: generated keys written to PEM files, a
//! configuration over them, the client documents a case applies, the audit
//! lane and the records it stored.
//!
//! A case writes its clients as `[[client]]` tables beside its
//! configuration, each one client document in TOML: [`config`] leaves them
//! out and [`clients`] reads them, which [`apply`] then writes as
//! `ferrosmart client apply` does.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, RsaKeyPair};
use base64::Engine as _;

use axum::body::Body;
use axum::extract::ConnectInfo;
use ferrosmart::audit::Audit;
use ferrosmart::config::Config;
use ferrosmart::config::settings::Settings;
use ferrosmart::store::Store;
use ferrosmart::store::Transaction;
use ferrosmart::store::audit::{AuditQuery, AuditRow};
use http::Request;
use secrecy::SecretString;
use serde_json::Value;
use sqlx::Connection as _;
use tempfile::TempDir;

/// Returns `der` as a PEM `PRIVATE KEY` document.
fn pem(der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
        .collect();
    format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        lines.join("\n")
    )
}

/// The `acr` the stub providers' ID Tokens carry.
pub(crate) const SUBSTANTIAL_ACR: &str = "urn:synthetic:loa:substantial";

/// The `[ferrosmart.upstream.assurance]` table of a stub provider: a value
/// for each eIDAS level, [`SUBSTANTIAL_ACR`] at the deployment's default
/// floor.
pub(crate) const ASSURANCE: &str = "[ferrosmart.upstream.assurance]\n\
     levels = { \"urn:synthetic:loa:low\" = \"low\", \
     \"urn:synthetic:loa:substantial\" = \"substantial\", \
     \"urn:synthetic:loa:high\" = \"high\" }\n";

/// The `[ferrosmart.upstream.oidc.private_key_jwt.keys]` table of a case,
/// with a fresh assertion key under `dir`: `private_key_jwt`, the client
/// authentication FerroSMART takes upstream when no table names another
/// (OpenID Connect Core 1.0 §9).
pub(crate) fn upstream_assertion(dir: &Path) -> String {
    format!(
        "[ferrosmart.upstream.oidc.private_key_jwt.keys]\n\
         private_key_file = {:?}\n",
        rsa_key(dir, "upstream-assertion.pem").display().to_string()
    )
}

/// Writes a fresh RSA key to `dir/name` and returns its path.
pub(crate) fn rsa_key(dir: &Path, name: &str) -> PathBuf {
    let pair = RsaKeyPair::generate(KeySize::Rsa2048).expect("a key pair");
    let der = pair.as_der().expect("PKCS#8");
    let path = dir.join(name);
    std::fs::write(&path, pem(der.as_ref())).expect("the key is written");
    path
}

/// Writes a fresh P-384 key to `dir/name` and returns its path.
pub(crate) fn ec_key(dir: &Path, name: &str) -> PathBuf {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let der =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng).expect("a key pair");
    let path = dir.join(name);
    std::fs::write(&path, pem(der.as_ref())).expect("the key is written");
    path
}

/// A directory of keys that lives as long as the case.
pub(crate) struct Keys {
    /// The directory.
    pub(crate) dir: TempDir,
    /// The current key.
    pub(crate) current: PathBuf,
}

impl Keys {
    /// Returns a directory with one current RSA key.
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().expect("a directory");
        let current = rsa_key(dir.path(), "current.pem");
        Self { dir, current }
    }
}

/// The resource server a case configures unless it names its own.
pub(crate) const RESOURCE: &str = "https://ehr.example.org/fhir";

/// The address every case's requests come from (RFC 5737).
pub(crate) const CLIENT_ADDRESS: &str = "192.0.2.10";

/// The database URL a case that never reaches the database configures.
pub(crate) const UNREACHED_DATABASE: &str = "postgres://ferrosmart@127.0.0.1:1/unreached";

/// Returns `text` split into the configuration and the `[[client]]`
/// tables with their subtables.
fn split(text: &str) -> (String, String) {
    let (mut config, mut clients) = (String::new(), String::new());
    let mut in_client = false;
    for line in text.lines() {
        let header = line.trim();
        if header.starts_with('[') {
            in_client = header == "[[client]]" || header.starts_with("[client.");
        }
        let out = if in_client { &mut clients } else { &mut config };
        out.push_str(line);
        out.push('\n');
    }
    (config, clients)
}

/// Returns the client documents the `[[client]]` tables of `text` hold. A
/// table may write `scope` as an array, which the document joins with
/// spaces (RFC 7591 §2).
pub(crate) fn clients(text: &str) -> Vec<Value> {
    let (_, tables) = split(text);
    let table: toml::Table = toml::from_str(&tables).expect("the client tables read");
    let Some(clients) = table.get("client") else {
        return Vec::new();
    };
    let mut documents: Vec<Value> =
        serde_json::from_value(serde_json::to_value(clients).expect("the client tables convert"))
            .expect("an array of tables");
    for document in &mut documents {
        if let Some(scopes) = document.get("scope").and_then(Value::as_array) {
            let joined: Vec<&str> = scopes.iter().filter_map(Value::as_str).collect();
            document["scope"] = Value::from(joined.join(" "));
        }
    }
    documents
}

/// Gives the confidential symmetric client `client_id` the secret `secret`
/// in `store`, as a case that holds a known secret needs.
pub(crate) async fn set_secret(store: &Store, client_id: &str, secret: &str) {
    let hash = ferrosmart::clients::SecretHash::from(
        ferrosmart::clients::hash_secret(secret).expect("hashed"),
    );
    let mut tx = store.begin().await.expect("begins");
    tx.set_secret(client_id, &hash).await.expect("written");
    commit(tx).await;
}

/// Writes each of `documents` to the registry as `ferrosmart client apply`
/// does.
pub(crate) async fn apply(state: &ferrosmart::server::AppState, documents: &[Value]) {
    for document in documents {
        let document = serde_json::from_value(document.clone()).expect("a client document");
        ferrosmart::admin::apply(state, document)
            .await
            .expect("the client applies");
    }
}

/// Returns `value` as a TOML inline value, for a JWK Set a `[[client]]`
/// table holds by value.
pub(crate) fn inline(value: &Value) -> String {
    toml::Value::try_from(value)
        .expect("a TOML value")
        .to_string()
}

/// Returns the configuration `text` holds, its `[[client]]` tables left
/// out, with `[ferrosmart.keys]` naming `keys`' current key unless `text`
/// names one, and [`UNREACHED_DATABASE`] as the database unless `text`
/// names one.
pub(crate) fn config(text: &str, keys: &Keys) -> Config {
    let (text, _) = split(text);
    let text = text.as_str();
    let mut environment = BTreeMap::new();
    if !text.contains("[ferrosmart.database]") {
        environment.insert(
            String::from("FERROSMART__FERROSMART__DATABASE__URL"),
            String::from(UNREACHED_DATABASE),
        );
    }
    if !text.contains("[[ferrosmart.resource]]") {
        environment.insert(
            String::from("FERROSMART__FERROSMART__RESOURCE"),
            format!("[{{ base = {RESOURCE:?} }}]"),
        );
    }
    if !text.contains("[ferrosmart.keys]") {
        environment.insert(
            String::from("FERROSMART__FERROSMART__KEYS__PRIVATE_KEY_FILES"),
            keys.current.display().to_string(),
        );
    }
    Config::from_sources(Some(text), &environment).expect("the configuration reads")
}

/// Returns the `resources` key of a client that may name every base the
/// `[[ferrosmart.resource]]` tables of `text` configure, or [`RESOURCE`]
/// when `text` configures none, as [`config`] then does.
pub(crate) fn resources_of(text: &str) -> String {
    let mut bases = Vec::new();
    let mut in_resource = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("[[") || line.starts_with('[') {
            in_resource = line == "[[ferrosmart.resource]]";
        } else if in_resource && let Some(base) = line.strip_prefix("base = ") {
            bases.push(base.trim_matches('"').to_owned());
        }
    }
    if bases.is_empty() {
        bases.push(RESOURCE.to_owned());
    }
    format!("resources = {bases:?}\n")
}

/// Returns `text` with every `[[client]]` table that sets no
/// `resources` given [`resources_of`] `text`: a case's clients reach every
/// base it configures unless a table says otherwise.
pub(crate) fn reach_every_base(text: &str) -> String {
    let listing = resources_of(text);
    let mut out = String::with_capacity(text.len());
    let lines: Vec<&str> = text.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        out.push_str(line);
        out.push('\n');
        if line.trim() == "[[client]]" {
            let listed = lines
                .iter()
                .skip(index + 1)
                .take_while(|next| !next.trim().starts_with('['))
                .any(|next| next.trim().starts_with("resources"));
            if !listed {
                out.push_str(&listing);
            }
        }
    }
    out
}

/// Returns the audit lane `settings` describe.
pub(crate) fn audit(settings: &Settings) -> Audit {
    Audit::new(settings.audit.observer.clone())
}

/// Returns whether `record` is one [`apply`] wrote when the case started.
pub(crate) fn applied(record: &Value) -> bool {
    record
        .pointer("/agent/0/who/display")
        .and_then(Value::as_str)
        == Some(ferrosmart::admin::APPLY_REQUESTER)
}

/// Returns every `AuditEvent` `store` keeps after the case's clients were
/// applied, oldest first.
pub(crate) async fn records(store: &Store) -> Vec<Value> {
    let mut records = all_records(store).await;
    records.retain(|record| !applied(record));
    records
}

/// Returns every `AuditEvent` `store` keeps, oldest first.
pub(crate) async fn all_records(store: &Store) -> Vec<Value> {
    let mut records = store
        .audit_records(&AuditQuery {
            limit: 1000,
            ..AuditQuery::default()
        })
        .await
        .expect("the records read");
    records.reverse();
    records
}

/// Returns `request` as if it came over a connection from
/// [`CLIENT_ADDRESS`], which the stack names the client by.
pub(crate) fn from_client(mut request: Request<Body>) -> Request<Body> {
    let peer: SocketAddr = format!("{CLIENT_ADDRESS}:49152")
        .parse()
        .expect("an address");
    request.extensions_mut().insert(ConnectInfo(peer));
    request
}

/// The variable naming the test server.
const ENV: &str = "FERROSMART_TEST_PG_URL";

/// A database of its own for one case: a schema of the shared test
/// database, which the case's URL puts first on its `search_path`.
///
/// Creating a database per case serializes the cases on the server, which
/// copies a whole database for each, and under a parallel run a case's
/// first connection can wait past the pool's acquire timeout; a schema is
/// a few catalog rows.
pub(crate) struct Database {
    /// The URL of the shared test database.
    shared: String,
    /// The schema's name.
    name: String,
    /// The schema's URL.
    pub(crate) url: SecretString,
    /// Whether the case dropped it.
    disposed: bool,
}

/// The database every case's schema lives in, on the server
/// `FERROSMART_TEST_PG_URL` names.
const SHARED: &str = "ferrosmart_test";

/// The advisory lock under which the first case creates [`SHARED`]. Any
/// fixed key: our own.
const SHARED_LOCK: i64 = 7_175_170_517;

/// Returns `admin` naming the database [`SHARED`], with `search_path` set
/// to `schema` when one is named.
fn shared_url(admin: &str, schema: Option<&str>) -> String {
    let mut url = url::Url::parse(admin).expect("a URL");
    url.set_path(SHARED);
    if let Some(schema) = schema {
        url.query_pairs_mut()
            .append_pair("options", &format!("-c search_path={schema}"));
    }
    url.to_string()
}

impl Database {
    /// Creates a fresh schema in [`SHARED`] with the migrations applied,
    /// creating that database first when no case has.
    pub(crate) async fn create() -> Self {
        let admin = std::env::var(ENV)
            .expect("FERROSMART_TEST_PG_URL names the PostgreSQL server to test against");
        let mut bytes = [0_u8; 8];
        aws_lc_rs::rand::fill(&mut bytes).expect("the random source draws");
        let name = bytes
            .iter()
            .fold(String::from("ferrosmart_test_"), |mut name, byte| {
                use std::fmt::Write as _;
                write!(name, "{byte:02x}").expect("a String takes every write");
                name
            });
        let mut connection = sqlx::PgConnection::connect(&admin)
            .await
            .expect("the server answers");
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(SHARED_LOCK)
            .execute(&mut connection)
            .await
            .expect("the lock is taken");
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)")
                .bind(SHARED)
                .fetch_one(&mut connection)
                .await
                .expect("the catalog reads");
        if !exists {
            sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {SHARED}")))
                .execute(&mut connection)
                .await
                .expect("the shared database is created");
        }
        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(SHARED_LOCK)
            .execute(&mut connection)
            .await
            .expect("the lock is released");
        let shared = shared_url(&admin, None);
        let mut connection = sqlx::PgConnection::connect(&shared)
            .await
            .expect("the shared database answers");
        // The name is the fixed prefix and the hex digits this case drew, never input.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {name}")))
            .execute(&mut connection)
            .await
            .expect("the schema is created");
        let url = shared_url(&admin, Some(&name));
        // sqlx takes one migration lock per database, which would queue every case
        // of the shared database behind the others; each schema migrates alone.
        let mut migrator = sqlx::migrate!("./migrations");
        migrator.set_locking(false);
        let mut schema = sqlx::PgConnection::connect(&url)
            .await
            .expect("the schema answers");
        migrator
            .run(&mut schema)
            .await
            .expect("the schema migrates");
        Self {
            url: SecretString::from(url),
            shared,
            name,
            disposed: false,
        }
    }

    /// Drops the schema.
    pub(crate) async fn drop(mut self, store: Store) {
        drop(store);
        dispose(&self.shared, &self.name).await;
        self.disposed = true;
    }
}

impl Drop for Database {
    /// Drops the schema of a case that failed before it dropped it, so a
    /// failing run leaves nothing behind.
    fn drop(&mut self) {
        if self.disposed {
            return;
        }
        let (shared, name) = (self.shared.clone(), self.name.clone());
        let _disposed = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime");
            runtime.block_on(dispose(&shared, &name));
        })
        .join();
    }
}

/// Drops the schema `name` of the shared database `shared` names.
async fn dispose(shared: &str, name: &str) {
    let mut connection = sqlx::PgConnection::connect(shared)
        .await
        .expect("the shared database answers");
    // The name is the fixed prefix and the hex digits a case drew, never input.
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {name} CASCADE")))
        .execute(&mut connection)
        .await
        .expect("the schema is dropped");
}

/// Checks `record` against BALP 1.1.4's profile `IHE.IUA.71`, the FHIR
/// form of the ITI-71 audit event, element by element of its differential.
///
/// # Errors
///
/// Returns the first constraint the record breaks.
pub(crate) fn iua_71(record: &Value) -> Result<(), String> {
    let at = |pointer: &str| record.pointer(pointer);
    let coded = |value: Option<&Value>, system: &str, code: &str| {
        value.is_some_and(|coding| {
            coding.get("system") == Some(&Value::from(system))
                && coding.get("code") == Some(&Value::from(code))
        })
    };
    let concept = |value: Option<&Value>, system: &str, code: &str| {
        value
            .and_then(|concept| concept.get("coding"))
            .and_then(Value::as_array)
            .is_some_and(|codings| {
                codings
                    .iter()
                    .any(|coding| coded(Some(coding), system, code))
            })
    };
    let profiled = at("/meta/profile")
        .and_then(Value::as_array)
        .is_some_and(|profiles| profiles.iter().any(|profile| profile == IUA_71));
    if !profiled {
        return Err(String::from("meta.profile names no IHE.IUA.71"));
    }
    if !coded(at("/type"), DCM, "110114") {
        return Err(String::from("type is no 110114"));
    }
    let subtypes = at("/subtype").and_then(Value::as_array).map_or(0, Vec::len);
    if subtypes != 1 || !coded(at("/subtype/0"), "urn:ihe:event-type-code", "ITI-71") {
        return Err(String::from("subtype is not ITI-71 alone"));
    }
    if at("/outcome").is_none() {
        return Err(String::from("no outcome"));
    }
    let agents = at("/agent")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !(2..=3).contains(&agents.len()) {
        return Err(format!("{} agents", agents.len()));
    }
    let (mut clients, mut servers, mut users) = (0, 0, 0);
    for agent in &agents {
        let kind = agent.get("type");
        let has = |member: &str| agent.get(member).is_some();
        if concept(kind, DCM, "110150") {
            clients += 1;
            if !has("who") || !has("network") || has("media") {
                return Err(String::from("agent:client needs who and network"));
            }
        } else if concept(kind, USER_AGENT_TYPES, "AuthzOauthService") {
            servers += 1;
            if !has("who") || !has("network") || has("media") {
                return Err(String::from("agent:auth-server needs who and network"));
            }
        } else if concept(kind, PARTICIPATION_TYPE, "IRCP") {
            users += 1;
            if !has("who") || has("network") || has("altId") || has("media") {
                return Err(String::from("agent:user needs who and no network or altId"));
            }
        } else {
            return Err(String::from(
                "an agent fills no slice of the closed slicing",
            ));
        }
    }
    if clients != 1 || servers != 1 || users > 1 {
        return Err(format!(
            "{clients} clients, {servers} servers, {users} users"
        ));
    }
    let entities = at("/entity").and_then(Value::as_array).map_or(0, Vec::len);
    if entities != 1 {
        return Err(format!("{entities} entities"));
    }
    let request = at("/entity/0");
    let entity = |member: &str| request.and_then(|entity| entity.get(member));
    if !coded(entity("type"), AUDIT_ENTITY_TYPE, "2")
        || !coded(entity("role"), OBJECT_ROLE, "24")
        || entity("what").is_some()
        || entity("query").is_none()
    {
        return Err(String::from("the entity is no token-request"));
    }
    Ok(())
}

/// The canonical URL of BALP 1.1.4's `IHE.IUA.71`.
const IUA_71: &str = "https://profiles.ihe.net/ITI/BALP/StructureDefinition/IHE.IUA.71";
/// The DICOM code system.
const DCM: &str = "http://dicom.nema.org/resources/ontology/DCM";
/// BALP's agent types.
const USER_AGENT_TYPES: &str = "https://profiles.ihe.net/ITI/BALP/CodeSystem/UserAgentTypes";
/// HL7 v3 `ParticipationType`.
const PARTICIPATION_TYPE: &str = "http://terminology.hl7.org/CodeSystem/v3-ParticipationType";
/// FHIR R4 `audit-entity-type`.
const AUDIT_ENTITY_TYPE: &str = "http://terminology.hl7.org/CodeSystem/audit-entity-type";
/// FHIR R4 `object-role`.
const OBJECT_ROLE: &str = "http://terminology.hl7.org/CodeSystem/object-role";

/// Commits `tx`, a write a case makes in place of the endpoint that would,
/// with a record of it, as every audited write commits.
pub(crate) async fn commit(mut tx: Transaction) {
    tx.record(&AuditRow {
        recorded_at: jiff::Timestamp::now().to_string(),
        kind: "test",
        outcome: "0",
        subject: None,
        client_id: None,
        document: String::from("{\"resourceType\":\"AuditEvent\"}"),
    })
    .await
    .expect("recorded");
    tx.commit().await.expect("committed");
}

/// Returns the FerroSMART event codes of `records`, in order: each
/// record's subtype in `urn:ferrosmart:audit-event`.
pub(crate) fn events(records: &[Value]) -> Vec<String> {
    records
        .iter()
        .filter_map(|record| record.get("subtype").and_then(Value::as_array))
        .flat_map(|subtypes| subtypes.iter())
        .filter(|coding| coding.get("system").and_then(Value::as_str) == Some(OWN_EVENTS))
        .filter_map(|coding| coding.get("code").and_then(Value::as_str))
        .map(str::to_owned)
        .collect()
}

/// Returns the basis each `authorization-code` record of `records` names,
/// in order: the `basis` detail of its entity.
pub(crate) fn bases(records: &[Value]) -> Vec<String> {
    records
        .iter()
        .filter(|record| events(std::slice::from_ref(*record)) == ["authorization-code"])
        .filter_map(|record| record.get("entity").and_then(Value::as_array))
        .flat_map(|entities| entities.iter())
        .filter_map(|entity| entity.get("detail").and_then(Value::as_array))
        .flat_map(|details| details.iter())
        .filter(|detail| detail.get("type").and_then(Value::as_str) == Some("basis"))
        .filter_map(|detail| detail.get("valueString").and_then(Value::as_str))
        .map(str::to_owned)
        .collect()
}

/// FerroSMART's own code system of audit events.
const OWN_EVENTS: &str = "urn:ferrosmart:audit-event";

/// Returns the caller `token` is read as by a resource server for
/// `audience` that trusts FerroSMART's `issuer` with the deployment's `keys`
/// over the defaults, with the published JWK Set `jwks` as its key set.
pub(crate) async fn read_at_resource_server(
    jwks: &Value,
    issuer: &str,
    audience: &str,
    kind: ferrohealth_smart::kind::IssuerKind,
    keys: &ferrohealth_smart::profile::ProfileKeys,
    token: &str,
) -> Result<ferrohealth_smart::resource::Caller, ferrohealth_smart::resource::Rejection> {
    use ferrohealth_smart::profile::Profile;
    use ferrohealth_smart::resource::{ResourceServer, Settings as ResourceSettings};

    let dir = tempfile::tempdir().expect("a directory");
    let path = dir.path().join("ferrosmart-jwks.json");
    std::fs::write(&path, jwks.to_string()).expect("written");
    let mut settings = ResourceSettings::new(issuer, audience, kind);
    settings.profile = Profile::default().with_keys(keys.clone());
    settings.jwks_file = Some(path);
    let server = ResourceServer::discover(settings)
        .await
        .expect("the resource server starts");
    server.authenticate(token).await
}

/// Moves the rotation of the refresh token `token` in the database at `url`
/// back by `seconds`, past the repeat window when `seconds` exceeds it.
pub(crate) async fn rotated_ago(url: &str, token: &str, seconds: u32) {
    use sqlx::Connection as _;
    let mut connection = sqlx::PgConnection::connect(url).await.expect("connects");
    let moved = sqlx::query(
        "UPDATE refresh_token SET used_at = used_at - make_interval(secs => $2) \
         WHERE token_hash = $1 AND used_at IS NOT NULL",
    )
    .bind(ferrosmart::authorize::sha256(token))
    .bind(f64::from(seconds))
    .execute(&mut connection)
    .await
    .expect("the rotation moves");
    assert_eq!(1, moved.rows_affected(), "the token was rotated");
}

/// Returns the logins of every provider `settings` configures, discovered
/// at their stubs.
pub(crate) async fn providers(settings: &Settings) -> ferrosmart::upstream::Providers {
    ferrosmart::upstream::Providers::connect(
        &settings.upstreams,
        &settings.endpoint_url(ferrosmart::authorize::CALLBACK_ROUTE),
        &settings.endpoint_url(ferrosmart::logout::end_session::END_SESSION_RETURN_ROUTE),
        settings.saml.as_ref(),
    )
    .await
    .expect("the providers are discovered")
}

/// Every grant type a token endpoint may be asked for: the four of RFC 6749
/// §4, the refresh token of §6, and the extension grants of RFC 8693, RFC
/// 7523 and RFC 8628.
pub(crate) const GRANT_TYPES: [&str; 8] = [
    "authorization_code",
    "implicit",
    "password",
    "client_credentials",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:token-exchange",
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
    "urn:ietf:params:oauth:grant-type:device_code",
];

/// Returns the grant types the metadata `document` lists.
pub(crate) fn listed_grants(document: &Value) -> Vec<String> {
    document["grant_types_supported"]
        .as_array()
        .expect("grant_types_supported")
        .iter()
        .map(|grant| grant.as_str().expect("a string").to_owned())
        .collect()
}
