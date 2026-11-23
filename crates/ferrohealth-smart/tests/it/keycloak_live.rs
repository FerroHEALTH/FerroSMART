// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The `keycloak` profile against a live Keycloak: the image pinned in
//! `docs/VERSIONS.md` is started, a realm, two clients and a user are
//! created with the admin CLI (Keycloak 26.8.2 `admin-cli.adoc`), and the
//! tokens it issues are classified. The container is started as
//! `guides/server/containers.adoc` runs it in development mode, and each
//! client's audience mapper is the one `clients/oidc/con-audience.adoc`
//! describes, by the provider id and keys `AudienceProtocolMapper.java` and
//! `OIDCAttributeMapperHelper.java` define, all vendored under
//! `docs/specs/keycloak-docs/` at the tag. Nothing is committed: every token, key
//! and password exists only while the case runs. The case is gated on
//! `FERROHEALTH_KEYCLOAK_E2E=1`, because it needs a container runtime.

use std::error::Error as StdError;
use std::process::Command;
use std::time::Duration;

use ferrohealth_smart::kind::CallerKind;
use ferrohealth_smart::kind::IssuerKind;
use ferrohealth_smart::profile::Marker;
use ferrohealth_smart::profile::Preset;
use ferrohealth_smart::profile::Profile;
use ferrohealth_smart::profile::ProfileKeys;
use ferrohealth_smart::resource::ResourceServer;
use ferrohealth_smart::resource::Settings;

type Outcome = Result<(), Box<dyn StdError>>;

/// The Keycloak image, by the index digest `docs/VERSIONS.md` pins.
const IMAGE: &str = "quay.io/keycloak/keycloak:26.8.2@sha256:3879c623248408de29a5303178b5816c77e8dfef3890c361f8c0bbeaa979ba3b";

/// The realm the case creates.
const REALM: &str = "ferro";

/// The audience the case's tokens carry.
const AUDIENCE: &str = "ehr";

/// A running container, removed when dropped.
struct Container(String);

impl Drop for Container {
    fn drop(&mut self) {
        let removed = Command::new("docker").args(["rm", "-f", &self.0]).output();
        drop(removed);
    }
}

/// Returns a random value for a password or a secret of this case.
fn random() -> String {
    use base64::Engine as _;
    let mut bytes = [0_u8; 24];
    aws_lc_rs::rand::fill(&mut bytes).expect("the random source draws");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Runs `docker` with `args` and returns its standard output, trimmed.
fn docker(args: &[&str]) -> Result<String, Box<dyn StdError>> {
    let output = Command::new("docker").args(args).output()?;
    if !output.status.success() {
        return Err(format!(
            "docker {} failed: {}",
            args.first().copied().unwrap_or_default(),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

/// Runs the admin CLI in `container` with `args`.
fn kcadm(container: &Container, args: &[&str]) -> Result<String, Box<dyn StdError>> {
    let mut all = vec!["exec", container.0.as_str(), "/opt/keycloak/bin/kcadm.sh"];
    all.extend_from_slice(args);
    docker(&all)
}

/// Returns a token of the realm's token endpoint for `form`.
async fn token(
    http: &reqwest::Client,
    base: &str,
    form: &[(&str, &str)],
) -> Result<String, Box<dyn StdError>> {
    let answer = http
        .post(format!(
            "{base}/realms/{REALM}/protocol/openid-connect/token"
        ))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(form)
                .finish(),
        )
        .send()
        .await?;
    let status = answer.status();
    let body = answer.text().await?;
    if !status.is_success() {
        let grant = form
            .iter()
            .find(|(name, _)| *name == "grant_type")
            .map_or("", |(_, grant)| *grant);
        return Err(format!("the {grant} grant answered {status}: {body}").into());
    }
    let response: serde_json::Value = serde_json::from_str(&body)?;
    Ok(response
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .ok_or("no access_token")?
        .to_owned())
}

/// What the case set up in the realm.
struct Realm {
    /// The server's base URL.
    base: String,
    /// The machine client's secret.
    machine_secret: String,
    /// The first-party client's secret.
    app_secret: String,
    /// The synthetic user's password.
    user_password: String,
    /// The `sub` of the machine client's service account user.
    service_account: String,
}

/// Starts the pinned image and returns the container, its base URL and its
/// administrator password, once it answers.
async fn start() -> Result<(Container, String, String), Box<dyn StdError>> {
    let admin_password = random();
    // NOTE: Keycloak 26.8.2 `guides/server/containers.adoc`, "Trying Keycloak in
    // development mode": the image runs `start-dev` with the two bootstrap variables.
    let id = docker(&[
        "run",
        "-d",
        "-p",
        "127.0.0.1::8080",
        "-e",
        "KC_BOOTSTRAP_ADMIN_USERNAME=admin",
        "-e",
        &format!("KC_BOOTSTRAP_ADMIN_PASSWORD={admin_password}"),
        IMAGE,
        "start-dev",
    ])?;
    let container = Container(id);
    let port = docker(&["port", &container.0, "8080/tcp"])?;
    let base = format!("http://{port}");
    let http = reqwest::Client::new();
    let mut ready = false;
    for _ in 0..120 {
        let answer = http
            .get(format!(
                "{base}/realms/master/.well-known/openid-configuration"
            ))
            .send()
            .await;
        if answer.is_ok_and(|answer| answer.status().is_success()) {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(ready, "the Keycloak container answers");
    Ok((container, base, admin_password))
}

/// Creates the realm, the two clients and the user, and returns what the
/// case needs of them.
fn configure(
    container: &Container,
    base: String,
    admin_password: &str,
) -> Result<Realm, Box<dyn StdError>> {
    kcadm(
        container,
        &[
            "config",
            "credentials",
            "--server",
            "http://localhost:8080",
            "--realm",
            "master",
            "--user",
            "admin",
            "--password",
            admin_password,
        ],
    )?;
    kcadm(
        container,
        &[
            "create",
            "realms",
            "-s",
            &format!("realm={REALM}"),
            "-s",
            "enabled=true",
        ],
    )?;
    let machine_secret = random();
    client(
        container,
        "machine-client",
        "serviceAccountsEnabled=true",
        &machine_secret,
    )?;
    let app_secret = random();
    client(
        container,
        "first-party-app",
        "directAccessGrantsEnabled=true",
        &app_secret,
    )?;
    let user_password = random();
    // NOTE: Keycloak 26.8.2 `users/user-profile.adoc`: `VerifyProfile` is on by default,
    // and `keycloak-default-user-profile.json` requires `email` and both names for users.
    kcadm(
        container,
        &[
            "create",
            "users",
            "-r",
            REALM,
            "-s",
            "username=synthetic-person",
            "-s",
            "enabled=true",
            "-s",
            "email=synthetic-person@example.org",
            "-s",
            "emailVerified=true",
            "-s",
            "firstName=Synthetic",
            "-s",
            "lastName=Person",
        ],
    )?;
    kcadm(
        container,
        &[
            "set-password",
            "-r",
            REALM,
            "--username",
            "synthetic-person",
            "--new-password",
            &user_password,
        ],
    )?;
    // NOTE: Keycloak 26.8.2 `admin-cli.adoc`: the service account is the user
    // `service-account-CLIENT_ID`, found by the `q=username:` query.
    let accounts: serde_json::Value = serde_json::from_str(&kcadm(
        container,
        &[
            "get",
            "users",
            "-r",
            REALM,
            "-q",
            "q=username:service-account-machine-client",
        ],
    )?)?;
    let service_account = accounts
        .as_array()
        .and_then(|users| users.first())
        .and_then(|user| user.get("id"))
        .and_then(serde_json::Value::as_str)
        .ok_or("the service account user has an id")?
        .to_owned();
    Ok(Realm {
        base,
        machine_secret,
        app_secret,
        user_password,
        service_account,
    })
}

// NOTE: Keycloak 26.8.2 `admin-cli.adoc`: "A client's service account is a user
// account with username `service-account-CLIENT_ID`", so its `sub` is listed.
#[tokio::test]
async fn a_live_keycloak_token_is_classified_under_the_keycloak_profile() -> Outcome {
    if std::env::var("FERROHEALTH_KEYCLOAK_E2E").as_deref() != Ok("1") {
        return Ok(());
    }
    let (container, base, admin_password) = start().await?;
    let realm = configure(&container, base, &admin_password)?;
    let Realm {
        base,
        machine_secret,
        app_secret,
        user_password,
        service_account,
    } = realm;
    let http = reqwest::Client::new();
    let mut profile = Profile::resolve(Preset::Keycloak, &ProfileKeys::default())?;
    profile.app_only = vec![Marker::Subjects(vec![service_account])];
    let mut settings = Settings::new(
        format!("{base}/realms/{REALM}"),
        AUDIENCE,
        IssuerKind::Persons,
    );
    settings.profile = profile;
    let server = ResourceServer::discover(settings).await?;
    let person = token(
        &http,
        &base,
        &[
            ("grant_type", "password"),
            ("client_id", "first-party-app"),
            ("client_secret", &app_secret),
            ("username", "synthetic-person"),
            ("password", &user_password),
        ],
    )
    .await?;
    let caller = server.authenticate(&person).await?;
    assert_eq!(
        &CallerKind::Person,
        caller.kind(),
        "a person through the first-party client"
    );
    let system = token(
        &http,
        &base,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", "machine-client"),
            ("client_secret", &machine_secret),
        ],
    )
    .await?;
    let caller = server.authenticate(&system).await?;
    assert_eq!(
        &CallerKind::System,
        caller.kind(),
        "the listed service account"
    );
    Ok(())
}

/// Creates the confidential client `id` with `grant` enabled and `secret`,
/// and an audience mapper that puts [`AUDIENCE`] in its access tokens;
/// returns the client's internal id.
fn client(
    container: &Container,
    id: &str,
    grant: &str,
    secret: &str,
) -> Result<String, Box<dyn StdError>> {
    let client = kcadm(
        container,
        &[
            "create",
            "clients",
            "-r",
            REALM,
            "-s",
            &format!("clientId={id}"),
            "-s",
            grant,
            "-s",
            "clientAuthenticatorType=client-secret",
            "-s",
            &format!("secret={secret}"),
            "-i",
        ],
    )?;
    // NOTE: Keycloak 26.8.2 `clients/oidc/con-audience.adoc` and
    // `AudienceProtocolMapper.java`: the Audience mapper is `oidc-audience-mapper`,
    // configured by `included.custom.audience` and `access.token.claim`.
    kcadm(
        container,
        &[
            "create",
            &format!("clients/{client}/protocol-mappers/models"),
            "-r",
            REALM,
            "-s",
            "name=audience",
            "-s",
            "protocol=openid-connect",
            "-s",
            "protocolMapper=oidc-audience-mapper",
            "-s",
            &format!("config.\"included.custom.audience\"={AUDIENCE}"),
            "-s",
            "config.\"access.token.claim\"=true",
        ],
    )?;
    Ok(client)
}
