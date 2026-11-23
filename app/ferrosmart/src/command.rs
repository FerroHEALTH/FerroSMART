// SPDX-FileCopyrightText: Cadasto B.V.
// SPDX-License-Identifier: BUSL-1.1

//! The run path of the `ferrosmart` binary: the command line parsed, the
//! configuration read, and each job run to its exit code.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ferrohealth_config::loader::Loaded;
use ferrohealth_server::cli::{Common, ConfigArgs, ConfigCommand};
use ferrohealth_server::run::{Failure, Run, chain};
use ferrohealth_telemetry::section::TelemetrySection;
use ferrohealth_telemetry::telemetry::{Console, InitError, Service, Telemetry};
use ihe_atna::atna::forwarder::Forwarder;

use crate::cli::{Cli, ClientCommand, Command, UpstreamCommand};
use crate::config::Config;
use crate::config::settings::Settings;
use crate::server::AppState;
use crate::store::Store;
use crate::upstream::Providers;

/// How long `healthcheck` waits for the readiness answer, shorter than the
/// five seconds a container `HEALTHCHECK` commonly allows.
pub const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(3);

/// The run path of the `ferrosmart` binary, which names it in every line it
/// writes.
pub const RUN: Run = Run::new("ferrosmart");

/// Runs the job `cli` names and returns its exit code.
///
/// # Errors
///
/// Returns the [`Failure`] of a configuration that does not resolve and of
/// a job that fails.
pub async fn dispatch(cli: Cli) -> Result<ExitCode, Failure> {
    let command = match cli.command {
        Command::Common(command) => command,
        Command::Client {
            command: ClientCommand::Apply { files },
        } => return Box::pin(apply_clients(&cli.config, &files)).await,
        Command::Client {
            command: ClientCommand::Secret { client_id },
        } => return Box::pin(rotate_secret(&cli.config, &client_id)).await,
        Command::Subject { upstream, sub } => return subject(&cli.config, &upstream, &sub),
        Command::Upstream {
            command: UpstreamCommand::Registration { name },
        } => return registration(&cli.config, &name),
    };
    let loaded = Config::load(&cli.config).and_then(|loaded| {
        loaded
            .settings()
            .resolve()
            .map(|settings| (loaded, settings))
    });
    let (loaded, settings) = loaded.map_err(|error| command.refused(error))?;
    match command {
        Common::Healthcheck => healthcheck(&settings).await,
        Common::Config {
            command: ConfigCommand::Check,
        } => config_check(&loaded),
        Common::Serve => {
            let telemetry = loaded.settings().telemetry.clone();
            Box::pin(serve(settings, telemetry)).await
        }
    }
}

/// Runs `client apply`: each file's client document written to the
/// registry by [`crate::admin::apply`], in the order given, one line per
/// client. The first file that cannot be read or is refused stops the job;
/// the clients before it stay written.
#[expect(
    clippy::print_stdout,
    reason = "the job's answer, a line per client, goes to standard output"
)]
async fn apply_clients(
    args: &ConfigArgs,
    files: &[std::path::PathBuf],
) -> Result<ExitCode, Failure> {
    let state = registry(args).await?;
    for file in files {
        let named = |context: &str| format!("{context} {}", file.display());
        let bytes = std::fs::read(file)
            .map_err(|error| Failure::from(error).with_context(named("cannot read")))?;
        let document: crate::admin::document::ClientDocument = serde_json::from_slice(&bytes)
            .map_err(|error| Failure::from(error).with_context(named("no client document in")))?;
        let applied = crate::admin::apply(&state, document)
            .await
            .map_err(|error| Failure::from(error).with_context(named("cannot apply")))?;
        let client = &applied.registered.client;
        let done = if applied.created {
            "created"
        } else {
            "replaced"
        };
        println!("ferrosmart: client {:?} {done}", client.client_id);
        if let Some(secret) = &applied.secret {
            println!(
                "ferrosmart: client {:?} client_secret {}",
                client.client_id,
                secrecy::ExposeSecret::expose_secret(secret)
            );
        }
        if let Some(warning) = crate::clients::unassured_public(client) {
            println!("ferrosmart: warning: {warning}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Returns the state the `client` jobs write the registry through: the
/// settings `args` name and the store, migrated.
async fn registry(args: &ConfigArgs) -> Result<AppState, Failure> {
    let settings = Config::load(args)
        .and_then(|loaded| loaded.settings().resolve())
        .map_err(Failure::refused_configuration)?;
    let store = migrated(&settings, 1).await?;
    let audit = crate::audit::Audit::new(settings.audit.observer.clone());
    Ok(AppState::new(settings, store, audit))
}

/// Runs `client secret`: a new secret for the confidential symmetric client
/// `client_id`, its hash stored and the change recorded, the secret printed
/// once (RFC 7591 §3.2.1).
#[expect(
    clippy::print_stdout,
    reason = "the job's one answer goes to standard output"
)]
async fn rotate_secret(args: &ConfigArgs, client_id: &str) -> Result<ExitCode, Failure> {
    let state = registry(args).await?;
    let secret = crate::admin::issue_secret(&state, client_id)
        .await
        .map_err(|error| Failure::from(error).with_context("cannot issue the secret"))?;
    println!("{}", secrecy::ExposeSecret::expose_secret(&secret));
    Ok(ExitCode::SUCCESS)
}

/// Reads the configuration tree `args` names, unresolved: the jobs that
/// read one upstream entry need no key, secret or database.
fn tree(args: &ConfigArgs) -> Result<crate::config::FerroSmartSection, Failure> {
    let loaded = Config::load(args).map_err(Failure::refused_configuration)?;
    Ok(loaded.settings().ferrosmart.clone())
}

/// Runs `subject`: the pairwise `sub` of the person `sub` at the provider
/// `upstream`, on one line (`docs/architecture.md` §13.6 item 9).
#[expect(
    clippy::print_stdout,
    reason = "the job's one answer goes to standard output"
)]
fn subject(args: &ConfigArgs, upstream: &str, sub: &str) -> Result<ExitCode, Failure> {
    if sub.is_empty() {
        return Err(Failure::boxed("the subject is empty"));
    }
    let section = tree(args)?;
    let subject = crate::upstream::registration::subject(&section, upstream, sub)
        .map_err(Failure::refused_configuration)?;
    println!("{subject}");
    Ok(ExitCode::SUCCESS)
}

/// Runs `upstream registration`: what the provider `name` must be
/// configured with.
#[expect(
    clippy::print_stdout,
    reason = "the job's one answer goes to standard output"
)]
fn registration(args: &ConfigArgs, name: &str) -> Result<ExitCode, Failure> {
    let section = tree(args)?;
    let registration = crate::upstream::registration::Registration::of(&section, name)
        .map_err(Failure::refused_configuration)?;
    print!("{registration}");
    Ok(ExitCode::SUCCESS)
}

/// Runs `config check`: every key printed with where it came from and every
/// secret masked, after the settings resolved, keys read included, and a
/// warning for a setting that resolves but works against the person.
#[expect(
    clippy::print_stdout,
    reason = "the job's one answer goes to standard output"
)]
fn config_check(loaded: &Loaded<Config>) -> Result<ExitCode, Failure> {
    ferrohealth_server::run::config_check(loaded)?;
    println!("ferrosmart: the configuration is valid");
    Ok(ExitCode::SUCCESS)
}

/// Runs `healthcheck` against the server this configuration describes.
#[expect(
    clippy::print_stdout,
    reason = "the job's one-line answer goes to standard output"
)]
async fn healthcheck(settings: &Settings) -> Result<ExitCode, Failure> {
    let target = ferrohealth_server::healthcheck::target(settings.server.listen);
    let base = settings.server.base_path.as_str();
    let outcome = match &settings.server.tls {
        Some(tls) => {
            let pinned = ferrohealth_server::tls::HealthcheckTls::read_of(
                tls,
                ferrohealth_server::tls::TlsKeys::SERVER,
            )
            .map_err(Failure::refused_configuration)?;
            ferrohealth_server::healthcheck::check_tls(target, base, HEALTHCHECK_TIMEOUT, &pinned)
                .await
        }
        None => ferrohealth_server::healthcheck::check(target, base, HEALTHCHECK_TIMEOUT).await,
    };
    if outcome.exit_code() == 0 {
        println!("ferrosmart: {outcome}");
        Ok(ExitCode::SUCCESS)
    } else {
        Err(Failure::boxed(outcome.to_string()))
    }
}

/// Runs `serve`: the subscriber, the state, and the server until `SIGTERM`
/// or `SIGINT`.
async fn serve(settings: Settings, section: TelemetrySection) -> Result<ExitCode, Failure> {
    let service = Service::new("ferrosmart", env!("CARGO_PKG_VERSION")).export_crate("ferrosmart");
    let log = |error: InitError| Failure::from(error).with_context("cannot start the log");
    let telemetry = Telemetry::new(&section, service).map_err(log)?;
    telemetry
        .install(&section, &Console::detect())
        .map_err(log)?;
    ferrohealth_telemetry::panic::install_hook();
    let served = listen_and_serve(settings).await;
    if let Err(error) = telemetry.shutdown() {
        tracing::warn!(error = %chain(&error), "the telemetry did not flush");
    }
    served
}

/// Returns the store `settings` name, over at most `connections`
/// connections, with its migrations run.
async fn migrated(settings: &Settings, connections: u32) -> Result<Store, Failure> {
    let store = Store::connect(&settings.database_url, connections)
        .await
        .map_err(|error| Failure::not_up(error).with_context("cannot reach the database"))?;
    store
        .migrate()
        .await
        .map_err(|error| Failure::not_up(error).with_context("cannot migrate the database"))?;
    Ok(store)
}

/// Serves the state `settings` describe until `SIGTERM` or `SIGINT`.
async fn listen_and_serve(settings: Settings) -> Result<ExitCode, Failure> {
    let listen = settings.server.listen;
    let section = settings.server.clone();
    let store = migrated(&settings, settings.max_connections).await?;
    let audit = crate::audit::Audit::new(settings.audit.observer.clone());
    let forwarder = settings.audit.feed.clone().map(|feed| {
        let forwarder = Forwarder::fhir_feed_from(audit.outbox(store.clone(), FEED_IDLE), feed);
        let running = tokio::spawn(Arc::clone(&forwarder).run());
        (forwarder, running)
    });
    settings
        .keys
        .refresh(&store, jiff::Timestamp::now().as_second())
        .await
        .map_err(|error| Failure::not_up(error).with_context("cannot read the signing keys"))?;
    let rotation = tokio::spawn(Arc::clone(&settings.keys).run(store.clone()));
    let sweeper = tokio::spawn(sweep(store.clone()));
    let providers = Providers::connect(
        &settings.upstreams,
        &settings.endpoint_url(crate::authorize::CALLBACK_ROUTE),
        &settings.endpoint_url(crate::logout::end_session::END_SESSION_RETURN_ROUTE),
        settings.saml.as_ref(),
    )
    .await
    .map_err(|error| Failure::not_up(error).with_context("cannot reach an upstream provider"))?;
    let brands =
        match &settings.brand {
            Some(brands) => Some(crate::brands::publish(brands, &store).await.map_err(
                |error| {
                    Failure::not_up(error).with_context("cannot record the brands' last change")
                },
            )?),
            None => None,
        };
    let mut state = AppState::new(settings, store, audit);
    if let Some(brands) = brands {
        state = state.with_brands(brands);
    }
    let state = Arc::new(state.with_login(providers));
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|error| Failure::from(error).with_context("cannot bind the listen address"))?;
    tracing::info!(%listen, "ferrosmart is listening");
    let lifecycle = state.lifecycle().clone();
    let app = crate::server::router(state);
    let stop = ferrohealth_server::serve::shutdown_signal();
    let served = ferrohealth_server::serve::run(listener, app, &section, lifecycle, stop).await;
    sweeper.abort();
    rotation.abort();
    // NOTE: ITI TF-2 §3.20.4.1.1, a record not yet delivered stays in the store
    // and the next start sends it.
    if let Some((forwarder, running)) = forwarder {
        forwarder.stop();
        if let Err(error) = running.await {
            tracing::warn!(error = %chain(&error), "the audit forwarder did not end cleanly");
        }
    }
    match served {
        Ok(_drained) => Ok(ExitCode::SUCCESS),
        Err(error) => {
            tracing::error!(error = %chain(&error), "the listener failed");
            Ok(ExitCode::FAILURE)
        }
    }
}

/// How long the audit forwarder waits for a record before it reads the
/// store again, which catches a record another replica stored. No
/// specification governs the value: our own design.
pub const FEED_IDLE: Duration = Duration::from_secs(5);

/// How often a replica deletes the expired assertion ids and token records.
/// No specification governs the value: our own design.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Deletes the expired rows every [`SWEEP_INTERVAL`]; a failed sweep is
/// logged and the next one tries again.
async fn sweep(store: Store) {
    let mut interval = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        interval.tick().await;
        if let Err(error) = store.sweep().await {
            tracing::warn!(error = %chain(&error), "the expired rows were not swept");
        }
    }
}
