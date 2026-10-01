//! Point d'entrée : arguments, configuration, journaux, runtime, signaux.
//!
//! ```text
//! synco-cdn --config /etc/synco-cdn/config.toml    démarre le service
//! synco-cdn --config … --check-config              valide la configuration et sort
//! synco-cdn --version
//! synco-cdn --healthcheck [URL]                    sonde de santé (HEALTHCHECK Docker)
//! ```
//!
//! Signaux : `SIGTERM` / `SIGINT` = arrêt propre ; `SIGHUP` = rechargement
//! des clés de tickets et des origines CORS.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Empty;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use synco_cdn::config::LogFormat;
use synco_cdn::{Config, Server};
use tokio::signal::unix::{SignalKind, signal};
use tracing_subscriber::EnvFilter;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const USAGE: &str = "usage : synco-cdn --config <fichier.toml> [--check-config] | --healthcheck [URL] | --version";

/// Sonde de santé par défaut : écouteur interne, même conteneur.
const DEFAULT_HEALTHCHECK_URL: &str = "http://127.0.0.1:9101/readyz";
/// Délai de la sonde de santé.
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(3);

enum Command {
    Run(PathBuf),
    Check(PathBuf),
    Healthcheck(String),
    Version,
}

fn parse_args() -> Result<Command, String> {
    let mut config = None;
    let mut check = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" | "-c" => config = Some(PathBuf::from(args.next().ok_or("--config attend un chemin")?)),
            "--check-config" => check = true,
            "--version" | "-V" => return Ok(Command::Version),
            "--healthcheck" => {
                let url = args.next().unwrap_or_else(|| DEFAULT_HEALTHCHECK_URL.to_owned());
                return Ok(Command::Healthcheck(url));
            }
            other => return Err(format!("argument inconnu « {other} »")),
        }
    }
    let config = config.ok_or("--config est requis")?;
    Ok(if check { Command::Check(config) } else { Command::Run(config) })
}

fn main() -> ExitCode {
    let command = match parse_args() {
        Ok(command) => command,
        Err(message) => {
            eprintln!("{message}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let path = match command {
        Command::Version => {
            eprintln!("synco-cdn {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Command::Healthcheck(url) => return healthcheck(&url),
        Command::Check(path) => {
            return match Config::load(&path) {
                Ok(_) => {
                    eprintln!("configuration valide");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("configuration invalide : {error}");
                    ExitCode::from(2)
                }
            };
        }
        Command::Run(path) => path,
    };

    let config = match Config::load(&path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("configuration invalide : {error}");
            return ExitCode::from(2);
        }
    };
    if let Err(error) = init_logging(&config) {
        eprintln!("journaux : {error}");
        return ExitCode::from(2);
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.worker_threads)
        .max_blocking_threads(config.blocking_threads)
        .thread_name("synco-cdn")
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "création du runtime impossible");
            return ExitCode::FAILURE;
        }
    };

    tracing::info!(
        workers = config.worker_threads,
        blocking = config.blocking_threads,
        public = %config.public_addr,
        internal = %config.internal_addr,
        "démarrage"
    );
    match runtime.block_on(run(config, &path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "arrêt sur erreur");
            ExitCode::FAILURE
        }
    }
}

async fn run(config: Config, path: &Path) -> Result<(), String> {
    let server = Server::build(config).await?;
    let state = server.state();

    let mut terminate = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|e| e.to_string())?;
    let mut hangup = signal(SignalKind::hangup()).map_err(|e| e.to_string())?;
    let config_path = path.to_path_buf();

    let shutdown = async move {
        loop {
            tokio::select! {
                _ = terminate.recv() => break,
                _ = interrupt.recv() => break,
                _ = hangup.recv() => reload(&state, &config_path),
            }
        }
    };
    server.run(shutdown).await;
    Ok(())
}

/// `SIGHUP` : relit le fichier et applique les parties rechargeables. Une
/// configuration invalide est ignorée (l'ancienne reste en vigueur).
fn reload(state: &Arc<synco_cdn::state::AppState>, path: &Path) {
    match Config::load(path).map_err(|e| e.to_string()).and_then(|config| state.reload(&config)) {
        Ok(()) => tracing::info!("clés de tickets et origines CORS rechargées"),
        Err(error) => tracing::error!(%error, "rechargement refusé, configuration précédente conservée"),
    }
}

/// Sonde de santé : `GET url`, succès si la réponse est `200`. Permet un
/// `HEALTHCHECK` Docker sans outil supplémentaire dans l'image (ni curl, ni
/// shell nécessaire).
fn healthcheck(url: &str) -> ExitCode {
    let Ok(uri) = url.parse::<http::Uri>() else {
        eprintln!("URL de sonde invalide : {url}");
        return ExitCode::from(2);
    };
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("runtime : {error}");
            return ExitCode::FAILURE;
        }
    };
    let status = runtime.block_on(async {
        let client: Client<HttpConnector, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        tokio::time::timeout(HEALTHCHECK_TIMEOUT, client.get(uri)).await
    });
    match status {
        Ok(Ok(response)) if response.status() == http::StatusCode::OK => ExitCode::SUCCESS,
        Ok(Ok(response)) => {
            eprintln!("sonde : statut {}", response.status());
            ExitCode::FAILURE
        }
        Ok(Err(error)) => {
            eprintln!("sonde : {error}");
            ExitCode::FAILURE
        }
        Err(_) => {
            eprintln!("sonde : délai dépassé");
            ExitCode::FAILURE
        }
    }
}

fn init_logging(config: &Config) -> Result<(), String> {
    let filter = EnvFilter::try_new(&config.log_level).map_err(|e| format!("log.level : {e}"))?;
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_target(false);
    let result = match config.log_format {
        LogFormat::Json => builder.json().flatten_event(true).try_init(),
        LogFormat::Text => builder.try_init(),
    };
    result.map_err(|e| e.to_string())
}
