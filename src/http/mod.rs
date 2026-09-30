//! Serveur HTTP : écouteurs, boucles d'acceptation, traitement isolé de
//! chaque requête, arrêt propre.
//!
//! - HTTP/1.1 et HTTP/2 (détection automatique, y compris h2c en clair
//!   derrière nginx).
//! - Nombre de connexions plafonné : au-delà, l'acceptation est suspendue
//!   (le noyau met les connexions en file) au lieu d'épuiser la mémoire.
//! - Chaque requête s'exécute dans sa propre tâche : une panique (qui ne
//!   devrait jamais arriver, cf. lints) donne un `500` pour cette requête
//!   seulement et incrémente `cdn_panics_total` ; le processus continue.

pub mod cors;
pub mod downloads;
pub mod internal;
pub mod public;
pub mod respond;
pub mod uploads;

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use http::header::ORIGIN;
use http::{HeaderValue, Request};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::{Semaphore, watch};

use crate::error::CdnError;
use crate::metrics::Route;
use crate::state::{AppState, RequestLog};
use respond::{HttpResponse, error_response};

/// Écouteur d'origine d'une requête.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listener {
    Public,
    Internal,
}

/// Attente après une erreur d'acceptation due à l'épuisement des ressources.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// File d'attente du noyau pour les connexions pas encore acceptées.
const LISTEN_BACKLOG: u32 = 4096;

/// Ouvre un écouteur TCP. `SO_REUSEPORT` sur l'écouteur public permet de
/// démarrer une nouvelle version avant d'arrêter l'ancienne (mise à jour
/// sans coupure, cf. docs/plan/08-exploitation.md).
pub fn bind(addr: SocketAddr, reuse_port: bool) -> io::Result<TcpListener> {
    let socket = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
    socket.set_reuseaddr(true)?;
    if reuse_port {
        socket.set_reuseport(true)?;
    }
    socket.bind(addr)?;
    socket.listen(LISTEN_BACKLOG)
}

/// Réglages HTTP (cf. docs/plan/04-moteur-io.md#réglages-http).
fn connection_builder(state: &AppState) -> auto::Builder<TokioExecutor> {
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(state.config.header_read_timeout)
        .keep_alive(true)
        .max_headers(64);
    builder
        .http2()
        .timer(TokioTimer::new())
        .adaptive_window(true)
        .max_concurrent_streams(256)
        .max_frame_size(256 * 1024)
        .max_header_list_size(16 * 1024)
        .max_pending_accept_reset_streams(Some(64))
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .keep_alive_timeout(Duration::from_secs(20));
    builder
}

/// Accepte les connexions de `listener` jusqu'au signal d'arrêt, puis laisse
/// les requêtes en cours se terminer (au plus `shutdown_grace`).
pub async fn accept_loop(
    listener: TcpListener,
    kind: Listener,
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let graceful = GracefulShutdown::new();
    let builder = connection_builder(&state);
    let slots = Arc::new(Semaphore::new(state.config.max_connections));

    loop {
        let permit = tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            permit = Arc::clone(&slots).acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => break,
            },
        };
        let accepted = tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            accepted = listener.accept() => accepted,
        };
        let stream = match accepted {
            Ok((stream, _peer)) => stream,
            Err(error) => {
                if is_resource_exhaustion(&error) {
                    tracing::warn!(%error, "acceptation impossible (ressources épuisées), nouvelle tentative");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                } else {
                    tracing::debug!(%error, "erreur d'acceptation");
                }
                continue;
            }
        };
        let _ = stream.set_nodelay(true);

        let service_state = Arc::clone(&state);
        let service = service_fn(move |request| {
            let state = Arc::clone(&service_state);
            async move { Ok::<_, Infallible>(serve_request(state, kind, request).await) }
        });
        let connection = graceful.watch(builder.serve_connection(TokioIo::new(stream), service).into_owned());
        let metrics = Arc::clone(&state.metrics);
        metrics.connections_open.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(%error, "connexion terminée sur erreur");
            }
            metrics.connections_open.fetch_sub(1, Ordering::Relaxed);
            drop(permit);
        });
    }

    let grace = state.config.shutdown_grace;
    if tokio::time::timeout(grace, graceful.shutdown()).await.is_err() {
        tracing::warn!(?kind, "délai d'arrêt dépassé, connexions restantes fermées");
    }
}

fn is_resource_exhaustion(error: &io::Error) -> bool {
    use rustix::io::Errno;
    [Errno::MFILE, Errno::NFILE, Errno::NOBUFS, Errno::NOMEM]
        .iter()
        .any(|errno| error.raw_os_error() == Some(errno.raw_os_error()))
}

/// Traite une requête dans sa propre tâche, puis ajoute CORS, en-têtes de
/// sécurité, métriques et journal.
async fn serve_request(state: Arc<AppState>, kind: Listener, request: Request<Incoming>) -> HttpResponse {
    let started = Instant::now();
    let method = request.method().clone();
    let route = match kind {
        Listener::Public => public::classify(&method, request.uri().path()),
        Listener::Internal => internal::classify(&method, request.uri().path()),
    };
    let origin: Option<HeaderValue> = request.headers().get(ORIGIN).cloned();

    let task_state = Arc::clone(&state);
    let task = tokio::spawn(async move {
        let mut log = RequestLog::default();
        let result = match kind {
            Listener::Public => public::handle(&task_state, request, &mut log).await,
            Listener::Internal => internal::handle(&task_state, request, &mut log).await,
        };
        (result, log)
    });

    let (mut response, log, failure) = match task.await {
        Ok((Ok(response), log)) => (response, log, None),
        Ok((Err(error), log)) => (error_response(&error), log, Some(error)),
        Err(join_error) => {
            if join_error.is_panic() {
                state.metrics.panics.fetch_add(1, Ordering::Relaxed);
                tracing::error!(route = route.name(), "panique capturée pendant le traitement d'une requête");
            }
            let error = CdnError::internal("tâche de requête", join_error);
            (error_response(&error), RequestLog::default(), Some(error))
        }
    };

    if kind == Listener::Public {
        state.cors().apply(origin.as_ref(), response.headers_mut());
    }
    response.headers_mut().insert(http::header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));

    let status = response.status().as_u16();
    state.metrics.record_request(route, status);
    log_request(route, &method, status, started.elapsed(), &log, failure.as_ref());
    response
}

fn log_request(
    route: Route,
    method: &http::Method,
    status: u16,
    elapsed: Duration,
    log: &RequestLog,
    failure: Option<&CdnError>,
) {
    let duration_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    let tid = log.tid.map(|t| t.hyphenated().to_string());
    let fid = log.fid.map(|f| f.hyphenated().to_string());
    match failure {
        Some(error) if error.status.is_server_error() => tracing::error!(
            route = route.name(), %method, status, duration_ms, tid, fid, sub = log.sub, error = %error,
            "requête en erreur"
        ),
        Some(error) => tracing::info!(
            route = route.name(), %method, status, duration_ms, tid, fid, sub = log.sub, error = error.code,
            "requête refusée"
        ),
        None => tracing::info!(
            route = route.name(), %method, status, duration_ms, tid, fid, sub = log.sub, bytes = log.bytes,
            "requête"
        ),
    }
}
