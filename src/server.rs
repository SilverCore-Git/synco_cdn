//! Assemblage du service : stockage, reprise, écouteurs, balayage
//! périodique, arrêt propre.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::api_client::ApiClient;
use crate::config::Config;
use crate::http::{Listener, accept_loop, bind, uploads};
use crate::revocation::Revocations;
use crate::state::AppState;
use crate::storage::Storage;
use crate::storage::recovery::recover;
use crate::storage::session::PhaseKind;
use crate::storage::space::SpacePolicy;
use crate::ticket::TicketVerifier;
use crate::util::now_unix;

/// Intervalle du balayage des sessions.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// Délai de grâce après expiration avant abandon d'une session ouverte.
const OPEN_SESSION_GRACE_SECS: u64 = 3600;
/// Conservation d'une session terminée après expiration (réponse à un
/// `complete` rejoué).
const COMPLETED_SESSION_GRACE_SECS: u64 = 3600;

/// Service prêt à tourner : écouteurs ouverts, sessions rechargées.
#[derive(Debug)]
pub struct Server {
    state: Arc<AppState>,
    public: TcpListener,
    internal: TcpListener,
}

impl Server {
    /// Prépare le service. Toute erreur ici empêche le démarrage.
    pub async fn build(config: Config) -> Result<Self, String> {
        let config = Arc::new(config);
        let tickets = TicketVerifier::new(&config.ticket_keys, config.ticket_policy)?;
        let storage = Storage::init(
            &config.data_dir,
            SpacePolicy { min_free_bytes: config.min_free_bytes, min_free_percent: config.min_free_percent },
            config.max_open_sessions,
        )?;

        let layout = storage.layout().clone();
        let now = now_unix();
        let sessions = tokio::task::spawn_blocking(move || recover(&layout, now))
            .await
            .map_err(|e| format!("reprise des sessions : {e}"))?;
        storage.restore(sessions);

        let retention = config.ticket_policy.max_lifetime_secs.saturating_add(config.ticket_policy.clock_skew_secs);
        let revocations = Revocations::load(storage.layout().revocations(), retention);
        let api = ApiClient::new(
            config.api_internal_url.clone(),
            Arc::new(config.internal_secret.clone()),
            config.api_callback_timeout,
        );

        let public = bind(config.public_addr, true).map_err(|e| format!("écoute sur {} : {e}", config.public_addr))?;
        let internal =
            bind(config.internal_addr, false).map_err(|e| format!("écoute sur {} : {e}", config.internal_addr))?;

        let state = Arc::new(AppState::new(Arc::clone(&config), tickets, revocations, storage, api));
        Ok(Self { state, public, internal })
    }

    pub fn public_addr(&self) -> std::io::Result<SocketAddr> {
        self.public.local_addr()
    }

    pub fn internal_addr(&self) -> std::io::Result<SocketAddr> {
        self.internal.local_addr()
    }

    pub fn state(&self) -> Arc<AppState> {
        Arc::clone(&self.state)
    }

    /// Sert jusqu'à ce que `shutdown` se termine, puis s'arrête proprement.
    pub async fn run(self, shutdown: impl Future<Output = ()> + Send) {
        let (stop_tx, stop_rx) = watch::channel(false);
        let public = tokio::spawn(accept_loop(self.public, Listener::Public, Arc::clone(&self.state), stop_rx.clone()));
        let internal = tokio::spawn(accept_loop(self.internal, Listener::Internal, Arc::clone(&self.state), stop_rx));
        let sweeper = tokio::spawn(sweep_loop(Arc::clone(&self.state)));

        tracing::info!("service démarré");
        shutdown.await;
        tracing::info!("arrêt demandé : fin des requêtes en cours");
        let _ = stop_tx.send(true);
        sweeper.abort();
        for (name, task) in [("public", public), ("interne", internal)] {
            if let Err(error) = task.await {
                tracing::error!(listener = name, %error, "boucle d'acceptation terminée anormalement");
            }
        }
        tracing::info!("service arrêté");
    }
}

async fn sweep_loop(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(SWEEP_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        sweep(&state).await;
    }
}

/// Un passage de balayage :
/// - sessions ouvertes expirées et inactives : abandonnées ;
/// - sessions finalisées (client parti avant l'enregistrement) : l'API est
///   rappelée, pour que tout fichier complet finisse enregistré ;
/// - sessions terminées anciennes : oubliées ;
/// - révocations expirées : supprimées.
pub async fn sweep(state: &Arc<AppState>) {
    let now = now_unix();
    for session in state.storage.sessions().snapshot() {
        match session.phase_kind() {
            PhaseKind::Open
                if now > session.expires_at().saturating_add(OPEN_SESSION_GRACE_SECS) && session.in_flight() == 0 =>
            {
                tracing::info!(tid = %session.tid, "session expirée abandonnée");
                state.storage.abort(&session, false).await;
                let api = state.api.clone();
                let tid = session.tid;
                tokio::spawn(async move { api.notify_abort(tid).await });
            }
            PhaseKind::Finalized => {
                if let Some(hash) = session.hash()
                    && session.try_start_callback()
                {
                    let state = Arc::clone(state);
                    tokio::spawn(async move {
                        if let Err(error) = uploads::register(&state, &session, hash).await {
                            tracing::debug!(tid = %session.tid, %error, "rappel d'arrière-plan à refaire");
                        }
                        session.end_callback();
                    });
                }
            }
            PhaseKind::Completed if now > session.expires_at().saturating_add(COMPLETED_SESSION_GRACE_SECS) => {
                state.storage.forget_completed(&session).await;
            }
            _ => {}
        }
    }

    let revocations = Arc::clone(&state.revocations);
    let pruned = tokio::task::spawn_blocking(move || revocations.prune(now)).await;
    if let Ok(Err(error)) = pruned {
        tracing::warn!(%error, "nettoyage des révocations impossible");
    }
}
