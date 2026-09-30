//! Écouteur interne (cf. docs/plan/03-protocole.md#routes-internes-écouteur-12700019101).
//!
//! `/readyz` et `/metrics` sont en lecture seule et sans authentification
//! (l'écouteur n'est joignable que localement). Les routes qui modifient
//! l'état exigent une signature HMAC de synco_api.

use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::CdnError;
use crate::http::public::parse_id;
use crate::http::respond::{HttpResponse, no_content, text};
use crate::internal_auth::{SIGNATURE_HEADER, TIMESTAMP_HEADER};
use crate::metrics::{Gauges, Route};
use crate::revocation::RevocationError;
use crate::state::{AppState, RequestLog};
use crate::storage::session::PhaseKind;
use crate::storage::writer::run_blocking;
use crate::util::now_unix;

/// Taille maximale d'un corps de requête interne.
const MAX_INTERNAL_BODY: usize = 64 * 1024;
/// Délai maximal de réception d'un corps de requête interne.
const INTERNAL_BODY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resource {
    Ready,
    Metrics,
    Revocations,
    Upload(Uuid),
}

fn parse(path: &str) -> Option<Resource> {
    match path {
        "/readyz" => Some(Resource::Ready),
        "/metrics" => Some(Resource::Metrics),
        "/internal/v1/revocations" => Some(Resource::Revocations),
        _ => path.strip_prefix("/internal/v1/uploads/").and_then(parse_id).map(Resource::Upload),
    }
}

pub fn classify(method: &Method, path: &str) -> Route {
    match (parse(path), method) {
        (Some(Resource::Ready), _) => Route::InternalReady,
        (Some(Resource::Metrics), _) => Route::InternalMetrics,
        (Some(Resource::Revocations), _) => Route::InternalRevoke,
        (Some(Resource::Upload(_)), _) => Route::InternalAbort,
        (None, _) => Route::NotFound,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationBody {
    sub: String,
    until: u64,
}

pub async fn handle(
    state: &AppState,
    request: Request<Incoming>,
    log: &mut RequestLog,
) -> Result<HttpResponse, CdnError> {
    let resource = parse(request.uri().path()).ok_or(CdnError::not_found("not_found", "Ressource inconnue."))?;
    match (resource, request.method().clone()) {
        (Resource::Ready, Method::GET) => {
            if state.storage.is_ready().await {
                Ok(text(StatusCode::OK, "ok".to_owned(), "text/plain; charset=utf-8"))
            } else {
                Err(CdnError::unavailable("not_ready", "Stockage indisponible ou plein.", 10))
            }
        }
        (Resource::Metrics, Method::GET) => {
            let data_dir = state.storage.layout().data_dir().to_path_buf();
            let disk_free = run_blocking(move || crate::storage::space::disk_usage(&data_dir))
                .await
                .map(|u| u.available)
                .unwrap_or(0);
            let gauges = Gauges {
                upload_sessions_open: crate::util::to_u64(state.storage.sessions().len()),
                buffer_budget_available_bytes: state.budget.available_bytes(),
                disk_free_bytes: disk_free,
            };
            Ok(text(StatusCode::OK, state.metrics.render(gauges), "text/plain; version=0.0.4; charset=utf-8"))
        }
        (Resource::Revocations, Method::POST) => {
            let body = authenticated_body(state, request).await?;
            let revocation: RevocationBody = serde_json::from_slice(&body)
                .map_err(|_| CdnError::bad_request("bad_body", "Corps de requête invalide."))?;
            let valid_sub = !revocation.sub.is_empty()
                && revocation.sub.len() <= 64
                && !revocation.sub.chars().any(char::is_control);
            if !valid_sub {
                return Err(CdnError::bad_request("bad_body", "Identifiant d'utilisateur invalide."));
            }
            log.sub = Some(revocation.sub.clone());
            revoke(state, move |r, now| r.revoke_sub(&revocation.sub, revocation.until, now)).await?;
            Ok(no_content())
        }
        (Resource::Upload(tid), Method::DELETE) => {
            authenticated_body(state, request).await?;
            log.tid = Some(tid);
            if let Some(session) = state.storage.sessions().get(tid) {
                match session.phase_kind() {
                    PhaseKind::Completed => {
                        return Err(CdnError::conflict("upload_completed", "L'envoi est déjà enregistré."));
                    }
                    kind => {
                        // Le fichier terminé n'est supprimé que s'il provient
                        // de cette session (phase finalisée).
                        state.storage.abort(&session, kind == PhaseKind::Finalized).await;
                    }
                }
            }
            // Le ticket ne doit plus pouvoir rouvrir ce transfert.
            revoke(state, move |r, now| r.revoke_tid(tid, now)).await?;
            Ok(no_content())
        }
        _ => Err(CdnError::method_not_allowed()),
    }
}

/// Lit le corps (borné, avec délai) et vérifie la signature HMAC.
async fn authenticated_body(state: &AppState, request: Request<Incoming>) -> Result<Bytes, CdnError> {
    let (parts, body) = request.into_parts();
    let header = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned);
    let (timestamp, signature) = (header(TIMESTAMP_HEADER), header(SIGNATURE_HEADER));

    let collected = tokio::time::timeout(INTERNAL_BODY_TIMEOUT, Limited::new(body, MAX_INTERNAL_BODY).collect())
        .await
        .map_err(|_| CdnError::request_timeout())?
        .map_err(|e| CdnError::bad_request_cause("bad_body", "Corps de requête invalide.", e))?
        .to_bytes();

    let valid = state.config.internal_secret.verify(
        parts.method.as_str(),
        parts.uri.path(),
        timestamp.as_deref(),
        signature.as_deref(),
        &collected,
        now_unix(),
    );
    if !valid {
        return Err(CdnError::forbidden("bad_signature", "Signature interne invalide."));
    }
    Ok(collected)
}

async fn revoke<F>(state: &AppState, operation: F) -> Result<(), CdnError>
where
    F: FnOnce(&crate::revocation::Revocations, u64) -> Result<(), RevocationError> + Send + 'static,
{
    // La persistance écrit sur le disque : pool bloquant.
    let revocations = std::sync::Arc::clone(&state.revocations);
    let result = tokio::task::spawn_blocking(move || operation(&revocations, now_unix())).await;
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(RevocationError::Full)) => {
            Err(CdnError::unavailable("revocations_full", "Liste de révocation pleine.", 60))
        }
        Ok(Err(error)) => Err(CdnError::internal("révocation", error)),
        Err(join_error) => Err(CdnError::internal("tâche de révocation", join_error)),
    }
}
