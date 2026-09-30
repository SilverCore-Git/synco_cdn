//! Routes d'envoi (cf. docs/plan/03-protocole.md#routes-publiques).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use http::header::CONTENT_LENGTH;
use http::{HeaderMap, Request, StatusCode};
use hyper::body::Incoming;
use serde::Serialize;
use uuid::Uuid;

use crate::api_client::CallbackOutcome;
use crate::error::CdnError;
use crate::http::respond::{HttpResponse, json, json_bytes, no_content};
use crate::state::{AppState, RequestLog};
use crate::storage::session::{CompleteStep, PartSlot, PhaseKind, UploadSession};
use crate::storage::writer::{PartWriteOptions, drain_body, write_part};
use crate::ticket::{Operation, Ticket};
use crate::util::{hex_decode, now_unix, parse_decimal_u64};

pub const PART_INDEX_HEADER: &str = "x-part-index";
pub const PART_SHA256_HEADER: &str = "x-part-sha256";

/// État d'une session, renvoyé à l'ouverture et sur `GET`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UploadStatus {
    tid: Uuid,
    size: u64,
    part_size: u64,
    part_count: u64,
    /// Plages inclusives de parts reçues.
    received_parts: Vec<[u64; 2]>,
    expires_at: u64,
}

fn status_of(session: &UploadSession) -> UploadStatus {
    UploadStatus {
        tid: session.tid,
        size: session.size,
        part_size: session.part_size,
        part_count: session.part_count,
        received_parts: session.received_ranges(),
        expires_at: session.expires_at(),
    }
}

/// Ticket d'envoi valide pour le transfert `tid`, et sa session.
fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    tid: Uuid,
    log: &mut RequestLog,
) -> Result<(Ticket, Arc<UploadSession>), CdnError> {
    let ticket = state.verify_ticket(headers, Operation::Upload, log)?;
    if ticket.tid != tid {
        return Err(state.wrong_target());
    }
    let session =
        state.storage.sessions().get(tid).ok_or(CdnError::not_found("upload_not_found", "Envoi introuvable."))?;
    if session.fid != ticket.fid {
        return Err(state.wrong_target());
    }
    // Un ticket renouvelé prolonge la session.
    session.extend_expiry(ticket.exp);
    session.touch(now_unix());
    Ok((ticket, session))
}

/// `POST /v1/uploads` : ouvre ou reprend une session.
pub async fn open(state: &AppState, headers: &HeaderMap, log: &mut RequestLog) -> Result<HttpResponse, CdnError> {
    let ticket = state.verify_ticket(headers, Operation::Upload, log)?;
    let opened = state.storage.open_upload(&ticket, now_unix()).await?;
    let status = if opened.created { StatusCode::CREATED } else { StatusCode::OK };
    Ok(json(status, &status_of(&opened.session)))
}

/// `GET /v1/uploads/{tid}` : parts déjà reçues (reprise).
pub fn status(
    state: &AppState,
    headers: &HeaderMap,
    tid: Uuid,
    log: &mut RequestLog,
) -> Result<HttpResponse, CdnError> {
    let (_, session) = authorize(state, headers, tid, log)?;
    Ok(json(StatusCode::OK, &status_of(&session)))
}

/// `PUT /v1/uploads/{tid}/part` : reçoit une part.
pub async fn part(
    state: &AppState,
    request: Request<Incoming>,
    tid: Uuid,
    log: &mut RequestLog,
) -> Result<HttpResponse, CdnError> {
    let (_, session) = authorize(state, request.headers(), tid, log)?;
    let headers = request.headers();

    let index = headers
        .get(PART_INDEX_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_decimal_u64)
        .ok_or(CdnError::bad_request("bad_part_index", "En-tête X-Part-Index manquant ou invalide."))?;
    let expected_len =
        session.part_len(index).ok_or(CdnError::bad_request("bad_part_index", "Index de part hors du fichier."))?;
    // Longueur annoncée incohérente : refus avant de lire le moindre octet.
    if let Some(declared) = headers.get(CONTENT_LENGTH) {
        let declared = declared.to_str().ok().and_then(parse_decimal_u64);
        if declared != Some(expected_len) {
            return Err(CdnError::bad_request("bad_part_length", "Taille de part différente de celle attendue."));
        }
    }
    let expected_hash = match headers.get(PART_SHA256_HEADER) {
        None => None,
        Some(value) => Some(
            value
                .to_str()
                .ok()
                .and_then(hex_decode)
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                .ok_or(CdnError::bad_request("bad_part_checksum", "En-tête X-Part-Sha256 invalide."))?,
        ),
    };

    let slot = session.acquire_part(index, state.config.max_parts_in_flight_per_transfer)?;
    let body = request.into_body();
    match slot {
        PartSlot::AlreadyReceived => {
            // Réessai d'une part déjà écrite : rien à réécrire.
            drain_body(body, expected_len, state.config.body_idle_timeout).await?;
            Ok(no_content())
        }
        PartSlot::Write(guard) => {
            let started = Instant::now();
            let options = PartWriteOptions {
                idle_timeout: state.config.body_idle_timeout,
                strict_durability: state.config.strict_durability,
            };
            let written = write_part(guard, index, body, expected_hash, &state.budget, options).await?;
            state.metrics.bytes_received.fetch_add(written, Ordering::Relaxed);
            state.metrics.part_write.observe(started.elapsed());
            log.bytes = written;
            Ok(no_content())
        }
    }
}

/// `POST /v1/uploads/{tid}/complete` : finalise et fait enregistrer le fichier.
pub async fn complete(
    state: &AppState,
    headers: &HeaderMap,
    tid: Uuid,
    log: &mut RequestLog,
) -> Result<HttpResponse, CdnError> {
    let (_, session) = authorize(state, headers, tid, log)?;

    let hash = match session.begin_complete()? {
        CompleteStep::Done { response } => return Ok(json_bytes(StatusCode::CREATED, response)),
        CompleteStep::Callback { hash } => hash,
        CompleteStep::Finalize(files) => match state.storage.finalize(&session, files.clone()).await {
            Ok(hash) => hash,
            Err(error) => {
                if error.code == "file_exists" {
                    // Un autre fichier occupe déjà cet identifiant : jamais écrasé.
                    state.storage.abort(&session, false).await;
                } else {
                    session.restore_open(files);
                }
                return Err(error);
            }
        },
    };

    let response = register(state, &session, hash).await?;
    Ok(json_bytes(StatusCode::CREATED, response))
}

/// Fait enregistrer le fichier finalisé par synco_api. Utilisé par
/// `complete` et par le balayage (client parti avant la fin).
pub async fn register(state: &AppState, session: &Arc<UploadSession>, hash: String) -> Result<bytes::Bytes, CdnError> {
    match state.api.complete_upload(session.tid, session.fid, session.size, &hash).await {
        CallbackOutcome::Accepted(response) => {
            session.set_completed(hash.clone(), response.clone());
            state.storage.mark_completed(session, hash).await;
            Ok(response)
        }
        CallbackOutcome::Rejected { status } => {
            tracing::warn!(tid = %session.tid, %status, "synco_api refuse l'enregistrement : fichier supprimé");
            state.storage.abort(session, true).await;
            Err(CdnError::conflict("upload_rejected", "L'enregistrement du fichier a été refusé."))
        }
        CallbackOutcome::Unavailable => {
            state.metrics.api_callback_failures.fetch_add(1, Ordering::Relaxed);
            Err(CdnError::unavailable("api_unavailable", "Enregistrement momentanément impossible, réessayez.", 5))
        }
    }
}

/// `DELETE /v1/uploads/{tid}` : abandon par le client.
pub async fn abort(
    state: &AppState,
    headers: &HeaderMap,
    tid: Uuid,
    log: &mut RequestLog,
) -> Result<HttpResponse, CdnError> {
    let (_, session) = authorize(state, headers, tid, log)?;
    match session.phase_kind() {
        PhaseKind::Open => {
            state.storage.abort(&session, false).await;
            // Libération du quota côté API, sans faire attendre le client.
            let api = state.api.clone();
            tokio::spawn(async move { api.notify_abort(tid).await });
            Ok(no_content())
        }
        PhaseKind::Aborted => Err(CdnError::not_found("upload_not_found", "Envoi introuvable.")),
        PhaseKind::Completing | PhaseKind::Finalized | PhaseKind::Completed => {
            Err(CdnError::conflict("upload_finalized", "L'envoi est déjà finalisé."))
        }
    }
}
