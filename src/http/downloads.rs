//! Route de téléchargement (cf. docs/plan/03-protocole.md#get-et-head-v1filesfid--lire-un-fichier).

use std::sync::Arc;

use http::header::{
    ACCEPT_RANGES, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, IF_RANGE,
    RANGE,
};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use uuid::Uuid;

use crate::body::empty;
use crate::config::DownloadMode;
use crate::error::CdnError;
use crate::http::respond::{HttpResponse, set_header, with_status};
use crate::range::{RangeRequest, parse_range};
use crate::state::{AppState, RequestLog};
use crate::storage::reader::{open_final, stream_range};
use crate::storage::writer::run_blocking;
use crate::ticket::{Operation, TicketScope};

/// En-tête de délégation de l'envoi à nginx (mode `accel`).
const X_ACCEL_REDIRECT: HeaderName = HeaderName::from_static("x-accel-redirect");

/// `GET` / `HEAD /v1/files/{fid}`.
pub async fn get(
    state: &AppState,
    headers: &HeaderMap,
    fid: Uuid,
    head_only: bool,
    log: &mut RequestLog,
) -> Result<HttpResponse, CdnError> {
    let ticket = state.verify_ticket(headers, Operation::Download, log)?;
    if ticket.fid != fid {
        return Err(state.wrong_target());
    }
    let TicketScope::Download { size, mtime_ns } = ticket.scope else {
        return Err(state.wrong_target());
    };

    let path = state.storage.final_path(fid);
    let opened = run_blocking(move || open_final(&path))
        .await?
        .ok_or(CdnError::not_found("file_not_found", "Fichier introuvable."))?;

    // Le fichier a changé depuis l'émission du ticket (édition, réenvoi) :
    // des plages lues maintenant viendraient d'une autre version.
    if opened.size != size || opened.mtime_ns != mtime_ns {
        return Err(CdnError::conflict("file_changed", "Le fichier a été modifié, redemandez un ticket."));
    }

    let etag = format!("\"{}-{}-{}\"", fid.hyphenated(), opened.size, opened.mtime_ns);

    if state.config.download_mode == DownloadMode::Accel {
        // nginx lit le fichier par sendfile et gère lui-même Range.
        let mut response = with_status(StatusCode::OK, empty());
        common_headers(&mut response, &etag);
        set_header(&mut response, X_ACCEL_REDIRECT, &format!("{}{}.enc", state.config.accel_prefix, fid.hyphenated()));
        return Ok(response);
    }

    // If-Range : si la version a changé, la plage est ignorée (fichier entier).
    let if_range_matches = headers.get(IF_RANGE).is_none_or(|value| value.to_str().is_ok_and(|v| v == etag));
    let range_header = if if_range_matches { headers.get(RANGE).and_then(|v| v.to_str().ok()) } else { None };

    let (status, start, end) = match parse_range(range_header, opened.size) {
        RangeRequest::Full => (StatusCode::OK, 0, opened.size),
        RangeRequest::Partial { start, end } => (StatusCode::PARTIAL_CONTENT, start, end),
        RangeRequest::Unsatisfiable => return Err(CdnError::range_not_satisfiable(opened.size)),
    };
    let length = end.saturating_sub(start);

    let body = if head_only || length == 0 {
        empty()
    } else {
        stream_range(Arc::clone(&opened.file), start, end, state.budget.clone(), Arc::clone(&state.metrics)).boxed()
    };

    let mut response = with_status(status, body);
    common_headers(&mut response, &etag);
    response.headers_mut().insert(CONTENT_LENGTH, HeaderValue::from(length));
    if status == StatusCode::PARTIAL_CONTENT {
        set_header(&mut response, CONTENT_RANGE, &format!("bytes {start}-{}/{}", end.saturating_sub(1), opened.size));
    }
    log.bytes = length;
    Ok(response)
}

/// Le contenu est toujours du chiffré opaque : jamais de type réel ni
/// d'affichage dans le navigateur.
fn common_headers(response: &mut HttpResponse, etag: &str) {
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    headers.insert(CONTENT_DISPOSITION, HeaderValue::from_static("attachment"));
    headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    set_header(response, ETAG, etag);
}
