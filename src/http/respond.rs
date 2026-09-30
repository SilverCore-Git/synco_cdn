//! Construction des réponses. Aucune de ces fonctions ne peut échouer : les
//! valeurs d'en-têtes dynamiques sont ASCII par construction, et un échec
//! éventuel omet simplement l'en-tête.

use bytes::Bytes;
use http::header::{CACHE_CONTROL, CONTENT_RANGE, CONTENT_TYPE, RETRY_AFTER};
use http::{HeaderName, HeaderValue, Response, StatusCode};
use serde::Serialize;

use crate::body::{ResponseBody, empty, full};
use crate::error::CdnError;

pub type HttpResponse = Response<ResponseBody>;

pub fn with_status(status: StatusCode, body: ResponseBody) -> HttpResponse {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
}

/// En-tête dont la valeur est construite dynamiquement.
pub fn set_header(response: &mut HttpResponse, name: HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        response.headers_mut().insert(name, value);
    }
}

pub fn no_content() -> HttpResponse {
    with_status(StatusCode::NO_CONTENT, empty())
}

pub fn json<T: Serialize>(status: StatusCode, value: &T) -> HttpResponse {
    match serde_json::to_vec(value) {
        Ok(bytes) => json_bytes(status, Bytes::from(bytes)),
        Err(error) => error_response(&CdnError::internal("sérialisation JSON", error)),
    }
}

/// Corps JSON déjà sérialisé (réponse de l'API relayée telle quelle).
pub fn json_bytes(status: StatusCode, bytes: Bytes) -> HttpResponse {
    let mut response = with_status(status, full(bytes));
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub fn text(status: StatusCode, body: String, content_type: &'static str) -> HttpResponse {
    let mut response = with_status(status, full(body));
    response.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response.headers_mut().insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    message: &'a str,
}

/// `{ "error": code, "message": texte }`, plus `Retry-After` et
/// `Content-Range` si l'erreur les demande.
pub fn error_response(error: &CdnError) -> HttpResponse {
    let body = ErrorBody { error: error.code, message: error.message };
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    let mut response = json_bytes(error.status, Bytes::from(bytes));
    if let Some(seconds) = error.retry_after {
        response.headers_mut().insert(RETRY_AFTER, HeaderValue::from(seconds));
    }
    if let Some(size) = error.unsatisfied_range_size {
        set_header(&mut response, CONTENT_RANGE, &format!("bytes */{size}"));
    }
    response
}
