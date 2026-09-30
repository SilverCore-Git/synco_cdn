//! Appels du CDN vers synco_api (cf. docs/plan/03-protocole.md#route-appelée-par-le-cdn-sur-synco_api).
//!
//! HTTP clair vers l'API sur le réseau local, requêtes signées HMAC
//! (`internal_auth`), délai par tentative, corps de réponse borné.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, StatusCode, header};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::Serialize;
use uuid::Uuid;

use crate::internal_auth::{InternalSecret, SIGNATURE_HEADER, TIMESTAMP_HEADER};
use crate::util::now_unix;

/// Taille maximale d'une réponse de l'API.
const MAX_RESPONSE_BYTES: usize = 1 << 20;
/// Attentes entre tentatives du rappel de fin d'envoi.
const RETRY_DELAYS: [Duration; 2] = [Duration::from_millis(200), Duration::from_millis(800)];

/// Issue du rappel de fin d'envoi.
#[derive(Debug)]
pub enum CallbackOutcome {
    /// L'API a enregistré le fichier ; corps = métadonnées JSON.
    Accepted(Bytes),
    /// L'API refuse (transfert inconnu, expiré, droits retirés…).
    Rejected { status: StatusCode },
    /// L'API est injoignable ou en erreur : à réessayer plus tard.
    Unavailable,
}

#[derive(Serialize)]
struct CompleteBody<'a> {
    tid: Uuid,
    fid: Uuid,
    size: u64,
    hash: &'a str,
}

#[derive(Debug, Clone)]
pub struct ApiClient {
    client: Client<HttpConnector, Full<Bytes>>,
    base_url: String,
    secret: Arc<InternalSecret>,
    timeout: Duration,
}

impl ApiClient {
    pub fn new(base_url: String, secret: Arc<InternalSecret>, timeout: Duration) -> Self {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(timeout));
        connector.set_nodelay(true);
        let client = Client::builder(TokioExecutor::new()).pool_idle_timeout(Duration::from_secs(30)).build(connector);
        Self { client, base_url, secret, timeout }
    }

    /// `POST /internal/cdn/uploads/{tid}/complete`, avec réessais sur erreur
    /// transitoire. Idempotent côté API.
    pub async fn complete_upload(&self, tid: Uuid, fid: Uuid, size: u64, hash: &str) -> CallbackOutcome {
        let path = format!("/internal/cdn/uploads/{}/complete", tid.hyphenated());
        let body = match serde_json::to_vec(&CompleteBody { tid, fid, size, hash }) {
            Ok(body) => Bytes::from(body),
            Err(error) => {
                tracing::error!(%error, "sérialisation du rappel impossible");
                return CallbackOutcome::Unavailable;
            }
        };

        let mut attempt = 0usize;
        loop {
            match self.post(&path, body.clone()).await {
                Some((status, response)) if status.is_success() => return CallbackOutcome::Accepted(response),
                Some((status, _)) if status.is_client_error() && status != StatusCode::TOO_MANY_REQUESTS => {
                    return CallbackOutcome::Rejected { status };
                }
                Some((status, _)) => tracing::warn!(%tid, %status, "rappel de fin d'envoi : réponse d'erreur"),
                None => tracing::warn!(%tid, "rappel de fin d'envoi : API injoignable"),
            }
            match RETRY_DELAYS.get(attempt) {
                Some(delay) => tokio::time::sleep(*delay).await,
                None => return CallbackOutcome::Unavailable,
            }
            attempt = attempt.saturating_add(1);
        }
    }

    /// `POST /internal/cdn/uploads/{tid}/abort` : libère le quota réservé
    /// côté API. Au mieux : l'API expire ses transferts de toute façon.
    pub async fn notify_abort(&self, tid: Uuid) {
        let path = format!("/internal/cdn/uploads/{}/abort", tid.hyphenated());
        match self.post(&path, Bytes::from_static(b"{}")).await {
            Some((status, _)) if status.is_success() || status == StatusCode::NOT_FOUND => {}
            Some((status, _)) => tracing::warn!(%tid, %status, "notification d'annulation refusée"),
            None => tracing::warn!(%tid, "notification d'annulation : API injoignable"),
        }
    }

    /// Une requête signée. `None` si l'API est injoignable, trop lente, ou
    /// si sa réponse est illisible ou trop grande.
    async fn post(&self, path: &str, body: Bytes) -> Option<(StatusCode, Bytes)> {
        let timestamp = now_unix();
        let signature = self.secret.sign(Method::POST.as_str(), path, timestamp, &body);
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("{}{path}", self.base_url))
            .header(header::CONTENT_TYPE, "application/json")
            .header(TIMESTAMP_HEADER, timestamp.to_string())
            .header(SIGNATURE_HEADER, signature)
            .body(Full::new(body))
            .ok()?;

        let exchange = async {
            let response = self.client.request(request).await.ok()?;
            let status = response.status();
            let bytes = Limited::new(response.into_body(), MAX_RESPONSE_BYTES).collect().await.ok()?.to_bytes();
            Some((status, bytes))
        };
        tokio::time::timeout(self.timeout, exchange).await.ok().flatten()
    }
}
