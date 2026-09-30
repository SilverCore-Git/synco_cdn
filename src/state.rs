//! État partagé par toutes les requêtes.

use std::sync::{Arc, PoisonError, RwLock};

use http::HeaderMap;
use http::header::AUTHORIZATION;
use uuid::Uuid;

use crate::api_client::ApiClient;
use crate::config::Config;
use crate::error::CdnError;
use crate::http::cors::CorsPolicy;
use crate::limits::BufferBudget;
use crate::metrics::Metrics;
use crate::revocation::Revocations;
use crate::storage::Storage;
use crate::ticket::{Operation, Ticket, TicketError, TicketVerifier};
use crate::util::now_unix;

/// Informations d'une requête, reportées dans sa ligne de journal.
#[derive(Debug, Default)]
pub struct RequestLog {
    pub tid: Option<Uuid>,
    pub fid: Option<Uuid>,
    pub sub: Option<String>,
    pub bytes: u64,
}

#[derive(Debug)]
pub struct AppState {
    pub config: Arc<Config>,
    /// Clés de tickets et origines CORS : rechargeables (`SIGHUP`).
    tickets: RwLock<Arc<TicketVerifier>>,
    cors: RwLock<Arc<CorsPolicy>>,
    pub revocations: Arc<Revocations>,
    pub storage: Storage,
    pub budget: BufferBudget,
    pub metrics: Arc<Metrics>,
    pub api: ApiClient,
}

impl AppState {
    pub fn new(
        config: Arc<Config>,
        tickets: TicketVerifier,
        revocations: Revocations,
        storage: Storage,
        api: ApiClient,
    ) -> Self {
        let cors = CorsPolicy::new(&config.cors_allowed_origins);
        Self {
            budget: BufferBudget::new(config.buffer_budget_bytes),
            tickets: RwLock::new(Arc::new(tickets)),
            cors: RwLock::new(Arc::new(cors)),
            config,
            revocations: Arc::new(revocations),
            storage,
            metrics: Arc::new(Metrics::default()),
            api,
        }
    }

    pub fn tickets(&self) -> Arc<TicketVerifier> {
        Arc::clone(&self.tickets.read().unwrap_or_else(PoisonError::into_inner))
    }

    pub fn cors(&self) -> Arc<CorsPolicy> {
        Arc::clone(&self.cors.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Applique les parties rechargeables d'une nouvelle configuration :
    /// clés de tickets et origines CORS. Le reste exige un redémarrage.
    pub fn reload(&self, config: &Config) -> Result<(), String> {
        let verifier = TicketVerifier::new(&config.ticket_keys, config.ticket_policy)?;
        *self.tickets.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(verifier);
        *self.cors.write().unwrap_or_else(PoisonError::into_inner) =
            Arc::new(CorsPolicy::new(&config.cors_allowed_origins));
        Ok(())
    }

    /// Vérifie le ticket de l'en-tête `Authorization: Bearer …` pour
    /// l'opération `op`, révocations comprises, et renseigne le journal.
    pub fn verify_ticket(&self, headers: &HeaderMap, op: Operation, log: &mut RequestLog) -> Result<Ticket, CdnError> {
        let token = bearer(headers).unwrap_or_default();
        let result = self.tickets().verify(token, op, now_unix()).and_then(|ticket| {
            if self.revocations.is_revoked(&ticket) { Err(TicketError::Revoked) } else { Ok(ticket) }
        });
        match result {
            Ok(ticket) => {
                log.sub = Some(ticket.sub.clone());
                log.tid = Some(ticket.tid);
                log.fid = Some(ticket.fid);
                Ok(ticket)
            }
            Err(error) => Err(self.reject(error)),
        }
    }

    /// Le ticket valide ne couvre pas la ressource demandée.
    pub fn wrong_target(&self) -> CdnError {
        self.reject(TicketError::WrongTarget)
    }

    fn reject(&self, error: TicketError) -> CdnError {
        self.metrics.record_ticket_rejection(error.code());
        error.into()
    }
}

/// Jeton de l'en-tête `Authorization: Bearer <jeton>` (schéma insensible à la casse).
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn bearer_extraction() {
        let mut headers = HeaderMap::new();
        assert_eq!(bearer(&headers), None);
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer abc"));
        assert_eq!(bearer(&headers), Some("abc"));
        headers.insert(AUTHORIZATION, HeaderValue::from_static("bearer  abc "));
        assert_eq!(bearer(&headers), Some("abc"));
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert_eq!(bearer(&headers), None);
    }
}
