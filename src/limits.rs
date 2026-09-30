//! Budget mémoire des tampons d'E/S (cf. docs/plan/04-moteur-io.md#budget-mémoire-et-contre-pression).
//!
//! Chaque lot d'environ 1 Mio (fragments d'une part en cours d'écriture,
//! bloc de téléchargement en cours d'envoi) doit détenir un jeton du budget. Quand le disque est plus
//! lent que le réseau, les jetons s'épuisent, les tâches cessent de lire
//! leur socket et le contrôle de flux TCP/HTTP2 ralentit le client : la
//! mémoire du service reste bornée quelle que soit la charge.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::CdnError;

/// Taille d'un tampon d'E/S.
pub const BUFFER_UNIT: usize = 1 << 20;
/// Jetons minimum, pour qu'une configuration trop basse reste utilisable.
const MIN_PERMITS: usize = 8;

/// Sémaphore dont chaque jeton représente `BUFFER_UNIT` octets.
#[derive(Debug, Clone)]
pub struct BufferBudget {
    semaphore: Arc<Semaphore>,
    total: usize,
}

impl BufferBudget {
    pub fn new(budget_bytes: u64) -> Self {
        let units = budget_bytes.checked_div(crate::util::to_u64(BUFFER_UNIT)).unwrap_or(0);
        let permits =
            usize::try_from(units).unwrap_or(Semaphore::MAX_PERMITS).clamp(MIN_PERMITS, Semaphore::MAX_PERMITS);
        Self { semaphore: Arc::new(Semaphore::new(permits)), total: permits }
    }

    /// Attend un jeton. Le sémaphore n'est jamais fermé : l'erreur est
    /// théorique, mais traitée.
    pub async fn acquire(&self) -> Result<OwnedSemaphorePermit, CdnError> {
        Arc::clone(&self.semaphore).acquire_owned().await.map_err(|e| CdnError::internal("budget mémoire", e))
    }

    /// Octets encore disponibles dans le budget.
    pub fn available_bytes(&self) -> u64 {
        crate::util::to_u64(self.semaphore.available_permits().saturating_mul(BUFFER_UNIT))
    }

    pub fn total_bytes(&self) -> u64 {
        crate::util::to_u64(self.total.saturating_mul(BUFFER_UNIT))
    }
}

/// Bloc de données lu depuis le disque, dont le jeton est rendu quand hyper
/// a fini de l'envoyer (la mémoire reste comptée tant qu'elle existe).
#[derive(Debug)]
pub struct BudgetedBlock {
    pub data: Vec<u8>,
    pub _permit: OwnedSemaphorePermit,
}

impl AsRef<[u8]> for BudgetedBlock {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn budget_is_bounded_and_released() {
        let budget = BufferBudget::new(8 << 20);
        assert_eq!(budget.total_bytes(), 8 << 20);
        let mut permits = Vec::new();
        for _ in 0..8 {
            permits.push(budget.acquire().await.unwrap());
        }
        assert_eq!(budget.available_bytes(), 0);
        // Un neuvième jeton attend.
        let waiting = tokio::time::timeout(std::time::Duration::from_millis(20), budget.acquire()).await;
        assert!(waiting.is_err());
        drop(permits);
        assert_eq!(budget.available_bytes(), 8 << 20);
    }
}
