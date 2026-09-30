//! Liste de révocation des tickets (cf. docs/plan/02-tickets.md#révocation).
//!
//! Deux sortes d'entrées :
//! - par utilisateur (`sub`) : tout ticket de cet utilisateur émis avant
//!   `until` est refusé (bannissement) ;
//! - par transfert (`tid`) : tout ticket de ce transfert est refusé
//!   (annulation par l'API).
//!
//! Chaque entrée expire après la durée de vie maximale d'un ticket : passé
//! ce délai, aucun ticket qu'elle vise ne peut plus être valide. La liste
//! est bornée et persistée (écriture atomique) pour survivre à un
//! redémarrage.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ticket::Ticket;

/// Nombre maximal d'entrées de chaque sorte.
const MAX_ENTRIES: usize = 100_000;

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    /// `sub` → (révoqué jusqu'à `until`, entrée supprimable après `expires_at`).
    subs: HashMap<String, (u64, u64)>,
    /// `tid` → entrée supprimable après `expires_at`.
    tids: HashMap<Uuid, u64>,
}

/// Liste de révocation partagée entre tous les threads.
#[derive(Debug)]
pub struct Revocations {
    state: RwLock<State>,
    path: PathBuf,
    /// Durée de conservation d'une entrée (durée de vie max. d'un ticket + marge).
    retention_secs: u64,
}

/// La liste est pleine : l'appelant doit réessayer plus tard.
#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    #[error("liste de révocation pleine")]
    Full,
    #[error("écriture de la liste de révocation : {0}")]
    Io(#[from] std::io::Error),
    #[error("verrou de la liste de révocation empoisonné")]
    Poisoned,
}

impl Revocations {
    /// Charge la liste depuis `path` (absente = vide ; illisible = vide, avec
    /// un avertissement : mieux vaut perdre des révocations qui expirent de
    /// toute façon en une heure que refuser de démarrer).
    pub fn load(path: PathBuf, retention_secs: u64) -> Self {
        let state = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|error| {
                tracing::warn!(%error, "liste de révocation illisible, ignorée");
                State::default()
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(error) => {
                tracing::warn!(%error, "liste de révocation inaccessible, ignorée");
                State::default()
            }
        };
        Self { state: RwLock::new(state), path, retention_secs }
    }

    /// Vrai si le ticket est révoqué. En cas de verrou empoisonné (panique
    /// d'un autre thread pendant une écriture), on refuse par prudence.
    pub fn is_revoked(&self, ticket: &Ticket) -> bool {
        let Ok(state) = self.state.read() else {
            return true;
        };
        if state.tids.contains_key(&ticket.tid) {
            return true;
        }
        matches!(state.subs.get(&ticket.sub), Some((until, _)) if ticket.iat <= *until)
    }

    /// Révoque les tickets de `sub` émis au plus tard à `until`.
    pub fn revoke_sub(&self, sub: &str, until: u64, now: u64) -> Result<(), RevocationError> {
        let expires_at = until.max(now).saturating_add(self.retention_secs);
        self.mutate(now, |state| {
            if state.subs.len() >= MAX_ENTRIES && !state.subs.contains_key(sub) {
                return Err(RevocationError::Full);
            }
            let entry = state.subs.entry(sub.to_owned()).or_insert((until, expires_at));
            entry.0 = entry.0.max(until);
            entry.1 = entry.1.max(expires_at);
            Ok(())
        })
    }

    /// Révoque tous les tickets du transfert `tid`.
    pub fn revoke_tid(&self, tid: Uuid, now: u64) -> Result<(), RevocationError> {
        let expires_at = now.saturating_add(self.retention_secs);
        self.mutate(now, |state| {
            if state.tids.len() >= MAX_ENTRIES && !state.tids.contains_key(&tid) {
                return Err(RevocationError::Full);
            }
            state.tids.insert(tid, expires_at);
            Ok(())
        })
    }

    /// Supprime les entrées expirées et persiste si quelque chose a changé.
    pub fn prune(&self, now: u64) -> Result<(), RevocationError> {
        let changed = {
            let mut state = self.state.write().map_err(|_| RevocationError::Poisoned)?;
            let before = state.subs.len().saturating_add(state.tids.len());
            state.subs.retain(|_, (_, expires_at)| *expires_at > now);
            state.tids.retain(|_, expires_at| *expires_at > now);
            before != state.subs.len().saturating_add(state.tids.len())
        };
        if changed {
            self.persist()?;
        }
        Ok(())
    }

    fn mutate(
        &self,
        now: u64,
        change: impl FnOnce(&mut State) -> Result<(), RevocationError>,
    ) -> Result<(), RevocationError> {
        {
            let mut state = self.state.write().map_err(|_| RevocationError::Poisoned)?;
            state.subs.retain(|_, (_, expires_at)| *expires_at > now);
            state.tids.retain(|_, expires_at| *expires_at > now);
            change(&mut state)?;
        }
        self.persist()
    }

    /// Écriture atomique : fichier temporaire, `fsync`, puis `rename`.
    fn persist(&self) -> Result<(), RevocationError> {
        let bytes = {
            let state = self.state.read().map_err(|_| RevocationError::Poisoned)?;
            serde_json::to_vec(&*state).map_err(|e| RevocationError::Io(e.into()))?
        };
        let tmp = self.path.with_extension("json.tmp");
        let mut file = fs::File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ticket::TicketScope;

    fn ticket(sub: &str, tid: Uuid, iat: u64) -> Ticket {
        Ticket {
            tid,
            fid: Uuid::nil(),
            sub: sub.to_owned(),
            iat,
            exp: iat.saturating_add(100),
            scope: TicketScope::Download { size: 0, mtime_ns: 0 },
        }
    }

    #[test]
    fn revocations_apply_and_persist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revocations.json");
        let tid = Uuid::from_u128(1);
        {
            let r = Revocations::load(path.clone(), 3600);
            r.revoke_sub("bob", 500, 500).unwrap();
            r.revoke_tid(tid, 500).unwrap();
            assert!(r.is_revoked(&ticket("bob", Uuid::nil(), 400)));
            assert!(!r.is_revoked(&ticket("bob", Uuid::nil(), 501)), "émis après la révocation");
            assert!(!r.is_revoked(&ticket("alice", Uuid::nil(), 400)));
            assert!(r.is_revoked(&ticket("alice", tid, 400)));
        }
        // Rechargée depuis le disque.
        let r = Revocations::load(path, 3600);
        assert!(r.is_revoked(&ticket("bob", Uuid::nil(), 400)));
        assert!(r.is_revoked(&ticket("alice", tid, 400)));
        // Expirée après la rétention.
        r.prune(500 + 3601).unwrap();
        assert!(!r.is_revoked(&ticket("bob", Uuid::nil(), 400)));
        assert!(!r.is_revoked(&ticket("alice", tid, 400)));
    }

    #[test]
    fn corrupted_file_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revocations.json");
        fs::write(&path, b"{not json").unwrap();
        let r = Revocations::load(path, 3600);
        assert!(!r.is_revoked(&ticket("bob", Uuid::nil(), 1)));
    }
}
