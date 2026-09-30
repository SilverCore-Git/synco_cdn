//! Stockage : sessions d'envoi, finalisation, fichiers terminés.
//!
//! Toutes les opérations disque passent par le pool de threads bloquants
//! (`run_blocking`) : un disque lent ne fige jamais les threads réseau.

pub mod layout;
pub mod reader;
pub mod recovery;
pub mod session;
pub mod space;
pub mod writer;

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

use rustix::fs::{CWD, RenameFlags};
use rustix::io::Errno;
use uuid::Uuid;

use crate::error::CdnError;
use crate::ticket::{Ticket, TicketScope};
use layout::Layout;
use session::{
    Phase, PhaseKind, RecordPhase, SessionFiles, UploadSession, file_hash, parts_file_len, sync_dir, write_record,
};
use space::{SpacePolicy, disk_usage, is_no_space, preallocate};
use writer::run_blocking;

/// Registre des sessions en mémoire.
#[derive(Debug, Default)]
pub struct Sessions {
    map: RwLock<HashMap<Uuid, Arc<UploadSession>>>,
}

impl Sessions {
    pub fn get(&self, tid: Uuid) -> Option<Arc<UploadSession>> {
        self.map.read().unwrap_or_else(PoisonError::into_inner).get(&tid).cloned()
    }

    pub fn len(&self) -> usize {
        self.map.read().unwrap_or_else(PoisonError::into_inner).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Insère la session, sauf si une autre existe déjà pour ce `tid`
    /// (renvoyée à la place).
    fn insert(&self, session: Arc<UploadSession>) -> Arc<UploadSession> {
        let mut map = self.map.write().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(map.entry(session.tid).or_insert(session))
    }

    fn remove(&self, tid: Uuid) {
        self.map.write().unwrap_or_else(PoisonError::into_inner).remove(&tid);
    }

    pub fn snapshot(&self) -> Vec<Arc<UploadSession>> {
        self.map.read().unwrap_or_else(PoisonError::into_inner).values().cloned().collect()
    }
}

/// Résultat de l'ouverture d'un envoi.
#[derive(Debug)]
pub struct Opened {
    pub session: Arc<UploadSession>,
    /// Faux si la session existait déjà (reprise).
    pub created: bool,
}

#[derive(Debug)]
pub struct Storage {
    layout: Layout,
    space: SpacePolicy,
    sessions: Sessions,
    max_open_sessions: usize,
}

impl Storage {
    /// Prépare le stockage : vérifie `data_dir`, crée `.cdn-uploads` et
    /// s'assure qu'ils sont sur le même système de fichiers (la
    /// finalisation doit être un simple `rename`).
    pub fn init(data_dir: &Path, space: SpacePolicy, max_open_sessions: usize) -> Result<Self, String> {
        let layout = Layout::new(data_dir);
        let meta =
            std::fs::metadata(data_dir).map_err(|e| format!("storage.data_dir ({}) : {e}", data_dir.display()))?;
        if !meta.is_dir() {
            return Err(format!("storage.data_dir ({}) n'est pas un répertoire", data_dir.display()));
        }
        std::fs::create_dir_all(layout.uploads_dir())
            .map_err(|e| format!("création de {} : {e}", layout.uploads_dir().display()))?;
        let uploads_meta = std::fs::metadata(layout.uploads_dir()).map_err(|e| e.to_string())?;
        use std::os::unix::fs::MetadataExt;
        if uploads_meta.dev() != meta.dev() {
            return Err(format!(
                "{} doit être sur le même système de fichiers que {}",
                layout.uploads_dir().display(),
                data_dir.display()
            ));
        }
        // Écriture test : un stockage en lecture seule doit empêcher le démarrage.
        let probe = layout.uploads_dir().join(".write-probe");
        std::fs::write(&probe, b"ok")
            .and_then(|()| std::fs::remove_file(&probe))
            .map_err(|e| format!("{} n'est pas accessible en écriture : {e}", layout.uploads_dir().display()))?;

        Ok(Self { layout, space, sessions: Sessions::default(), max_open_sessions })
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    pub fn sessions(&self) -> &Sessions {
        &self.sessions
    }

    pub fn space_policy(&self) -> SpacePolicy {
        self.space
    }

    /// Réinsère les sessions rechargées au démarrage.
    pub fn restore(&self, sessions: Vec<Arc<UploadSession>>) {
        for session in sessions {
            self.sessions.insert(session);
        }
    }

    /// Espace libre du stockage (0 si illisible).
    pub fn free_bytes(&self) -> u64 {
        disk_usage(self.layout.data_dir()).map(|u| u.available).unwrap_or(0)
    }

    /// Vrai si le stockage est utilisable (sonde `/readyz`).
    pub async fn is_ready(&self) -> bool {
        let dir = self.layout.uploads_dir().to_path_buf();
        let policy = self.space;
        run_blocking(move || {
            let usage = disk_usage(&dir)?;
            let writable = std::fs::metadata(&dir)?.is_dir();
            Ok(writable && policy.has_room(usage, 0))
        })
        .await
        .unwrap_or(false)
    }

    /// Ouvre (ou reprend) la session d'envoi décrite par `ticket`.
    pub async fn open_upload(&self, ticket: &Ticket, now: u64) -> Result<Opened, CdnError> {
        let TicketScope::Upload { size, part_size, part_count } = ticket.scope else {
            return Err(CdnError::forbidden("ticket_wrong_operation", "Ce ticket n'autorise pas cette opération."));
        };

        if let Some(existing) = self.sessions.get(ticket.tid) {
            return self.resume(existing, ticket);
        }
        if self.sessions.len() >= self.max_open_sessions {
            return Err(CdnError::unavailable("too_many_sessions", "Trop d'envois en cours, réessayez plus tard.", 30));
        }

        let layout = self.layout.clone();
        let policy = self.space;
        let (tid, fid) = (ticket.tid, ticket.fid);
        let record_seed =
            UploadSession::new(tid, fid, ticket.sub.clone(), size, part_size, ticket.exp, now, &[], Phase::Aborted)
                .ok_or(CdnError::bad_request("bad_geometry", "Géométrie d'envoi invalide."))?
                .record(RecordPhase::Open, None);

        let files =
            run_blocking(move || create_session_files(&layout, &policy, tid, fid, size, part_count, &record_seed))
                .await?;
        let files = match files {
            CreateOutcome::Created(files) => files,
            CreateOutcome::InProgress => {
                // Une ouverture concurrente du même tid est en train de créer
                // les fichiers : l'appelant réessaie.
                return Err(CdnError::unavailable("upload_initializing", "Envoi en cours d'initialisation.", 1));
            }
            CreateOutcome::FileExists => {
                return Err(CdnError::conflict("file_exists", "Ce fichier existe déjà."));
            }
            CreateOutcome::NoRoom => return Err(CdnError::insufficient_storage()),
        };

        let session =
            UploadSession::new(tid, fid, ticket.sub.clone(), size, part_size, ticket.exp, now, &[], Phase::Open(files))
                .ok_or(CdnError::bad_request("bad_geometry", "Géométrie d'envoi invalide."))?;
        let inserted = self.sessions.insert(Arc::new(session));
        Ok(Opened { session: inserted, created: true })
    }

    fn resume(&self, session: Arc<UploadSession>, ticket: &Ticket) -> Result<Opened, CdnError> {
        let TicketScope::Upload { size, part_size, .. } = ticket.scope else {
            return Err(CdnError::forbidden("ticket_wrong_operation", "Ce ticket n'autorise pas cette opération."));
        };
        if session.fid != ticket.fid || session.size != size || session.part_size != part_size {
            return Err(CdnError::conflict("upload_mismatch", "Ce transfert existe avec d'autres paramètres."));
        }
        if session.phase_kind() == PhaseKind::Aborted {
            return Err(CdnError::not_found("upload_not_found", "Envoi introuvable."));
        }
        session.extend_expiry(ticket.exp);
        Ok(Opened { session, created: false })
    }

    /// Finalisation disque : `fdatasync`, empreinte, enregistrement de la
    /// phase, déplacement sans écrasement, `fsync` du répertoire. En cas
    /// d'erreur, le fichier n'a pas été déplacé.
    pub async fn finalize(&self, session: &Arc<UploadSession>, files: SessionFiles) -> Result<String, CdnError> {
        let layout = self.layout.clone();
        let mut record = session.record(RecordPhase::Finalized, None);
        let (tid, fid, count) = (session.tid, session.fid, session.part_count);

        let result = tokio::task::spawn_blocking(move || -> io::Result<String> {
            files.data.sync_data()?;
            let hash = file_hash(&files.parts, count)?;

            // La phase « finalisée » est enregistrée AVANT le déplacement :
            // après un arrêt brutal entre les deux, la reprise sait terminer
            // le déplacement (cf. recovery).
            record.hash = Some(hash.clone());
            write_record(&layout.session_record(tid), &record)?;
            rename_no_replace(&layout.session_data(tid), &layout.final_path(fid))?;

            // Le fichier est en place : un échec ici n'annule rien.
            if let Err(error) = sync_dir(layout.data_dir()) {
                tracing::warn!(%tid, %error, "fsync du répertoire de stockage impossible");
            }
            let _ = std::fs::remove_file(layout.session_parts(tid));
            Ok(hash)
        })
        .await;

        match result {
            Ok(Ok(hash)) => {
                session.set_finalized(hash.clone());
                Ok(hash)
            }
            Ok(Err(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
                Err(CdnError::conflict("file_exists", "Ce fichier existe déjà."))
            }
            Ok(Err(error)) if is_no_space(&error) => Err(CdnError::insufficient_storage()),
            Ok(Err(error)) => Err(CdnError::internal("finalisation", error)),
            Err(join_error) => Err(CdnError::internal("tâche de finalisation", join_error)),
        }
    }

    /// Enregistre la phase « terminée » (au mieux : l'API a déjà confirmé,
    /// et son traitement est idempotent si on la rappelle après une reprise).
    pub async fn mark_completed(&self, session: &Arc<UploadSession>, hash: String) {
        let path = self.layout.session_record(session.tid);
        let record = session.record(RecordPhase::Completed, Some(hash));
        if let Err(error) = run_blocking(move || write_record(&path, &record)).await {
            tracing::warn!(tid = %session.tid, %error, "enregistrement de la phase terminée impossible");
        }
    }

    /// Annule une session et supprime ses fichiers. Si `delete_final`, le
    /// fichier déjà déplacé à sa place définitive est supprimé aussi (refus
    /// de l'API, annulation d'un envoi finalisé mais non enregistré).
    pub async fn abort(&self, session: &Arc<UploadSession>, delete_final: bool) {
        session.set_aborted();
        self.sessions.remove(session.tid);
        let layout = self.layout.clone();
        let (tid, fid) = (session.tid, session.fid);
        let result = run_blocking(move || {
            for path in [layout.session_data(tid), layout.session_parts(tid), layout.session_record(tid)] {
                remove_if_exists(&path)?;
            }
            if delete_final {
                remove_if_exists(&layout.final_path(fid))?;
            }
            Ok(())
        })
        .await;
        if let Err(error) = result {
            tracing::warn!(%tid, %error, "suppression des fichiers d'une session annulée incomplète");
        }
    }

    /// Oublie une session terminée (ses fichiers de suivi sont supprimés,
    /// le fichier terminé reste).
    pub async fn forget_completed(&self, session: &Arc<UploadSession>) {
        self.sessions.remove(session.tid);
        let path = self.layout.session_record(session.tid);
        if let Err(error) = run_blocking(move || remove_if_exists(&path)).await {
            tracing::warn!(tid = %session.tid, %error, "suppression d'une session terminée impossible");
        }
    }

    pub fn final_path(&self, fid: Uuid) -> PathBuf {
        self.layout.final_path(fid)
    }
}

enum CreateOutcome {
    Created(SessionFiles),
    InProgress,
    FileExists,
    NoRoom,
}

/// Crée les fichiers d'une nouvelle session. Ordre : données (création
/// exclusive, qui sert de verrou contre une ouverture concurrente), parts,
/// puis enregistrement de session en dernier — un fichier sans
/// enregistrement est un reste de création interrompue, nettoyé au démarrage.
fn create_session_files(
    layout: &Layout,
    policy: &SpacePolicy,
    tid: Uuid,
    fid: Uuid,
    size: u64,
    part_count: u64,
    record: &session::SessionRecord,
) -> io::Result<CreateOutcome> {
    if layout.final_path(fid).exists() {
        return Ok(CreateOutcome::FileExists);
    }
    if !policy.has_room(disk_usage(layout.uploads_dir())?, size) {
        return Ok(CreateOutcome::NoRoom);
    }

    let data_path = layout.session_data(tid);
    let data = match OpenOptions::new().read(true).write(true).create_new(true).open(&data_path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(CreateOutcome::InProgress),
        Err(error) => return Err(error),
    };

    let created = (|| -> io::Result<SessionFiles> {
        preallocate(&data, size)?;
        let parts_path = layout.session_parts(tid);
        let parts = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&parts_path)?;
        parts.set_len(parts_file_len(part_count).ok_or_else(|| io::Error::other("nombre de parts hors bornes"))?)?;
        write_record(&layout.session_record(tid), record)?;
        Ok(SessionFiles { data: Arc::new(data), parts: Arc::new(parts) })
    })();

    match created {
        Ok(files) => Ok(CreateOutcome::Created(files)),
        Err(error) => {
            let _ = std::fs::remove_file(&data_path);
            let _ = std::fs::remove_file(layout.session_parts(tid));
            let _ = std::fs::remove_file(layout.session_record(tid));
            if is_no_space(&error) { Ok(CreateOutcome::NoRoom) } else { Err(error) }
        }
    }
}

/// Renomme `from` en `to` sans jamais écraser `to` (`RENAME_NOREPLACE`).
/// Repli pour les systèmes de fichiers qui ne le permettent pas : lien dur
/// (qui échoue aussi si `to` existe) puis suppression de `from`.
pub fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    match rustix::fs::renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE) {
        Ok(()) => Ok(()),
        Err(errno) if errno == Errno::INVAL || errno == Errno::NOSYS || errno == Errno::OPNOTSUPP => {
            std::fs::hard_link(from, to)?;
            std::fs::remove_file(from)
        }
        Err(errno) => Err(errno.into()),
    }
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rename_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        std::fs::write(&a, b"new").unwrap();
        std::fs::write(&b, b"old").unwrap();
        let error = rename_no_replace(&a, &b).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&b).unwrap(), b"old");
        std::fs::remove_file(&b).unwrap();
        rename_no_replace(&a, &b).unwrap();
        assert_eq!(std::fs::read(&b).unwrap(), b"new");
        assert!(!a.exists());
    }
}
