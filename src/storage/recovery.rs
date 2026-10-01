//! Reprise après redémarrage (cf. docs/plan/05-robustesse-securite.md#reprise-après-redémarrage).
//!
//! Au démarrage, `.cdn-uploads/` est parcouru :
//! - session ouverte expirée depuis plus de `ORPHAN_GRACE_SECS` : supprimée ;
//! - session ouverte : rechargée avec l'état de ses parts ;
//! - session finalisée : déplacement du fichier terminé si l'arrêt a eu
//!   lieu entre l'enregistrement de la phase et le déplacement ; le rappel
//!   de l'API sera fait par le balayage ;
//! - session terminée : rechargée (pour répondre à un `complete` rejoué)
//!   jusqu'à son expiration ;
//! - tout fichier sans enregistrement de session valide (création
//!   interrompue, fichier temporaire) : supprimé.
//!
//! Une incohérence n'arrête jamais le démarrage : la session concernée est
//! supprimée et un avertissement journalisé. Le client recommencera.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;

use uuid::Uuid;

use super::layout::Layout;
use super::rename_no_replace;
use super::session::{
    MAX_RECORD_BYTES, Phase, RecordPhase, SessionFiles, SessionRecord, UploadSession, parts_file_len, read_markers,
};
use crate::ticket::part_count;

/// Délai de grâce après expiration avant suppression d'une session ouverte.
pub const ORPHAN_GRACE_SECS: u64 = 24 * 3600;

/// Recharge les sessions persistées. Fonction bloquante (E/S disque).
pub fn recover(layout: &Layout, now: u64) -> Vec<Arc<UploadSession>> {
    let entries = match fs::read_dir(layout.uploads_dir()) {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(%error, "lecture du répertoire des envois impossible");
            return Vec::new();
        }
    };

    let mut sessions = Vec::new();
    let mut kept: HashSet<Uuid> = HashSet::new();
    let mut others = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        match parse_name(&name) {
            Some((tid, "session")) => match load_session(layout, tid, &path, now) {
                Some(session) => {
                    kept.insert(tid);
                    sessions.push(Arc::new(session));
                }
                None => remove_session_files(layout, tid),
            },
            _ => others.push(path),
        }
    }

    // Restes : fichiers de session orphelins, temporaires, inconnus.
    for path in others {
        let name = path.file_name().unwrap_or_default();
        if name == OsStr::new("revocations.json") {
            continue;
        }
        let orphan = match parse_name(name) {
            Some((tid, "data" | "parts")) => !kept.contains(&tid),
            _ => true,
        };
        if orphan && let Err(error) = fs::remove_file(&path) {
            tracing::warn!(path = %path.display(), %error, "suppression d'un fichier orphelin impossible");
        }
    }

    tracing::info!(sessions = sessions.len(), "sessions d'envoi rechargées");
    sessions
}

/// `<uuid>.<extension>` → (uuid, extension).
fn parse_name(name: &OsStr) -> Option<(Uuid, &str)> {
    let name = name.to_str()?;
    let (stem, extension) = name.split_once('.')?;
    let tid = Uuid::try_parse(stem).ok()?;
    // Forme canonique uniquement (celle que le service écrit).
    (tid.hyphenated().to_string() == stem).then_some((tid, extension))
}

fn read_record(path: &Path) -> io::Result<SessionRecord> {
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(MAX_RECORD_BYTES).read_to_end(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

fn load_session(layout: &Layout, tid: Uuid, path: &Path, now: u64) -> Option<UploadSession> {
    let record = match read_record(path) {
        Ok(record) if record.tid == tid && record.is_supported_version() => record,
        Ok(_) => {
            tracing::warn!(%tid, "enregistrement de session incohérent, supprimé");
            return None;
        }
        Err(error) => {
            tracing::warn!(%tid, %error, "enregistrement de session illisible, supprimé");
            return None;
        }
    };
    let expired_long_ago = now > record.expires_at.saturating_add(ORPHAN_GRACE_SECS);

    let phase = match record.phase {
        RecordPhase::Open => {
            if expired_long_ago {
                tracing::info!(%tid, "session expirée, supprimée");
                return None;
            }
            return load_open(layout, &record, now);
        }
        RecordPhase::Finalized => {
            let hash = record.hash.clone()?;
            if !complete_move(layout, &record) {
                return None;
            }
            Phase::Finalized { hash }
        }
        RecordPhase::Completed => {
            if now > record.expires_at {
                // L'enregistrement n'est plus utile ; le fichier terminé reste.
                let _ = fs::remove_file(path);
                return None;
            }
            Phase::Completed { hash: record.hash.clone()?, response: None }
        }
    };
    UploadSession::new(tid, record.fid, record.sub, record.size, record.part_size, record.expires_at, now, &[], phase)
}

/// Termine un déplacement interrompu. Faux si la session est irrécupérable.
fn complete_move(layout: &Layout, record: &SessionRecord) -> bool {
    let data = layout.session_data(record.tid);
    let final_path = layout.final_path(record.fid);
    if data.exists() {
        match rename_no_replace(&data, &final_path) {
            Ok(()) => {
                let _ = fs::remove_file(layout.session_parts(record.tid));
                true
            }
            Err(error) => {
                // Un autre fichier occupe la place : on ne l'écrase jamais.
                tracing::warn!(tid = %record.tid, %error, "déplacement du fichier finalisé impossible, session supprimée");
                false
            }
        }
    } else if final_path.exists() {
        true
    } else {
        tracing::warn!(tid = %record.tid, "fichier finalisé introuvable, session supprimée");
        false
    }
}

fn load_open(layout: &Layout, record: &SessionRecord, now: u64) -> Option<UploadSession> {
    let count = part_count(record.size, record.part_size)?;
    let data_path = layout.session_data(record.tid);
    let parts_path = layout.session_parts(record.tid);

    let consistent = fs::metadata(&data_path).is_ok_and(|m| m.len() == record.size)
        && fs::metadata(&parts_path).is_ok_and(|m| Some(m.len()) == parts_file_len(count));
    if !consistent {
        tracing::warn!(tid = %record.tid, "fichiers de session incohérents, supprimés");
        return None;
    }

    let files = SessionFiles::open(&data_path, &parts_path).ok()?;
    let markers = read_markers(&files.parts, count).ok()?;
    UploadSession::new(
        record.tid,
        record.fid,
        record.sub.clone(),
        record.size,
        record.part_size,
        record.expires_at,
        now,
        &markers,
        Phase::Open(files),
    )
}

fn remove_session_files(layout: &Layout, tid: Uuid) {
    for path in [layout.session_data(tid), layout.session_parts(tid), layout.session_record(tid)] {
        if let Err(error) = fs::remove_file(&path)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(path = %path.display(), %error, "suppression impossible");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::session::{PhaseKind, persist_part, write_record};

    fn record(tid: Uuid, fid: Uuid, phase: RecordPhase, expires_at: u64) -> SessionRecord {
        SessionRecord {
            version: 1,
            tid,
            fid,
            sub: "u".into(),
            size: 300_000,
            part_size: 100_000,
            expires_at,
            phase,
            hash: Some("sha256p:00".into()),
        }
    }

    fn setup() -> (tempfile::TempDir, Layout) {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::new(dir.path());
        fs::create_dir_all(layout.uploads_dir()).unwrap();
        (dir, layout)
    }

    fn write_open_session(layout: &Layout, tid: Uuid, expires_at: u64, received: &[u64]) {
        fs::File::create(layout.session_data(tid)).unwrap().set_len(300_000).unwrap();
        let parts = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(layout.session_parts(tid))
            .unwrap();
        parts.set_len(parts_file_len(3).unwrap()).unwrap();
        for i in received {
            persist_part(&parts, 3, *i, &[1; 32]).unwrap();
        }
        write_record(&layout.session_record(tid), &record(tid, Uuid::from_u128(99), RecordPhase::Open, expires_at))
            .unwrap();
    }

    #[test]
    fn open_session_is_reloaded_with_its_parts() {
        let (_dir, layout) = setup();
        let tid = Uuid::from_u128(1);
        write_open_session(&layout, tid, 1000, &[0, 2]);
        let sessions = recover(&layout, 500);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].received_ranges(), vec![[0, 0], [2, 2]]);
        assert_eq!(sessions[0].phase_kind(), PhaseKind::Open);
    }

    #[test]
    fn expired_and_inconsistent_sessions_are_removed() {
        let (_dir, layout) = setup();
        let expired = Uuid::from_u128(1);
        write_open_session(&layout, expired, 1000, &[]);
        let broken = Uuid::from_u128(2);
        write_open_session(&layout, broken, 10_000_000, &[]);
        fs::File::create(layout.session_data(broken)).unwrap().set_len(5).unwrap(); // mauvaise taille
        let orphan = Uuid::from_u128(3);
        fs::write(layout.session_data(orphan), b"x").unwrap(); // sans enregistrement
        fs::write(layout.uploads_dir().join("junk.tmp"), b"x").unwrap();

        let sessions = recover(&layout, 1000 + ORPHAN_GRACE_SECS + 1);
        assert!(sessions.is_empty());
        let remaining: Vec<_> = fs::read_dir(layout.uploads_dir()).unwrap().collect();
        assert!(remaining.is_empty(), "tout a été nettoyé : {remaining:?}");
    }

    #[test]
    fn interrupted_finalization_is_completed() {
        let (_dir, layout) = setup();
        let tid = Uuid::from_u128(1);
        let fid = Uuid::from_u128(99);
        fs::write(layout.session_data(tid), b"contenu").unwrap();
        write_record(&layout.session_record(tid), &record(tid, fid, RecordPhase::Finalized, 0)).unwrap();

        let sessions = recover(&layout, 10_000_000);
        assert_eq!(sessions.len(), 1, "une session finalisée survit à l'expiration : le rappel reste à faire");
        assert_eq!(sessions[0].phase_kind(), PhaseKind::Finalized);
        assert_eq!(fs::read(layout.final_path(fid)).unwrap(), b"contenu");
        assert!(!layout.session_data(tid).exists());
    }

    #[test]
    fn finalization_never_overwrites_another_file() {
        let (_dir, layout) = setup();
        let tid = Uuid::from_u128(1);
        let fid = Uuid::from_u128(99);
        fs::write(layout.session_data(tid), b"nouveau").unwrap();
        fs::write(layout.final_path(fid), b"existant").unwrap();
        write_record(&layout.session_record(tid), &record(tid, fid, RecordPhase::Finalized, 0)).unwrap();

        assert!(recover(&layout, 0).is_empty());
        assert_eq!(fs::read(layout.final_path(fid)).unwrap(), b"existant");
    }

    #[test]
    fn corrupted_geometry_is_dropped_without_allocating() {
        let (_dir, layout) = setup();
        let tid = Uuid::from_u128(7);
        // Taille de part de 1 octet pour 10 Gio : refusée avant toute allocation.
        let mut corrupted = record(tid, Uuid::from_u128(99), RecordPhase::Open, u64::MAX);
        corrupted.size = 10 << 30;
        corrupted.part_size = 1;
        write_record(&layout.session_record(tid), &corrupted).unwrap();
        assert!(recover(&layout, 0).is_empty());
        assert!(!layout.session_record(tid).exists(), "enregistrement corrompu supprimé");
    }
}
