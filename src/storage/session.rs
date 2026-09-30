//! Session d'envoi : état des parts, phase, persistance.
//!
//! ## Concurrence
//!
//! Plusieurs threads écrivent des parts différentes de la même session en
//! même temps, sans verrou : l'état de chaque part est un octet atomique
//! (absente → en cours → reçue) changé par comparaison-échange. Le seul
//! verrou (`phase`) protège les transitions de phase (ouverte → en
//! finalisation → finalisée → terminée) et n'est jamais tenu pendant une
//! E/S ou un `await`.
//!
//! Invariant de la finalisation : une part incrémente `in_flight` *avant*
//! de vérifier la phase sous le verrou ; la finalisation vérifie
//! `in_flight == 0` sous ce même verrou. Aucune part ne peut donc être en
//! cours d'écriture quand la finalisation commence.
//!
//! ## Persistance (`<tid>.parts`)
//!
//! `part_count` octets d'état (0 = absente, 1 = reçue), puis `part_count`
//! empreintes SHA-256 de 32 octets. L'octet d'état d'une part n'est écrit
//! qu'après ses données et son empreinte.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::CdnError;
use crate::ticket::part_count;
use crate::util::{hex_encode, to_u64, to_usize};

const PART_EMPTY: u8 = 0;
const PART_WRITING: u8 = 1;
const PART_DONE: u8 = 2;
/// Valeur de l'octet d'état d'une part reçue, dans `<tid>.parts`.
const MARKER_DONE: u8 = 1;
pub const HASH_LEN: usize = 32;
const HASH_LEN_U64: u64 = 32;
/// Version du format des fichiers de session.
const RECORD_VERSION: u32 = 1;
/// Taille maximale d'un fichier `<tid>.session` (lecture bornée).
pub const MAX_RECORD_BYTES: u64 = 64 * 1024;

// ---------------------------------------------------------------------------
// Enregistrement persistant (<tid>.session)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordPhase {
    Open,
    Finalized,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRecord {
    pub version: u32,
    pub tid: Uuid,
    pub fid: Uuid,
    pub sub: String,
    pub size: u64,
    pub part_size: u64,
    pub expires_at: u64,
    pub phase: RecordPhase,
    #[serde(default)]
    pub hash: Option<String>,
}

impl SessionRecord {
    pub fn is_supported_version(&self) -> bool {
        self.version == RECORD_VERSION
    }
}

/// Écriture atomique d'un petit fichier : temporaire, `fsync`, `rename`,
/// puis `fsync` du répertoire pour que le renommage survive à une coupure.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut file = File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        sync_dir(dir)?;
    }
    Ok(())
}

pub fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

pub fn write_record(path: &Path, record: &SessionRecord) -> io::Result<()> {
    let bytes = serde_json::to_vec(record).map_err(io::Error::other)?;
    write_atomic(path, &bytes)
}

// ---------------------------------------------------------------------------
// Fichier des parts (<tid>.parts)
// ---------------------------------------------------------------------------

/// Taille du fichier des parts pour `count` parts.
pub fn parts_file_len(count: u64) -> Option<u64> {
    count.checked_mul(HASH_LEN_U64.checked_add(1)?)
}

/// Enregistre la réception d'une part : empreinte d'abord, état ensuite.
pub fn persist_part(parts: &File, count: u64, index: u64, hash: &[u8; HASH_LEN]) -> io::Result<()> {
    let hash_offset = index
        .checked_mul(HASH_LEN_U64)
        .and_then(|o| o.checked_add(count))
        .ok_or_else(|| io::Error::other("décalage d'empreinte hors bornes"))?;
    parts.write_all_at(hash, hash_offset)?;
    parts.write_all_at(&[MARKER_DONE], index)
}

/// Lit les octets d'état des parts.
pub fn read_markers(parts: &File, count: u64) -> io::Result<Vec<u8>> {
    let len = to_usize(count).ok_or_else(|| io::Error::other("nombre de parts hors bornes"))?;
    let mut markers = vec![0u8; len];
    parts.read_exact_at(&mut markers, 0)?;
    Ok(markers)
}

/// Empreinte du fichier : `sha256p:` + SHA-256 de la concaténation des
/// empreintes de parts. Calculée sans relire les données.
pub fn file_hash(parts: &File, count: u64) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let total = count.checked_mul(HASH_LEN_U64).ok_or_else(|| io::Error::other("nombre de parts hors bornes"))?;
    let mut offset = 0u64;
    while offset < total {
        let chunk = total.saturating_sub(offset).min(to_u64(buffer.len()));
        let chunk_len = to_usize(chunk).ok_or_else(|| io::Error::other("taille hors bornes"))?;
        let slice = buffer.get_mut(..chunk_len).ok_or_else(|| io::Error::other("tampon trop petit"))?;
        parts.read_exact_at(slice, count.saturating_add(offset))?;
        hasher.update(&*slice);
        offset = offset.saturating_add(chunk);
    }
    Ok(format!("sha256p:{}", hex_encode(&hasher.finalize())))
}

// ---------------------------------------------------------------------------
// Session en mémoire
// ---------------------------------------------------------------------------

/// Fichiers d'une session ouverte.
#[derive(Debug, Clone)]
pub struct SessionFiles {
    pub data: Arc<File>,
    pub parts: Arc<File>,
}

impl SessionFiles {
    pub fn open(data: &Path, parts: &Path) -> io::Result<Self> {
        let open = |p: &Path| OpenOptions::new().read(true).write(true).open(p).map(Arc::new);
        Ok(Self { data: open(data)?, parts: open(parts)? })
    }
}

/// Phase d'une session.
#[derive(Debug)]
pub enum Phase {
    /// Parts acceptées.
    Open(SessionFiles),
    /// Finalisation disque en cours (transitoire).
    Completing,
    /// Fichier en place, synco_api pas encore prévenue (ou injoignable).
    Finalized { hash: String },
    /// synco_api a enregistré le fichier. `response` est la réponse de l'API,
    /// renvoyée telle quelle si le client rappelle `complete` (absente après
    /// un redémarrage : l'API est alors rappelée, son traitement est idempotent).
    Completed { hash: String, response: Option<Bytes> },
    /// Annulée : plus rien n'est accepté.
    Aborted,
}

/// Résumé de la phase, sans les données.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseKind {
    Open,
    Completing,
    Finalized,
    Completed,
    Aborted,
}

/// Étape à exécuter par `complete`.
#[derive(Debug)]
pub enum CompleteStep {
    /// Finaliser sur disque, puis prévenir l'API.
    Finalize(SessionFiles),
    /// Déjà sur disque : prévenir l'API.
    Callback { hash: String },
    /// Déjà enregistré : renvoyer la réponse mémorisée.
    Done { response: Bytes },
}

/// Résultat d'une demande d'écriture de part.
#[derive(Debug)]
pub enum PartSlot {
    /// La part est réservée pour cet appelant.
    Write(PartGuard),
    /// La part a déjà été reçue : le corps peut être ignoré.
    AlreadyReceived,
}

#[derive(Debug)]
pub struct UploadSession {
    pub tid: Uuid,
    pub fid: Uuid,
    pub sub: String,
    pub size: u64,
    pub part_size: u64,
    pub part_count: u64,
    expires_at: AtomicU64,
    last_activity: AtomicU64,
    parts: Box<[AtomicU8]>,
    received: AtomicU64,
    in_flight: AtomicU32,
    phase: Mutex<Phase>,
    /// Un seul rappel d'arrière-plan à la fois (cf. balayage).
    callback_running: AtomicBool,
}

impl UploadSession {
    /// Construit une session. `markers` : états persistés des parts (vide =
    /// aucune reçue). `None` si la géométrie est incohérente.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tid: Uuid,
        fid: Uuid,
        sub: String,
        size: u64,
        part_size: u64,
        expires_at: u64,
        now: u64,
        markers: &[u8],
        phase: Phase,
    ) -> Option<Self> {
        let count = part_count(size, part_size)?;
        let len = to_usize(count)?;
        let parts: Box<[AtomicU8]> = (0..len)
            .map(|i| {
                let done = markers.get(i) == Some(&MARKER_DONE);
                AtomicU8::new(if done { PART_DONE } else { PART_EMPTY })
            })
            .collect();
        let received = to_u64(parts.iter().filter(|p| p.load(Ordering::Relaxed) == PART_DONE).count());
        Some(Self {
            tid,
            fid,
            sub,
            size,
            part_size,
            part_count: count,
            expires_at: AtomicU64::new(expires_at),
            last_activity: AtomicU64::new(now),
            parts,
            received: AtomicU64::new(received),
            in_flight: AtomicU32::new(0),
            phase: Mutex::new(phase),
            callback_running: AtomicBool::new(false),
        })
    }

    /// Le verrou n'est jamais tenu pendant une opération qui peut paniquer ;
    /// un empoisonnement éventuel laisse donc un état cohérent, récupéré.
    fn lock(&self) -> MutexGuard<'_, Phase> {
        self.phase.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn record(&self, phase: RecordPhase, hash: Option<String>) -> SessionRecord {
        SessionRecord {
            version: RECORD_VERSION,
            tid: self.tid,
            fid: self.fid,
            sub: self.sub.clone(),
            size: self.size,
            part_size: self.part_size,
            expires_at: self.expires_at(),
            phase,
            hash,
        }
    }

    // --- Géométrie -----------------------------------------------------------

    /// Position de la part `index` dans le fichier.
    pub fn part_offset(&self, index: u64) -> Option<u64> {
        if index >= self.part_count {
            return None;
        }
        index.checked_mul(self.part_size)
    }

    /// Longueur exacte de la part `index`.
    pub fn part_len(&self, index: u64) -> Option<u64> {
        let offset = self.part_offset(index)?;
        Some(self.size.saturating_sub(offset).min(self.part_size))
    }

    // --- Horloge ---------------------------------------------------------------

    pub fn expires_at(&self) -> u64 {
        self.expires_at.load(Ordering::Relaxed)
    }

    /// Un ticket renouvelé prolonge la session.
    pub fn extend_expiry(&self, exp: u64) {
        self.expires_at.fetch_max(exp, Ordering::Relaxed);
    }

    pub fn touch(&self, now: u64) {
        self.last_activity.fetch_max(now, Ordering::Relaxed);
    }

    pub fn last_activity(&self) -> u64 {
        self.last_activity.load(Ordering::Relaxed)
    }

    // --- Parts -----------------------------------------------------------------

    pub fn received_count(&self) -> u64 {
        self.received.load(Ordering::SeqCst)
    }

    pub fn in_flight(&self) -> u32 {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Réserve la part `index` pour écriture.
    pub fn acquire_part(self: &Arc<Self>, index: u64, max_in_flight: u32) -> Result<PartSlot, CdnError> {
        let slot = to_usize(index)
            .and_then(|i| self.parts.get(i).map(|s| (i, s)))
            .ok_or(CdnError::bad_request("bad_part_index", "Index de part hors du fichier."))?;

        // Incrément AVANT la vérification de phase (cf. invariant du module).
        let previous = self.in_flight.fetch_add(1, Ordering::SeqCst);
        if previous >= max_in_flight {
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            return Err(CdnError::too_many(
                "too_many_parts_in_flight",
                "Trop de parts de ce transfert en cours d'écriture.",
                1,
            ));
        }

        let files = match &*self.lock() {
            Phase::Open(files) => files.clone(),
            Phase::Aborted => {
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                return Err(CdnError::not_found("upload_not_found", "Envoi introuvable."));
            }
            _ => {
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                return Err(CdnError::conflict("upload_completing", "L'envoi est en cours de finalisation."));
            }
        };

        let (index_usize, state) = slot;
        match state.compare_exchange(PART_EMPTY, PART_WRITING, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => Ok(PartSlot::Write(PartGuard {
                session: Arc::clone(self),
                index: index_usize,
                files,
                committed: false,
            })),
            Err(PART_DONE) => {
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                Ok(PartSlot::AlreadyReceived)
            }
            Err(_) => {
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                Err(CdnError::conflict("part_in_progress", "Cette part est déjà en cours d'écriture."))
            }
        }
    }

    /// Parts reçues, en plages inclusives `[début, fin]`.
    pub fn received_ranges(&self) -> Vec<[u64; 2]> {
        let mut ranges: Vec<[u64; 2]> = Vec::new();
        for (i, state) in self.parts.iter().enumerate() {
            if state.load(Ordering::Relaxed) != PART_DONE {
                continue;
            }
            let i = to_u64(i);
            match ranges.last_mut() {
                Some(last) if last[1].checked_add(1) == Some(i) => last[1] = i,
                _ => ranges.push([i, i]),
            }
        }
        ranges
    }

    // --- Phases ----------------------------------------------------------------

    pub fn phase_kind(&self) -> PhaseKind {
        match &*self.lock() {
            Phase::Open(_) => PhaseKind::Open,
            Phase::Completing => PhaseKind::Completing,
            Phase::Finalized { .. } => PhaseKind::Finalized,
            Phase::Completed { .. } => PhaseKind::Completed,
            Phase::Aborted => PhaseKind::Aborted,
        }
    }

    /// Empreinte connue (sessions finalisées ou terminées).
    pub fn hash(&self) -> Option<String> {
        match &*self.lock() {
            Phase::Finalized { hash } | Phase::Completed { hash, .. } => Some(hash.clone()),
            _ => None,
        }
    }

    /// Détermine ce que doit faire `complete`, en passant la session en
    /// finalisation si toutes les parts sont là.
    pub fn begin_complete(&self) -> Result<CompleteStep, CdnError> {
        let mut phase = self.lock();
        match &*phase {
            Phase::Open(files) => {
                if self.in_flight.load(Ordering::SeqCst) != 0 {
                    return Err(CdnError::conflict("parts_in_progress", "Des parts sont encore en cours d'écriture."));
                }
                if self.received.load(Ordering::SeqCst) != self.part_count {
                    return Err(CdnError::conflict("parts_missing", "Des parts n'ont pas encore été reçues."));
                }
                let files = files.clone();
                *phase = Phase::Completing;
                Ok(CompleteStep::Finalize(files))
            }
            Phase::Completing => {
                Err(CdnError::unavailable("upload_completing", "La finalisation est déjà en cours.", 1))
            }
            Phase::Finalized { hash } => Ok(CompleteStep::Callback { hash: hash.clone() }),
            Phase::Completed { hash, response } => Ok(match response {
                Some(response) => CompleteStep::Done { response: response.clone() },
                None => CompleteStep::Callback { hash: hash.clone() },
            }),
            Phase::Aborted => Err(CdnError::not_found("upload_not_found", "Envoi introuvable.")),
        }
    }

    /// Finalisation disque réussie.
    pub fn set_finalized(&self, hash: String) {
        *self.lock() = Phase::Finalized { hash };
    }

    /// Finalisation disque échouée avant le déplacement du fichier : la
    /// session redevient ouverte, `complete` pourra être rappelé.
    pub fn restore_open(&self, files: SessionFiles) {
        let mut phase = self.lock();
        if matches!(*phase, Phase::Completing) {
            *phase = Phase::Open(files);
        }
    }

    pub fn set_completed(&self, hash: String, response: Bytes) {
        *self.lock() = Phase::Completed { hash, response: Some(response) };
    }

    /// Passe la session en annulée et renvoie la phase précédente.
    pub fn set_aborted(&self) -> PhaseKind {
        let mut phase = self.lock();
        let previous = match &*phase {
            Phase::Open(_) => PhaseKind::Open,
            Phase::Completing => PhaseKind::Completing,
            Phase::Finalized { .. } => PhaseKind::Finalized,
            Phase::Completed { .. } => PhaseKind::Completed,
            Phase::Aborted => PhaseKind::Aborted,
        };
        *phase = Phase::Aborted;
        previous
    }

    /// Réserve le droit de lancer un rappel d'arrière-plan.
    pub fn try_start_callback(&self) -> bool {
        self.callback_running.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok()
    }

    pub fn end_callback(&self) {
        self.callback_running.store(false, Ordering::SeqCst);
    }
}

/// Réservation d'une part. Si elle est abandonnée sans `commit` (erreur,
/// client coupé), la part redevient absente ; dans tous les cas le compteur
/// de parts en cours est décrémenté.
#[derive(Debug)]
pub struct PartGuard {
    session: Arc<UploadSession>,
    index: usize,
    files: SessionFiles,
    committed: bool,
}

impl PartGuard {
    pub fn files(&self) -> &SessionFiles {
        &self.files
    }

    pub fn session(&self) -> &Arc<UploadSession> {
        &self.session
    }

    /// Marque la part comme reçue (après persistance de son état).
    pub fn commit(mut self) {
        if let Some(state) = self.session.parts.get(self.index) {
            state.store(PART_DONE, Ordering::SeqCst);
            self.session.received.fetch_add(1, Ordering::SeqCst);
        }
        self.committed = true;
    }
}

impl Drop for PartGuard {
    fn drop(&mut self) {
        if !self.committed
            && let Some(state) = self.session.parts.get(self.index)
        {
            state.store(PART_EMPTY, Ordering::SeqCst);
        }
        self.session.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(size: u64, part_size: u64) -> (Arc<UploadSession>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("d");
        let parts = dir.path().join("p");
        File::create(&data).unwrap();
        let count = part_count(size, part_size).unwrap();
        File::create(&parts).unwrap().set_len(parts_file_len(count).unwrap()).unwrap();
        let files = SessionFiles::open(&data, &parts).unwrap();
        let s =
            UploadSession::new(Uuid::nil(), Uuid::nil(), "u".into(), size, part_size, 100, 0, &[], Phase::Open(files))
                .unwrap();
        (Arc::new(s), dir)
    }

    #[test]
    fn geometry() {
        let (s, _d) = session(25, 10);
        assert_eq!(s.part_count, 3);
        assert_eq!(s.part_len(0), Some(10));
        assert_eq!(s.part_len(2), Some(5));
        assert_eq!(s.part_offset(2), Some(20));
        assert_eq!(s.part_len(3), None);
        let (empty, _d) = session(0, 10);
        assert_eq!(empty.part_count, 1);
        assert_eq!(empty.part_len(0), Some(0));
    }

    #[test]
    fn part_lifecycle_and_completion_invariant() {
        let (s, _d) = session(25, 10);
        let PartSlot::Write(guard) = s.acquire_part(0, 8).unwrap() else { panic!() };
        // Même part en parallèle : refusée.
        assert_eq!(s.acquire_part(0, 8).unwrap_err().code, "part_in_progress");
        // Finalisation impossible pendant une écriture.
        assert_eq!(s.begin_complete().unwrap_err().code, "parts_in_progress");
        guard.commit();
        assert!(matches!(s.acquire_part(0, 8).unwrap(), PartSlot::AlreadyReceived));

        // Abandon sans commit : la part redevient absente.
        let PartSlot::Write(guard) = s.acquire_part(1, 8).unwrap() else { panic!() };
        drop(guard);
        assert_eq!(s.in_flight(), 0);
        assert_eq!(s.begin_complete().unwrap_err().code, "parts_missing");

        for i in 1..3 {
            let PartSlot::Write(g) = s.acquire_part(i, 8).unwrap() else { panic!() };
            g.commit();
        }
        assert_eq!(s.received_ranges(), vec![[0, 2]]);
        assert!(matches!(s.begin_complete().unwrap(), CompleteStep::Finalize(_)));
        // Plus aucune part acceptée.
        assert_eq!(s.acquire_part(0, 8).unwrap_err().code, "upload_completing");
        assert_eq!(s.begin_complete().unwrap_err().code, "upload_completing");
        s.set_finalized("h".into());
        assert!(matches!(s.begin_complete().unwrap(), CompleteStep::Callback { .. }));
        s.set_completed("h".into(), Bytes::from_static(b"{}"));
        assert!(matches!(s.begin_complete().unwrap(), CompleteStep::Done { .. }));
    }

    #[test]
    fn in_flight_limit() {
        let (s, _d) = session(100, 10);
        let guards: Vec<_> = (0..2).map(|i| s.acquire_part(i, 2).unwrap()).collect();
        assert_eq!(s.acquire_part(5, 2).unwrap_err().code, "too_many_parts_in_flight");
        drop(guards);
        assert!(s.acquire_part(5, 2).is_ok());
    }

    #[test]
    fn ranges_and_persisted_markers() {
        let dir = tempfile::tempdir().unwrap();
        let parts_path = dir.path().join("p");
        let parts = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&parts_path).unwrap();
        parts.set_len(parts_file_len(6).unwrap()).unwrap();
        for i in [0u64, 1, 3, 5] {
            persist_part(&parts, 6, i, &[u8::try_from(i).unwrap(); 32]).unwrap();
        }
        let markers = read_markers(&parts, 6).unwrap();
        let s =
            UploadSession::new(Uuid::nil(), Uuid::nil(), "u".into(), 60, 10, 0, 0, &markers, Phase::Aborted).unwrap();
        assert_eq!(s.received_ranges(), vec![[0, 1], [3, 3], [5, 5]]);
        assert_eq!(s.received_count(), 4);
        let hash = file_hash(&parts, 6).unwrap();
        assert!(hash.starts_with("sha256p:") && hash.len() == 8 + 64);
    }
}
