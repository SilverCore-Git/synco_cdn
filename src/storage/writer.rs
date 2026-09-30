//! Réception d'une part (cf. docs/plan/04-moteur-io.md#principes).
//!
//! Le corps arrive par fragments (`Bytes`, jamais copiés) de quelques
//! dizaines à quelques centaines de Kio. Ils sont regroupés en lots
//! d'environ 1 Mio, chacun compté dans le budget mémoire, et chaque lot est
//! écrit à sa position en un seul appel `pwritev` dans le pool de threads
//! bloquants, pendant que le lot suivant se remplit : réseau et disque
//! travaillent en parallèle, avec au plus deux lots par part, et aucun octet
//! n'est recopié en espace utilisateur.
//!
//! L'empreinte SHA-256 est calculée dans la même tâche que l'écriture,
//! pendant que les octets sont encore dans le cache du processeur.

use std::fs::File;
use std::io::{self, IoSlice};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http_body::Body;
use http_body_util::BodyExt;
use rustix::io::Errno;
use sha2::{Digest, Sha256};
use tokio::sync::OwnedSemaphorePermit;
use tokio::task::JoinHandle;

use crate::error::CdnError;
use crate::limits::{BUFFER_UNIT, BufferBudget};
use crate::storage::session::{HASH_LEN, PartGuard, persist_part};
use crate::storage::space::is_no_space;
use crate::util::to_u64;

/// Nombre maximal de tampons par appel `pwritev` (IOV_MAX sous Linux).
const IOV_MAX: usize = 1024;

/// Paramètres de réception d'une part.
#[derive(Debug, Clone, Copy)]
pub struct PartWriteOptions {
    /// Délai maximal entre deux fragments du corps.
    pub idle_timeout: Duration,
    /// `fdatasync` des données avant de marquer la part reçue.
    pub strict_durability: bool,
}

/// Lot de fragments reçus, écrit en une fois. Sa mémoire est comptée dans
/// le budget jusqu'à la fin de l'écriture.
#[derive(Debug)]
struct Batch {
    frames: Vec<Bytes>,
    len: usize,
    _permit: OwnedSemaphorePermit,
}

/// Écriture en cours : rend l'état du hachage.
type PendingWrite = JoinHandle<io::Result<Sha256>>;

/// Reçoit le corps `body` de la part réservée par `guard` et l'écrit à sa
/// place. `expected_hash` : empreinte annoncée par le client (`X-Part-Sha256`).
/// Renvoie le nombre d'octets écrits.
pub async fn write_part<B>(
    guard: PartGuard,
    index: u64,
    mut body: B,
    expected_hash: Option<[u8; HASH_LEN]>,
    budget: &BufferBudget,
    options: PartWriteOptions,
) -> Result<u64, CdnError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let session = Arc::clone(guard.session());
    let expected_len =
        session.part_len(index).ok_or(CdnError::bad_request("bad_part_index", "Index de part hors du fichier."))?;
    let base_offset =
        session.part_offset(index).ok_or(CdnError::bad_request("bad_part_index", "Index de part hors du fichier."))?;
    let data_file = Arc::clone(&guard.files().data);

    let mut received: u64 = 0;
    let mut write_offset = base_offset;
    let mut hasher = Some(Sha256::new());
    let mut batch: Option<Batch> = None;
    let mut pending: Option<PendingWrite> = None;

    loop {
        let frame = match tokio::time::timeout(options.idle_timeout, body.frame()).await {
            Err(_) => return Err(CdnError::request_timeout()),
            Ok(None) => break,
            Ok(Some(Err(error))) => {
                // Le client a coupé : la part sera renvoyée.
                return Err(CdnError::bad_request_cause("body_error", "Corps de requête interrompu.", error));
            }
            Ok(Some(Ok(frame))) => frame,
        };
        let Ok(data) = frame.into_data() else {
            continue; // trailers : ignorés
        };
        if data.is_empty() {
            continue;
        }

        received = received
            .checked_add(to_u64(data.len()))
            .filter(|total| *total <= expected_len)
            .ok_or(CdnError::bad_request("bad_part_length", "La part est plus longue que prévu."))?;

        let current = match batch.as_mut() {
            Some(current) => current,
            None => batch.insert(Batch { frames: Vec::new(), len: 0, _permit: budget.acquire().await? }),
        };
        current.len = current.len.saturating_add(data.len());
        current.frames.push(data);

        if current.len >= BUFFER_UNIT
            && let Some(full) = batch.take()
        {
            let written = to_u64(full.len);
            hasher = finish_pending(pending.take(), hasher).await?;
            pending = Some(spawn_write(&data_file, full, write_offset, &mut hasher)?);
            write_offset = write_offset.saturating_add(written);
        }
    }

    if received != expected_len {
        return Err(CdnError::bad_request("bad_part_length", "La part est plus courte que prévu."));
    }

    // Dernier lot, puis attente de toutes les écritures.
    if let Some(last) = batch.take() {
        hasher = finish_pending(pending.take(), hasher).await?;
        pending = Some(spawn_write(&data_file, last, write_offset, &mut hasher)?);
    }
    hasher = finish_pending(pending.take(), hasher).await?;

    let digest: [u8; HASH_LEN] =
        hasher.ok_or_else(|| CdnError::internal("écriture de part", "état de hachage perdu"))?.finalize().into();
    if expected_hash.is_some_and(|expected| expected != digest) {
        return Err(CdnError::unprocessable(
            "part_checksum_mismatch",
            "L'empreinte de la part ne correspond pas à X-Part-Sha256.",
        ));
    }

    // Persistance de l'état : après les données, et après leur fdatasync si
    // la durabilité stricte est demandée.
    let parts_file = Arc::clone(&guard.files().parts);
    let count = session.part_count;
    let strict = options.strict_durability;
    run_blocking(move || {
        if strict {
            data_file.sync_data()?;
        }
        persist_part(&parts_file, count, index, &digest)
    })
    .await?;

    guard.commit();
    Ok(received)
}

/// Lance l'écriture d'un lot dans le pool bloquant. Le hachage est déplacé
/// dans la tâche et rendu à la fin.
fn spawn_write(
    file: &Arc<File>,
    batch: Batch,
    offset: u64,
    hasher: &mut Option<Sha256>,
) -> Result<PendingWrite, CdnError> {
    let mut state = hasher.take().ok_or_else(|| CdnError::internal("écriture de part", "état de hachage perdu"))?;
    let file = Arc::clone(file);
    Ok(tokio::task::spawn_blocking(move || {
        pwrite_all_vectored(&file, &batch.frames, offset)?;
        for frame in &batch.frames {
            state.update(frame);
        }
        Ok(state)
    }))
}

/// Écrit tous les fragments à partir de `offset`, en reprenant après une
/// écriture partielle ou une interruption (`EINTR`).
pub fn pwrite_all_vectored(file: &File, frames: &[Bytes], mut offset: u64) -> io::Result<()> {
    let mut slices: Vec<IoSlice<'_>> = frames.iter().filter(|f| !f.is_empty()).map(|f| IoSlice::new(f)).collect();
    let mut remaining: &mut [IoSlice<'_>] = &mut slices;
    while !remaining.is_empty() {
        let window = remaining.get(..remaining.len().min(IOV_MAX)).unwrap_or_default();
        let written = match rustix::io::pwritev(file, window, offset) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "pwritev n'a rien écrit")),
            Ok(written) => written,
            Err(errno) if errno == Errno::INTR => continue,
            Err(errno) => return Err(errno.into()),
        };
        offset = offset.saturating_add(to_u64(written));
        IoSlice::advance_slices(&mut remaining, written);
    }
    Ok(())
}

/// Attend l'écriture précédente et récupère l'état du hachage.
async fn finish_pending(pending: Option<PendingWrite>, hasher: Option<Sha256>) -> Result<Option<Sha256>, CdnError> {
    let Some(task) = pending else {
        return Ok(hasher);
    };
    match task.await {
        Ok(Ok(state)) => Ok(Some(state)),
        Ok(Err(error)) if is_no_space(&error) => Err(CdnError::insufficient_storage()),
        Ok(Err(error)) => Err(CdnError::internal("écriture de part", error)),
        Err(join_error) => Err(CdnError::internal("tâche d'écriture", join_error)),
    }
}

/// Exécute une opération disque dans le pool bloquant.
pub async fn run_blocking<T, F>(operation: F) -> Result<T, CdnError>
where
    F: FnOnce() -> std::io::Result<T> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(operation).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) if is_no_space(&error) => Err(CdnError::insufficient_storage()),
        Ok(Err(error)) => Err(CdnError::internal("opération disque", error)),
        Err(join_error) => Err(CdnError::internal("tâche disque", join_error)),
    }
}

/// Lit et jette au plus `limit` octets du corps (part déjà reçue) : la
/// connexion reste réutilisable sans réécrire le disque.
pub async fn drain_body<B>(mut body: B, limit: u64, idle_timeout: Duration) -> Result<(), CdnError>
where
    B: Body + Unpin,
    B::Error: std::fmt::Display,
{
    let mut total: u64 = 0;
    loop {
        match tokio::time::timeout(idle_timeout, body.frame()).await {
            Err(_) => return Err(CdnError::request_timeout()),
            Ok(None) => return Ok(()),
            Ok(Some(Err(error))) => {
                return Err(CdnError::bad_request_cause("body_error", "Corps de requête interrompu.", error));
            }
            Ok(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    total = total.saturating_add(to_u64(data.remaining()));
                    if total > limit {
                        return Err(CdnError::bad_request("bad_part_length", "La part est plus longue que prévu."));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::session::{PartSlot, Phase, SessionFiles, UploadSession, parts_file_len, read_markers};
    use bytes::Bytes;
    use http_body::Frame;
    use uuid::Uuid;

    struct Fixture {
        _dir: tempfile::TempDir,
        session: Arc<UploadSession>,
        data_path: std::path::PathBuf,
    }

    fn fixture(size: u64, part_size: u64) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let data_path = dir.path().join("d");
        let parts_path = dir.path().join("p");
        File::create(&data_path).unwrap().set_len(size).unwrap();
        let count = crate::ticket::part_count(size, part_size).unwrap();
        File::create(&parts_path).unwrap().set_len(parts_file_len(count).unwrap()).unwrap();
        let files = SessionFiles::open(&data_path, &parts_path).unwrap();
        let session =
            UploadSession::new(Uuid::nil(), Uuid::nil(), "u".into(), size, part_size, 100, 0, &[], Phase::Open(files))
                .unwrap();
        Fixture { _dir: dir, session: Arc::new(session), data_path }
    }

    /// Corps de test : une suite de fragments donnée d'avance.
    fn body_of(chunks: Vec<Vec<u8>>) -> test_body::Chunks {
        test_body::Chunks(chunks.into_iter().map(|c| Ok(Frame::data(Bytes::from(c)))).collect())
    }

    mod test_body {
        use super::*;
        use std::pin::Pin;
        use std::task::{Context, Poll};
        pub struct Chunks(pub std::collections::VecDeque<Result<Frame<Bytes>, std::io::Error>>);
        impl http_body::Body for Chunks {
            type Data = Bytes;
            type Error = std::io::Error;
            fn poll_frame(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
                Poll::Ready(self.get_mut().0.pop_front())
            }
        }
    }

    fn options() -> PartWriteOptions {
        PartWriteOptions { idle_timeout: Duration::from_secs(5), strict_durability: false }
    }

    async fn write(f: &Fixture, index: u64, chunks: Vec<Vec<u8>>, budget: &BufferBudget) -> Result<u64, CdnError> {
        let PartSlot::Write(guard) = f.session.acquire_part(index, 8).unwrap() else { panic!("déjà reçue") };
        write_part(guard, index, body_of(chunks), None, budget, options()).await
    }

    #[tokio::test]
    async fn parts_land_at_their_offset_with_any_fragmentation() {
        // Parts de 3 Mio (plusieurs tampons), fragments de tailles variées.
        let part = 3 << 20;
        let size = part * 2 + 12345;
        let f = fixture(size, part);
        let budget = BufferBudget::new(16 << 20);
        let source: Vec<u8> = (0..size).map(|i| u8::try_from(i % 251).unwrap()).collect();

        for index in [2u64, 0, 1] {
            let start = usize::try_from(index * part).unwrap();
            let end = usize::try_from(((index + 1) * part).min(size)).unwrap();
            let slice = &source[start..end];
            let chunks: Vec<Vec<u8>> =
                slice.chunks(7919 * (usize::try_from(index).unwrap() + 1)).map(<[u8]>::to_vec).collect();
            assert_eq!(write(&f, index, chunks, &budget).await.unwrap(), u64::try_from(slice.len()).unwrap());
        }
        assert_eq!(std::fs::read(&f.data_path).unwrap(), source);
        assert_eq!(f.session.received_count(), 3);
        assert_eq!(budget.available_bytes(), budget.total_bytes(), "tous les tampons rendus");
    }

    #[tokio::test]
    async fn wrong_lengths_are_rejected_and_part_stays_missing() {
        let f = fixture(200_000, 100_000);
        let budget = BufferBudget::new(16 << 20);
        let too_long = write(&f, 0, vec![vec![1; 100_001]], &budget).await.unwrap_err();
        assert_eq!(too_long.code, "bad_part_length");
        let too_short = write(&f, 0, vec![vec![1; 99_999]], &budget).await.unwrap_err();
        assert_eq!(too_short.code, "bad_part_length");
        assert_eq!(f.session.received_count(), 0);
        assert_eq!(f.session.in_flight(), 0);
        assert!(write(&f, 0, vec![vec![1; 100_000]], &budget).await.is_ok());
    }

    #[tokio::test]
    async fn checksum_is_verified_and_persisted() {
        let f = fixture(10, 65536);
        let budget = BufferBudget::new(16 << 20);
        let PartSlot::Write(guard) = f.session.acquire_part(0, 8).unwrap() else { panic!() };
        let error =
            write_part(guard, 0, body_of(vec![vec![5; 10]]), Some([0; 32]), &budget, options()).await.unwrap_err();
        assert_eq!(error.code, "part_checksum_mismatch");

        let good: [u8; 32] = Sha256::digest([5u8; 10]).into();
        let PartSlot::Write(guard) = f.session.acquire_part(0, 8).unwrap() else { panic!() };
        write_part(guard, 0, body_of(vec![vec![5; 10]]), Some(good), &budget, options()).await.unwrap();
        let parts = std::fs::File::open(f._dir.path().join("p")).unwrap();
        assert_eq!(read_markers(&parts, 1).unwrap(), vec![1]);
    }

    #[tokio::test]
    async fn empty_file_single_empty_part() {
        let f = fixture(0, 65536);
        let budget = BufferBudget::new(16 << 20);
        assert_eq!(write(&f, 0, vec![], &budget).await.unwrap(), 0);
        assert_eq!(f.session.received_count(), 1);
    }
}
