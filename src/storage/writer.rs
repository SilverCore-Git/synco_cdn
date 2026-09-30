//! Réception d'une part (cf. docs/plan/04-moteur-io.md#principes).
//!
//! Le corps arrive par fragments de quelques dizaines de Kio. Ils sont
//! regroupés dans des tampons de 1 Mio (budget mémoire) et chaque tampon
//! plein est écrit à sa position (`pwrite`) dans le pool de threads
//! bloquants, pendant que le suivant se remplit : réseau et disque
//! travaillent en parallèle, avec au plus deux tampons par part.
//!
//! L'empreinte SHA-256 est calculée dans la même tâche que l'écriture,
//! pendant que les octets sont encore dans le cache du processeur.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use std::time::Duration;

use bytes::Buf;
use http_body::Body;
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;

use crate::error::CdnError;
use crate::limits::{BUFFER_UNIT, BudgetedBuffer, BufferBudget};
use crate::storage::session::{HASH_LEN, PartGuard, persist_part};
use crate::storage::space::is_no_space;
use crate::util::{to_u64, to_usize};

/// Paramètres de réception d'une part.
#[derive(Debug, Clone, Copy)]
pub struct PartWriteOptions {
    /// Délai maximal entre deux fragments du corps.
    pub idle_timeout: Duration,
    /// `fdatasync` des données avant de marquer la part reçue.
    pub strict_durability: bool,
}

/// Tâche d'écriture en cours : rend l'état du hachage et le tampon (réutilisé).
type PendingWrite = JoinHandle<std::io::Result<(Sha256, BudgetedBuffer)>>;

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
    B: Body + Unpin,
    B::Error: std::fmt::Display,
{
    let session = Arc::clone(guard.session());
    let expected_len =
        session.part_len(index).ok_or(CdnError::bad_request("bad_part_index", "Index de part hors du fichier."))?;
    let base_offset =
        session.part_offset(index).ok_or(CdnError::bad_request("bad_part_index", "Index de part hors du fichier."))?;
    let data_file = Arc::clone(&guard.files().data);
    let buffer_capacity = to_usize(expected_len).unwrap_or(BUFFER_UNIT).clamp(1, BUFFER_UNIT);

    let mut received: u64 = 0;
    let mut write_offset = base_offset;
    let mut hasher = Some(Sha256::new());
    let mut filling: Option<BudgetedBuffer> = None;
    let mut spare: Option<BudgetedBuffer> = None;
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
        let Ok(mut data) = frame.into_data() else {
            continue; // trailers : ignorés
        };

        received = received
            .checked_add(to_u64(data.remaining()))
            .filter(|total| *total <= expected_len)
            .ok_or(CdnError::bad_request("bad_part_length", "La part est plus longue que prévu."))?;

        while data.has_remaining() {
            let buffer = match filling.as_mut() {
                Some(buffer) => buffer,
                None => {
                    let buffer = match spare.take() {
                        Some(buffer) => buffer,
                        None => budget.buffer(buffer_capacity).await?,
                    };
                    filling.insert(buffer)
                }
            };
            let room = buffer_capacity.saturating_sub(buffer.data.len());
            let take = room.min(data.remaining());
            buffer.data.extend_from_slice(data.chunk().get(..take).unwrap_or_default());
            data.advance(take);

            if buffer.data.len() >= buffer_capacity
                && let Some(full) = filling.take()
            {
                let written = to_u64(full.data.len());
                (hasher, spare) = finish_pending(pending.take(), hasher, spare).await?;
                pending = Some(spawn_write(&data_file, full, write_offset, &mut hasher)?);
                write_offset = write_offset.saturating_add(written);
            }
        }
    }

    if received != expected_len {
        return Err(CdnError::bad_request("bad_part_length", "La part est plus courte que prévu."));
    }

    // Dernier tampon partiel, puis attente de toutes les écritures.
    if let Some(last) = filling.take().filter(|b| !b.data.is_empty()) {
        (hasher, spare) = finish_pending(pending.take(), hasher, spare).await?;
        pending = Some(spawn_write(&data_file, last, write_offset, &mut hasher)?);
    }
    (hasher, spare) = finish_pending(pending.take(), hasher, spare).await?;
    drop(spare);

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

/// Lance l'écriture d'un tampon plein dans le pool bloquant. Le hachage est
/// déplacé dans la tâche et rendu avec le tampon.
fn spawn_write(
    file: &Arc<File>,
    buffer: BudgetedBuffer,
    offset: u64,
    hasher: &mut Option<Sha256>,
) -> Result<PendingWrite, CdnError> {
    let mut state = hasher.take().ok_or_else(|| CdnError::internal("écriture de part", "état de hachage perdu"))?;
    let file = Arc::clone(file);
    Ok(tokio::task::spawn_blocking(move || {
        file.write_all_at(&buffer.data, offset)?;
        state.update(&buffer.data);
        let mut buffer = buffer;
        buffer.data.clear();
        Ok((state, buffer))
    }))
}

/// Attend l'écriture précédente et récupère le hachage et le tampon libéré.
async fn finish_pending(
    pending: Option<PendingWrite>,
    hasher: Option<Sha256>,
    spare: Option<BudgetedBuffer>,
) -> Result<(Option<Sha256>, Option<BudgetedBuffer>), CdnError> {
    let Some(task) = pending else {
        return Ok((hasher, spare));
    };
    match task.await {
        Ok(Ok((state, buffer))) => Ok((Some(state), Some(buffer))),
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
