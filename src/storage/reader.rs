//! Lecture des fichiers terminés (cf. docs/plan/04-moteur-io.md#téléchargements).
//!
//! Une tâche lit la plage demandée par blocs de 1 Mio (`pread` dans le pool
//! bloquant) et les pousse dans un canal de capacité 2 : au plus deux blocs
//! d'avance par réponse. Chaque bloc détient un jeton du budget mémoire,
//! rendu seulement quand hyper a fini de l'envoyer : un client lent
//! n'immobilise que quelques Mio, quel que soit le nombre de clients.

use std::fs::File;
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::body::ChannelBody;
use crate::limits::{BUFFER_UNIT, BudgetedBlock, BufferBudget};
use crate::metrics::Metrics;
use crate::util::{to_u64, to_usize};

/// Blocs lus d'avance par réponse.
const READ_AHEAD: usize = 2;

/// Fichier ouvert et ses attributs, lus une seule fois (`fstat`).
#[derive(Debug, Clone)]
pub struct OpenedFile {
    pub file: Arc<File>,
    pub size: u64,
    /// Date de modification en nanosecondes depuis l'époque (comparée à celle du ticket).
    pub mtime_ns: u64,
}

/// Ouvre un fichier terminé. `Ok(None)` s'il n'existe pas.
pub fn open_final(path: &Path) -> io::Result<Option<OpenedFile>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Ok(None);
    }
    Ok(Some(OpenedFile { size: metadata.len(), mtime_ns: mtime_ns(&metadata), file: Arc::new(file) }))
}

/// Date de modification en nanosecondes, comme `fs.statSync(p, { bigint: true }).mtimeNs` côté Node.
pub fn mtime_ns(metadata: &std::fs::Metadata) -> u64 {
    let secs = u64::try_from(metadata.mtime()).unwrap_or(0);
    let nanos = u64::try_from(metadata.mtime_nsec()).unwrap_or(0);
    secs.saturating_mul(1_000_000_000).saturating_add(nanos)
}

/// Corps de réponse qui envoie `[start, end)` de `file`.
pub fn stream_range(file: Arc<File>, start: u64, end: u64, budget: BufferBudget, metrics: Arc<Metrics>) -> ChannelBody {
    let (tx, rx) = mpsc::channel(READ_AHEAD);
    let length = end.saturating_sub(start);
    tokio::spawn(async move {
        let started = Instant::now();
        let mut offset = start;
        while offset < end {
            let permit = match budget.acquire().await {
                Ok(permit) => permit,
                Err(error) => {
                    let _ = tx.send(Err(io::Error::other(error.to_string()))).await;
                    return;
                }
            };
            let chunk = end.saturating_sub(offset).min(to_u64(BUFFER_UNIT));
            let file = Arc::clone(&file);
            let read_at = offset;
            let block = tokio::task::spawn_blocking(move || -> io::Result<Vec<u8>> {
                let len = to_usize(chunk).ok_or_else(|| io::Error::other("taille de bloc hors bornes"))?;
                let mut data = vec![0u8; len];
                file.read_exact_at(&mut data, read_at)?;
                Ok(data)
            })
            .await;

            let data = match block {
                Ok(Ok(data)) => data,
                Ok(Err(error)) => {
                    tracing::warn!(%error, "lecture d'un bloc impossible");
                    let _ = tx.send(Err(error)).await;
                    return;
                }
                Err(join_error) => {
                    let _ = tx.send(Err(io::Error::other(join_error.to_string()))).await;
                    return;
                }
            };

            let bytes = Bytes::from_owner(BudgetedBlock { data, _permit: permit });
            if tx.send(Ok(bytes)).await.is_err() {
                return; // client parti : on arrête de lire
            }
            metrics.bytes_sent.fetch_add(chunk, Ordering::Relaxed);
            offset = offset.saturating_add(chunk);
        }
        metrics.range_read.observe(started.elapsed());
    });
    ChannelBody::new(rx, length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn streams_exact_range() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        let content: Vec<u8> = (0..(3 * BUFFER_UNIT + 17)).map(|i| u8::try_from(i % 253).unwrap()).collect();
        std::fs::write(&path, &content).unwrap();

        let opened = open_final(&path).unwrap().unwrap();
        assert_eq!(opened.size, to_u64(content.len()));
        assert!(opened.mtime_ns > 0);

        let budget = BufferBudget::new(8 << 20);
        let metrics = Arc::new(Metrics::default());
        let (start, end) = (100u64, to_u64(content.len()) - 5);
        let body = stream_range(Arc::clone(&opened.file), start, end, budget.clone(), metrics);
        let collected = body.collect().await.unwrap().to_bytes();
        assert_eq!(&collected[..], &content[100..content.len() - 5]);
        assert_eq!(budget.available_bytes(), budget.total_bytes());

        assert!(open_final(&dir.path().join("absent")).unwrap().is_none());
        assert!(open_final(dir.path()).unwrap().is_none(), "un répertoire n'est pas servi");
    }
}
