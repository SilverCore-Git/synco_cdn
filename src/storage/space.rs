//! Espace disque : contrôle de la réserve et préallocation.

use std::fs::File;
use std::io;
use std::path::Path;

use rustix::fs::FallocateFlags;
use rustix::io::Errno;

/// Réserve d'espace libre à ne jamais entamer.
#[derive(Debug, Clone, Copy)]
pub struct SpacePolicy {
    pub min_free_bytes: u64,
    pub min_free_percent: u8,
}

/// Espace du système de fichiers qui contient `path`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskUsage {
    /// Octets disponibles pour un processus non privilégié.
    pub available: u64,
    pub total: u64,
}

pub fn disk_usage(path: &Path) -> io::Result<DiskUsage> {
    let stat = rustix::fs::statvfs(path)?;
    Ok(DiskUsage {
        available: stat.f_bavail.saturating_mul(stat.f_frsize),
        total: stat.f_blocks.saturating_mul(stat.f_frsize),
    })
}

impl SpacePolicy {
    /// Octets à laisser libres sur un disque de `total` octets.
    pub fn reserve(&self, total: u64) -> u64 {
        let percent = (total / 100).saturating_mul(u64::from(self.min_free_percent));
        self.min_free_bytes.max(percent)
    }

    /// Vrai si `needed` octets peuvent être écrits sans entamer la réserve.
    pub fn has_room(&self, usage: DiskUsage, needed: u64) -> bool {
        usage.available.checked_sub(needed).is_some_and(|left| left >= self.reserve(usage.total))
    }
}

/// Réserve `len` octets pour `file` (`fallocate`) : les blocs sont alloués
/// d'un coup, contigus autant que possible, et un disque plein est détecté
/// avant le premier octet reçu. Sur un système de fichiers qui ne le permet
/// pas, le fichier est seulement étendu (creux) : le fonctionnement reste
/// correct, sans la garantie d'espace.
pub fn preallocate(file: &File, len: u64) -> io::Result<()> {
    if len == 0 {
        return Ok(());
    }
    match rustix::fs::fallocate(file, FallocateFlags::empty(), 0, len) {
        Ok(()) => Ok(()),
        Err(errno) if errno == Errno::OPNOTSUPP || errno == Errno::NOSYS => {
            tracing::warn!("fallocate non pris en charge par ce système de fichiers, fichier creux");
            file.set_len(len)
        }
        Err(errno) => Err(errno.into()),
    }
}

/// Vrai si l'erreur signifie « disque plein ».
pub fn is_no_space(error: &io::Error) -> bool {
    error.raw_os_error() == Some(Errno::NOSPC.raw_os_error())
        || error.raw_os_error() == Some(Errno::DQUOT.raw_os_error())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_rules() {
        let policy = SpacePolicy { min_free_bytes: 100, min_free_percent: 10 };
        assert_eq!(policy.reserve(500), 100);
        assert_eq!(policy.reserve(10_000), 1000);
        let usage = DiskUsage { available: 1500, total: 10_000 };
        assert!(policy.has_room(usage, 500));
        assert!(!policy.has_room(usage, 501));
        assert!(!policy.has_room(usage, 2000));
    }

    #[test]
    fn preallocation_sets_length() {
        let dir = tempfile::tempdir().unwrap();
        let file = File::create(dir.path().join("f")).unwrap();
        preallocate(&file, 3 << 20).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 3 << 20);
        preallocate(&file, 0).unwrap();
        assert!(disk_usage(dir.path()).unwrap().total > 0);
    }
}
