//! Chemins sur disque (cf. docs/plan/01-architecture.md#état-partagé).
//!
//! Tous les chemins sont construits à partir d'identifiants `Uuid` déjà
//! validés, jamais à partir d'une chaîne reçue : aucune traversée de
//! répertoire n'est possible.
//!
//! ```text
//! <data_dir>/
//! ├── <fid>.enc                  fichiers terminés (partagés avec synco_api)
//! └── .cdn-uploads/
//!     ├── <tid>.data             fichier en cours, préalloué
//!     ├── <tid>.parts            état des parts + empreinte de chacune
//!     ├── <tid>.session          contenu du ticket d'ouverture et phase
//!     └── revocations.json       liste de révocation
//! ```

use std::path::{Path, PathBuf};

use uuid::Uuid;

/// Nom du répertoire des envois en cours, dans `data_dir`.
pub const UPLOADS_DIR: &str = ".cdn-uploads";

#[derive(Debug, Clone)]
pub struct Layout {
    data_dir: PathBuf,
    uploads_dir: PathBuf,
}

impl Layout {
    pub fn new(data_dir: &Path) -> Self {
        Self { data_dir: data_dir.to_path_buf(), uploads_dir: data_dir.join(UPLOADS_DIR) }
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn uploads_dir(&self) -> &Path {
        &self.uploads_dir
    }

    /// Fichier terminé, au format attendu par synco_api (`<id>.enc`).
    pub fn final_path(&self, fid: Uuid) -> PathBuf {
        self.data_dir.join(format!("{}.enc", fid.hyphenated()))
    }

    pub fn session_data(&self, tid: Uuid) -> PathBuf {
        self.uploads_dir.join(format!("{}.data", tid.hyphenated()))
    }

    pub fn session_parts(&self, tid: Uuid) -> PathBuf {
        self.uploads_dir.join(format!("{}.parts", tid.hyphenated()))
    }

    pub fn session_record(&self, tid: Uuid) -> PathBuf {
        self.uploads_dir.join(format!("{}.session", tid.hyphenated()))
    }

    pub fn revocations(&self) -> PathBuf {
        self.uploads_dir.join("revocations.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_derived_from_ids() {
        let layout = Layout::new(Path::new("/srv/data"));
        let id = Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
        assert_eq!(layout.final_path(id), PathBuf::from("/srv/data/01234567-89ab-cdef-0123-456789abcdef.enc"));
        assert_eq!(
            layout.session_data(id),
            PathBuf::from("/srv/data/.cdn-uploads/01234567-89ab-cdef-0123-456789abcdef.data")
        );
    }
}
