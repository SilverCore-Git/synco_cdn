//! Erreur unique du service et sa traduction en réponse HTTP.
//!
//! Chaque erreur porte un code machine stable (`error`), lu par le client,
//! et un message lisible (`message`). Ni l'un ni l'autre ne contient de
//! chemin, de nom de fichier ou de détail interne : la cause technique est
//! seulement journalisée.

use std::fmt;

use http::StatusCode;

use crate::ticket::TicketError;

/// Erreur renvoyée par un gestionnaire de requête.
#[derive(Debug)]
pub struct CdnError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: &'static str,
    /// Délai conseillé avant de réessayer (en-tête `Retry-After`).
    pub retry_after: Option<u64>,
    /// Taille du fichier, pour `Content-Range: bytes */<taille>` (416).
    pub unsatisfied_range_size: Option<u64>,
    /// Cause interne, journalisée mais jamais envoyée au client.
    pub source: Option<String>,
}

impl CdnError {
    const fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self { status, code, message, retry_after: None, unsatisfied_range_size: None, source: None }
    }

    pub const fn bad_request(code: &'static str, message: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    /// Erreur du client dont la cause technique est journalisée.
    pub fn bad_request_cause(code: &'static str, message: &'static str, cause: impl fmt::Display) -> Self {
        let mut error = Self::new(StatusCode::BAD_REQUEST, code, message);
        error.source = Some(cause.to_string());
        error
    }

    pub const fn forbidden(code: &'static str, message: &'static str) -> Self {
        Self::new(StatusCode::FORBIDDEN, code, message)
    }

    pub const fn not_found(code: &'static str, message: &'static str) -> Self {
        Self::new(StatusCode::NOT_FOUND, code, message)
    }

    pub const fn conflict(code: &'static str, message: &'static str) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }

    pub const fn method_not_allowed() -> Self {
        Self::new(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed", "Méthode non autorisée sur cette ressource.")
    }

    pub const fn unprocessable(code: &'static str, message: &'static str) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, code, message)
    }

    pub const fn request_timeout() -> Self {
        Self::new(StatusCode::REQUEST_TIMEOUT, "body_timeout", "Le corps de la requête a cessé d'arriver.")
    }

    /// Contre-pression : l'appelant doit réessayer après `retry_after` secondes.
    pub const fn too_many(code: &'static str, message: &'static str, retry_after: u64) -> Self {
        let mut error = Self::new(StatusCode::TOO_MANY_REQUESTS, code, message);
        error.retry_after = Some(retry_after);
        error
    }

    pub const fn unavailable(code: &'static str, message: &'static str, retry_after: u64) -> Self {
        let mut error = Self::new(StatusCode::SERVICE_UNAVAILABLE, code, message);
        error.retry_after = Some(retry_after);
        error
    }

    pub const fn insufficient_storage() -> Self {
        Self::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "insufficient_storage",
            "Espace de stockage du serveur insuffisant.",
        )
    }

    pub const fn range_not_satisfiable(size: u64) -> Self {
        let mut error = Self::new(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "range_not_satisfiable",
            "La plage demandée est hors du fichier.",
        );
        error.unsatisfied_range_size = Some(size);
        error
    }

    /// Erreur interne : `context` et `cause` sont journalisés, le client ne
    /// reçoit qu'un message générique.
    pub fn internal(context: &'static str, cause: impl fmt::Display) -> Self {
        let mut error = Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", "Erreur interne du service.");
        error.source = Some(format!("{context}: {cause}"));
        error
    }
}

impl fmt::Display for CdnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.status.as_u16(), self.code)?;
        if let Some(source) = &self.source {
            write!(f, " ({source})")?;
        }
        Ok(())
    }
}

impl std::error::Error for CdnError {}

impl From<std::io::Error> for CdnError {
    fn from(error: std::io::Error) -> Self {
        Self::internal("io", error)
    }
}

impl From<TicketError> for CdnError {
    fn from(error: TicketError) -> Self {
        let (status, message) = match error {
            TicketError::WrongOperation | TicketError::WrongTarget => {
                (StatusCode::FORBIDDEN, "Ce ticket n'autorise pas cette opération.")
            }
            TicketError::Expired => (StatusCode::UNAUTHORIZED, "Le ticket a expiré."),
            TicketError::Revoked => (StatusCode::UNAUTHORIZED, "Le ticket a été révoqué."),
            TicketError::Missing => (StatusCode::UNAUTHORIZED, "Ticket manquant."),
            _ => (StatusCode::UNAUTHORIZED, "Ticket invalide."),
        };
        Self::new(status, error.code(), message)
    }
}
