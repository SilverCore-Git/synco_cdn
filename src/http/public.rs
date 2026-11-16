//! Routage de l'écouteur public.

use http::{HeaderValue, Method, Request, StatusCode};
use hyper::body::Incoming;
use uuid::Uuid;

use crate::error::CdnError;
use crate::http::respond::{HttpResponse, text};
use crate::http::{downloads, uploads};
use crate::metrics::Route;
use crate::state::{AppState, RequestLog};

/// Ressources publiques.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    Health,
    Uploads,
    Upload(Uuid),
    UploadPart(Uuid),
    UploadComplete(Uuid),
    File(Uuid),
}

impl Resource {
    /// Analyse strictement le chemin (sans paramètres) ; `None` = 404.
    pub fn parse(path: &str) -> Option<Self> {
        let mut segments = path.strip_prefix('/')?.split('/');
        let resource = match (segments.next(), segments.next(), segments.next(), segments.next()) {
            (Some("healthz"), None, None, None) => Self::Health,
            (Some("v1"), Some("uploads"), None, None) => Self::Uploads,
            (Some("v1"), Some("uploads"), Some(tid), None) => Self::Upload(parse_id(tid)?),
            (Some("v1"), Some("uploads"), Some(tid), Some("part")) => Self::UploadPart(parse_id(tid)?),
            (Some("v1"), Some("uploads"), Some(tid), Some("complete")) => Self::UploadComplete(parse_id(tid)?),
            (Some("v1"), Some("files"), Some(fid), None) => Self::File(parse_id(fid)?),
            _ => return None,
        };
        segments.next().is_none().then_some(resource)
    }

    /// Méthodes acceptées (préflight CORS et `405`).
    pub fn methods(self) -> (&'static [Method], &'static str) {
        match self {
            Self::Health => (&[Method::GET], "GET"),
            Self::Uploads => (&[Method::POST], "POST"),
            Self::Upload(_) => (&[Method::GET, Method::DELETE], "GET, DELETE"),
            Self::UploadPart(_) => (&[Method::PUT], "PUT"),
            Self::UploadComplete(_) => (&[Method::POST], "POST"),
            Self::File(_) => (&[Method::GET, Method::HEAD], "GET, HEAD"),
        }
    }
}

/// Identifiant canonique (minuscule, avec tirets) uniquement.
pub fn parse_id(segment: &str) -> Option<Uuid> {
    let id = Uuid::try_parse(segment).ok()?;
    (id.hyphenated().to_string() == segment).then_some(id)
}

/// Route de métriques d'une requête, déterminée avant son traitement.
pub fn classify(method: &Method, path: &str) -> Route {
    let Some(resource) = Resource::parse(path) else {
        return Route::NotFound;
    };
    if method == Method::OPTIONS {
        return Route::Preflight;
    }
    match (resource, method.clone()) {
        (Resource::Health, _) => Route::Health,
        (Resource::Uploads, _) => Route::UploadOpen,
        (Resource::Upload(_), Method::DELETE) => Route::UploadAbort,
        (Resource::Upload(_), _) => Route::UploadStatus,
        (Resource::UploadPart(_), _) => Route::UploadPart,
        (Resource::UploadComplete(_), _) => Route::UploadComplete,
        (Resource::File(_), _) => Route::FileGet,
    }
}

pub async fn handle(
    state: &AppState,
    request: Request<Incoming>,
    log: &mut RequestLog,
) -> Result<HttpResponse, CdnError> {
    let resource =
        Resource::parse(request.uri().path()).ok_or(CdnError::not_found("not_found", "Ressource inconnue."))?;
    let method = request.method().clone();
    let (methods, allow) = resource.methods();

    if method == Method::OPTIONS {
        return state.cors().preflight(request.headers(), methods, allow);
    }
    if !methods.contains(&method) {
        return Err(CdnError::method_not_allowed());
    }

    let headers = request.headers();
    match resource {
        Resource::Health => Ok(health()),
        Resource::Uploads => uploads::open(state, headers, log).await,
        Resource::Upload(tid) if method == Method::DELETE => uploads::abort(state, headers, tid, log).await,
        Resource::Upload(tid) => uploads::status(state, headers, tid, log),
        Resource::UploadPart(tid) => uploads::part(state, request, tid, log).await,
        Resource::UploadComplete(tid) => uploads::complete(state, headers, tid, log).await,
        Resource::File(fid) => downloads::get(state, headers, fid, method == Method::HEAD, log).await,
    }
}

/// Version du binaire (Cargo.toml) et commit (variable `GIT_SHA` au moment de
/// la compilation, posée par l'image Docker), en en-têtes : le corps reste
/// « ok » pour les sondes existantes. Lus par synco_api (`/api/system/info`).
pub const VERSION_HEADER: &str = "x-synco-version";
pub const COMMIT_HEADER: &str = "x-synco-commit";

fn health() -> HttpResponse {
    let mut response = text(StatusCode::OK, "ok".to_owned(), "text/plain; charset=utf-8");
    let headers = response.headers_mut();
    headers.insert(VERSION_HEADER, HeaderValue::from_static(env!("CARGO_PKG_VERSION")));
    if let Some(value) = option_env!("GIT_SHA")
        .filter(|c| !c.is_empty())
        .and_then(|c| HeaderValue::from_str(c).ok())
    {
        headers.insert(COMMIT_HEADER, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0b7a2d8e-5b1f-4f55-8a33-2e4f5a6b7c8d";

    #[test]
    fn health_carries_version() {
        let response = health();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get(VERSION_HEADER).unwrap(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn paths() {
        let id = parse_id(ID).unwrap();
        assert_eq!(Resource::parse("/healthz"), Some(Resource::Health));
        assert_eq!(Resource::parse("/v1/uploads"), Some(Resource::Uploads));
        assert_eq!(Resource::parse(&format!("/v1/uploads/{ID}")), Some(Resource::Upload(id)));
        assert_eq!(Resource::parse(&format!("/v1/uploads/{ID}/part")), Some(Resource::UploadPart(id)));
        assert_eq!(Resource::parse(&format!("/v1/uploads/{ID}/complete")), Some(Resource::UploadComplete(id)));
        assert_eq!(Resource::parse(&format!("/v1/files/{ID}")), Some(Resource::File(id)));

        for bad in [
            "/",
            "",
            "/v1/uploads/",
            "/v1/files/../etc/passwd",
            "/v1/files/0B7A2D8E-5B1F-4F55-8A33-2E4F5A6B7C8D",
            "/v1/files/0b7a2d8e5b1f4f558a332e4f5a6b7c8d",
            &format!("/v1/files/{ID}/x"),
            &format!("/v1/uploads/{ID}/part/1"),
            &format!("//v1/files/{ID}"),
        ] {
            assert_eq!(Resource::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn classification() {
        assert_eq!(classify(&Method::OPTIONS, "/v1/uploads"), Route::Preflight);
        assert_eq!(classify(&Method::DELETE, &format!("/v1/uploads/{ID}")), Route::UploadAbort);
        assert_eq!(classify(&Method::GET, &format!("/v1/uploads/{ID}")), Route::UploadStatus);
        assert_eq!(classify(&Method::GET, "/nope"), Route::NotFound);
    }
}
