//! CORS strict (cf. docs/plan/03-protocole.md#cors).
//!
//! Seules les origines de la liste blanche reçoivent des en-têtes CORS. Les
//! en-têtes autorisés sont une liste fixe (jamais recopiés de la requête).
//! Pas de cookies : le ticket voyage dans `Authorization`.

use std::collections::HashSet;

use http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE, ACCESS_CONTROL_REQUEST_METHOD, VARY,
};
use http::{HeaderMap, HeaderValue, Method};

use crate::error::CdnError;
use crate::http::respond::{HttpResponse, no_content};

const ALLOW_HEADERS: &str = "authorization, content-type, range, x-part-index, x-part-sha256";
const EXPOSE_HEADERS: &str = "content-range, content-length, accept-ranges, etag, retry-after";
/// Durée de mise en cache du préflight (plafond de Chromium : 2 h).
const MAX_AGE_SECS: u64 = 7200;

#[derive(Debug, Clone, Default)]
pub struct CorsPolicy {
    origins: HashSet<String>,
}

impl CorsPolicy {
    pub fn new(origins: &[String]) -> Self {
        Self { origins: origins.iter().cloned().collect() }
    }

    fn allowed<'a>(&self, origin: Option<&'a HeaderValue>) -> Option<&'a HeaderValue> {
        origin.filter(|o| o.to_str().is_ok_and(|s| self.origins.contains(s)))
    }

    /// Ajoute les en-têtes CORS à une réponse ordinaire.
    pub fn apply(&self, origin: Option<&HeaderValue>, headers: &mut HeaderMap) {
        headers.insert(VARY, HeaderValue::from_static("origin"));
        if let Some(origin) = self.allowed(origin) {
            headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
            headers.insert(ACCESS_CONTROL_EXPOSE_HEADERS, HeaderValue::from_static(EXPOSE_HEADERS));
        }
    }

    /// Répond à une requête préalable `OPTIONS` pour une ressource qui
    /// accepte `methods` (`allow` : même liste, en texte).
    pub fn preflight(
        &self,
        request_headers: &HeaderMap,
        methods: &[Method],
        allow: &'static str,
    ) -> Result<HttpResponse, CdnError> {
        let origin = self
            .allowed(request_headers.get(http::header::ORIGIN))
            .ok_or(CdnError::forbidden("cors_forbidden", "Origine non autorisée."))?;
        let requested = request_headers
            .get(ACCESS_CONTROL_REQUEST_METHOD)
            .and_then(|m| Method::from_bytes(m.as_bytes()).ok())
            .ok_or(CdnError::bad_request("cors_bad_preflight", "Requête préalable invalide."))?;
        if !methods.contains(&requested) {
            return Err(CdnError::method_not_allowed());
        }

        let mut response = no_content();
        let headers = response.headers_mut();
        headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
        headers.insert(ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static(allow));
        headers.insert(ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static(ALLOW_HEADERS));
        headers.insert(ACCESS_CONTROL_MAX_AGE, HeaderValue::from(MAX_AGE_SECS));
        headers.insert(
            VARY,
            HeaderValue::from_static("origin, access-control-request-method, access-control-request-headers"),
        );
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::ORIGIN;

    fn policy() -> CorsPolicy {
        CorsPolicy::new(&["https://app.example".to_owned()])
    }

    #[test]
    fn only_listed_origins_get_headers() {
        let mut headers = HeaderMap::new();
        policy().apply(Some(&HeaderValue::from_static("https://evil.example")), &mut headers);
        assert!(headers.get(ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
        policy().apply(Some(&HeaderValue::from_static("https://app.example")), &mut headers);
        assert_eq!(headers.get(ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), "https://app.example");
    }

    #[test]
    fn preflight_rules() {
        let mut request = HeaderMap::new();
        request.insert(ORIGIN, HeaderValue::from_static("https://app.example"));
        request.insert(ACCESS_CONTROL_REQUEST_METHOD, HeaderValue::from_static("PUT"));
        let response = policy().preflight(&request, &[Method::PUT], "PUT").unwrap();
        assert_eq!(response.headers().get(ACCESS_CONTROL_MAX_AGE).unwrap(), "7200");
        assert!(policy().preflight(&request, &[Method::GET], "GET").is_err());
        request.insert(ORIGIN, HeaderValue::from_static("https://evil.example"));
        assert_eq!(policy().preflight(&request, &[Method::PUT], "PUT").unwrap_err().code, "cors_forbidden");
    }
}
