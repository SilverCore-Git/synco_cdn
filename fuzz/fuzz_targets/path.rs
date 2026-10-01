//! Chemins d'URL arbitraires : jamais de panique, et tout identifiant accepté
//! est sous forme canonique (seule forme utilisée pour construire un chemin
//! sur disque).
#![no_main]

use http::Method;
use libfuzzer_sys::fuzz_target;
use synco_cdn::http::{internal, public};

fuzz_target!(|data: &[u8]| {
    let Ok(path) = std::str::from_utf8(data) else {
        return;
    };
    if let Some(resource) = public::Resource::parse(path) {
        let id = match resource {
            public::Resource::Upload(id)
            | public::Resource::UploadPart(id)
            | public::Resource::UploadComplete(id)
            | public::Resource::File(id) => Some(id),
            public::Resource::Health | public::Resource::Uploads => None,
        };
        if let Some(id) = id {
            assert!(path.contains(&id.hyphenated().to_string()), "identifiant non canonique accepté : {path}");
        }
    }
    for method in [Method::GET, Method::PUT, Method::POST, Method::DELETE, Method::OPTIONS] {
        let _ = public::classify(&method, path);
        let _ = internal::classify(&method, path);
    }
});
