//! Fichier de configuration arbitraire : erreur explicite, jamais de panique.
#![no_main]

use libfuzzer_sys::fuzz_target;
use synco_cdn::Config;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = Config::from_toml_str(text, []);
    }
});
