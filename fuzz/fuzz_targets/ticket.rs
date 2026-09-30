//! Vérification de tickets sur des entrées arbitraires : jamais de panique.
#![no_main]

use std::collections::HashMap;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use synco_cdn::ticket::{Operation, TicketPolicy, TicketVerifier};

fn verifier() -> &'static TicketVerifier {
    static VERIFIER: OnceLock<TicketVerifier> = OnceLock::new();
    VERIFIER.get_or_init(|| {
        let mut keys = HashMap::new();
        // Clé publique des vecteurs de tests/vectors/tickets.json.
        keys.insert("vec-1".to_owned(), "GX9rI-FshTLGq8g4-s1ep4m-DHaykgM0A5v6iz02jWE".to_owned());
        let policy = TicketPolicy { clock_skew_secs: 30, max_lifetime_secs: 7200, max_file_bytes: 10 << 30 };
        match TicketVerifier::new(&keys, policy) {
            Ok(verifier) => verifier,
            Err(error) => panic!("clé de fuzzing invalide : {error}"),
        }
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(token) = std::str::from_utf8(data) {
        let _ = verifier().verify(token, Operation::Upload, 1_759_230_000);
        let _ = verifier().verify(token, Operation::Download, 1_759_230_000);
    }
});
