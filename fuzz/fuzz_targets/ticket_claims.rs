//! Contenu de ticket arbitraire, *correctement signé* avec la clé de test.
//!
//! La cible `ticket` ne peut pas forger de signature : elle ne dépasse
//! jamais la vérification Ed25519. Celle-ci signe l'entrée du fuzzer pour
//! atteindre le désérialiseur JSON et la validation des champs, c'est-à-dire
//! tout ce qu'un bug de l'API (ou une clé compromise) pourrait présenter.
//! Toute acceptation doit respecter les bornes documentées.
#![no_main]

use std::collections::HashMap;
use std::sync::OnceLock;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;
use synco_cdn::ticket::{MAX_PART_SIZE, MAX_PARTS, MIN_PART_SIZE, Operation, TicketPolicy, TicketScope, TicketVerifier, signed_message};

const NOW: u64 = 1_759_230_000;
const POLICY: TicketPolicy = TicketPolicy { clock_skew_secs: 30, max_lifetime_secs: 7200, max_file_bytes: 10 << 30 };

fn key() -> &'static SigningKey {
    static KEY: OnceLock<SigningKey> = OnceLock::new();
    KEY.get_or_init(|| SigningKey::from_bytes(&[0x2a; 32]))
}

fn verifier() -> &'static TicketVerifier {
    static VERIFIER: OnceLock<TicketVerifier> = OnceLock::new();
    VERIFIER.get_or_init(|| {
        let mut keys = HashMap::new();
        keys.insert("fz".to_owned(), STANDARD.encode(key().verifying_key().to_bytes()));
        match TicketVerifier::new(&keys, POLICY) {
            Ok(verifier) => verifier,
            Err(error) => panic!("clé de fuzzing invalide : {error}"),
        }
    })
}

fuzz_target!(|payload: &[u8]| {
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
    let signature = key().sign(&signed_message("fz", &payload_b64));
    let token = format!("sct1.fz.{payload_b64}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));

    for op in [Operation::Upload, Operation::Download] {
        let Ok(ticket) = verifier().verify(&token, op, NOW) else {
            continue;
        };
        assert!(!ticket.sub.is_empty() && ticket.sub.len() <= 64);
        assert!(ticket.iat <= ticket.exp && ticket.exp - ticket.iat <= POLICY.max_lifetime_secs);
        assert!(ticket.iat <= NOW + POLICY.clock_skew_secs && NOW < ticket.exp + POLICY.clock_skew_secs);
        match ticket.scope {
            TicketScope::Upload { size, part_size, part_count } => {
                assert_eq!(op, Operation::Upload);
                assert!((MIN_PART_SIZE..=MAX_PART_SIZE).contains(&part_size));
                assert!(size <= POLICY.max_file_bytes);
                assert!(part_count >= 1 && part_count <= MAX_PARTS);
                assert_eq!(part_count, size.div_ceil(part_size).max(1));
            }
            TicketScope::Download { .. } => assert_eq!(op, Operation::Download),
        }
    }
});
