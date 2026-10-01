//! Fichier de session (`<tid>.session`) corrompu ou falsifié, tel que relu
//! au démarrage : ni panique, ni allocation démesurée. Toute session
//! reconstruite respecte les bornes des tickets.
//!
//! Entrée : 2 octets (longueur N des états de parts, petit-boutiste), N
//! octets d'états de parts, puis le JSON de l'enregistrement.
#![no_main]

use libfuzzer_sys::fuzz_target;
use synco_cdn::storage::session::{Phase, SessionRecord, UploadSession};
use synco_cdn::ticket::{MAX_PART_SIZE, MAX_PARTS, MIN_PART_SIZE};

fuzz_target!(|data: &[u8]| {
    let Some((len, rest)) = data.split_first_chunk::<2>() else {
        return;
    };
    let markers_len = usize::from(u16::from_le_bytes(*len)).min(rest.len());
    let (markers, json) = rest.split_at(markers_len);
    let Ok(record) = serde_json::from_slice::<SessionRecord>(json) else {
        return;
    };
    let Some(session) = UploadSession::new(
        record.tid,
        record.fid,
        record.sub,
        record.size,
        record.part_size,
        record.expires_at,
        0,
        markers,
        Phase::Aborted,
    ) else {
        return;
    };
    assert!((MIN_PART_SIZE..=MAX_PART_SIZE).contains(&session.part_size));
    assert!(session.part_count >= 1 && session.part_count <= MAX_PARTS);
    assert!(session.received_count() <= session.part_count);
    let _ = session.received_ranges();
});
