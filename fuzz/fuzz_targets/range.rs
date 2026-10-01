//! En-tête `Range` arbitraire : jamais de panique, et une plage acceptée est
//! toujours non vide et contenue dans le fichier.
//!
//! Entrée : 8 octets (taille du fichier, petit-boutiste) puis l'en-tête.
#![no_main]

use libfuzzer_sys::fuzz_target;
use synco_cdn::range::{RangeRequest, parse_range};

fuzz_target!(|data: &[u8]| {
    let Some((len_bytes, header)) = data.split_first_chunk::<8>() else {
        return;
    };
    let len = u64::from_le_bytes(*len_bytes);
    let Ok(header) = std::str::from_utf8(header) else {
        return;
    };
    if let RangeRequest::Partial { start, end } = parse_range(Some(header), len) {
        assert!(start < end && end <= len, "plage hors fichier : {start}..{end} / {len}");
    }
});
