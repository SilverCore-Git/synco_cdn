//! En-tête Range arbitraire : jamais de panique, plage toujours dans le fichier.
#![no_main]

use libfuzzer_sys::fuzz_target;
use synco_cdn::range::{RangeRequest, parse_range};

fuzz_target!(|input: (&str, u64)| {
    let (header, len) = input;
    if let RangeRequest::Partial { start, end } = parse_range(Some(header), len) {
        assert!(start < end && end <= len);
    }
});
