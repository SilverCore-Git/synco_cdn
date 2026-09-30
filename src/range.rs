//! Analyse de l'en-tête `Range` (RFC 9110, §14), limitée à une seule plage
//! d'octets. Pur, sans E/S, testé par entrées aléatoires.
//!
//! Règles appliquées :
//! - pas d'en-tête, unité autre que `bytes`, syntaxe invalide, ou plage
//!   inversée (`5-2`) : l'en-tête est ignoré, le fichier est servi en entier
//!   (comportement prévu par la RFC) ;
//! - plusieurs plages : refusées (416) — le client n'en demande jamais et une
//!   réponse `multipart/byteranges` n'apporterait rien ;
//! - plage qui commence au-delà du fichier : 416.

use crate::util::parse_decimal_u64;

/// Résultat de l'analyse, pour un fichier de taille connue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeRequest {
    /// Servir le fichier entier (200).
    Full,
    /// Servir `[start, end)` (206). Toujours non vide et dans le fichier.
    Partial { start: u64, end: u64 },
    /// Plage impossible à satisfaire (416).
    Unsatisfiable,
}

/// Longueur maximale acceptée pour l'en-tête ; au-delà il est ignoré.
const MAX_HEADER_LEN: usize = 256;

/// Analyse `header` pour un fichier de `len` octets.
pub fn parse_range(header: Option<&str>, len: u64) -> RangeRequest {
    let Some(header) = header else {
        return RangeRequest::Full;
    };
    if header.len() > MAX_HEADER_LEN {
        return RangeRequest::Full;
    }
    let Some((unit, spec)) = header.split_once('=') else {
        return RangeRequest::Full;
    };
    if !unit.trim().eq_ignore_ascii_case("bytes") {
        return RangeRequest::Full;
    }
    if spec.contains(',') {
        return RangeRequest::Unsatisfiable;
    }
    let Some((first, last)) = spec.trim().split_once('-') else {
        return RangeRequest::Full;
    };
    let (first, last) = (first.trim(), last.trim());

    match (first.is_empty(), last.is_empty()) {
        // `bytes=-n` : les n derniers octets.
        (true, false) => match parse_decimal_u64(last) {
            None => RangeRequest::Full,
            Some(0) => RangeRequest::Unsatisfiable,
            Some(_) if len == 0 => RangeRequest::Unsatisfiable,
            Some(suffix) => RangeRequest::Partial { start: len.saturating_sub(suffix), end: len },
        },
        // `bytes=a-` : de a jusqu'à la fin.
        (false, true) => match parse_decimal_u64(first) {
            None if is_digits(first) => RangeRequest::Unsatisfiable, // entier géant : hors fichier
            None => RangeRequest::Full,
            Some(start) if start >= len => RangeRequest::Unsatisfiable,
            Some(start) => RangeRequest::Partial { start, end: len },
        },
        // `bytes=a-b` : bornes incluses.
        (false, false) => match (parse_decimal_u64(first), parse_decimal_u64(last)) {
            (Some(start), Some(last)) if start > last => RangeRequest::Full,
            (Some(start), Some(_)) if start >= len => RangeRequest::Unsatisfiable,
            (Some(start), Some(last)) => RangeRequest::Partial {
                start,
                // `last` est inclus ; plafonné à la fin du fichier.
                end: last.saturating_add(1).min(len),
            },
            (None, _) if is_digits(first) && is_digits(last) => RangeRequest::Unsatisfiable,
            _ => RangeRequest::Full,
        },
        (true, true) => RangeRequest::Full,
    }
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use RangeRequest::{Full, Partial, Unsatisfiable};

    #[test]
    fn forms() {
        assert_eq!(parse_range(None, 100), Full);
        assert_eq!(parse_range(Some("bytes=0-9"), 100), Partial { start: 0, end: 10 });
        assert_eq!(parse_range(Some("bytes=90-"), 100), Partial { start: 90, end: 100 });
        assert_eq!(parse_range(Some("bytes=-10"), 100), Partial { start: 90, end: 100 });
        assert_eq!(parse_range(Some("bytes=-500"), 100), Partial { start: 0, end: 100 });
        assert_eq!(parse_range(Some("bytes=50-5000"), 100), Partial { start: 50, end: 100 });
        assert_eq!(parse_range(Some("BYTES = 1-1"), 100), Partial { start: 1, end: 2 });
    }

    #[test]
    fn out_of_file() {
        assert_eq!(parse_range(Some("bytes=100-"), 100), Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=100-200"), 100), Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=-0"), 100), Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=0-0"), 0), Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=-5"), 0), Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=99999999999999999999999-"), 100), Unsatisfiable);
    }

    #[test]
    fn ignored_or_refused() {
        assert_eq!(parse_range(Some("bytes=5-2"), 100), Full);
        assert_eq!(parse_range(Some("items=0-5"), 100), Full);
        assert_eq!(parse_range(Some("bytes=a-b"), 100), Full);
        assert_eq!(parse_range(Some("bytes=-"), 100), Full);
        assert_eq!(parse_range(Some("bytes=+1-2"), 100), Full);
        assert_eq!(parse_range(Some("bytes"), 100), Full);
        assert_eq!(parse_range(Some("bytes=0-1,5-6"), 100), Unsatisfiable);
    }

    proptest::proptest! {
        /// Pour toute entrée : pas de panique, et une plage partielle est
        /// toujours non vide et contenue dans le fichier.
        #[test]
        fn partial_is_always_within_file(header in ".{0,80}", len in 0u64..u64::MAX) {
            if let Partial { start, end } = parse_range(Some(&header), len) {
                proptest::prop_assert!(start < end && end <= len);
            }
        }

        #[test]
        fn numeric_forms_within_file(a in 0u64..10_000, b in 0u64..10_000, len in 0u64..10_000) {
            for header in [format!("bytes={a}-{b}"), format!("bytes={a}-"), format!("bytes=-{b}")] {
                if let Partial { start, end } = parse_range(Some(&header), len) {
                    proptest::prop_assert!(start < end && end <= len);
                }
            }
        }
    }
}
