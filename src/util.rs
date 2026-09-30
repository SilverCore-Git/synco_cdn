//! Petites fonctions sans dépendance : temps, hexadécimal, tailles et durées
//! lisibles, conversions d'entiers sans troncature silencieuse.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Secondes écoulées depuis l'époque Unix. Une horloge système antérieure à
/// 1970 (machine mal réglée) donne 0 plutôt qu'une panique : les tickets
/// seront alors tous refusés comme « pas encore valides », ce qui est sûr.
pub fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Encode des octets en hexadécimal minuscule.
pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0x0f] {
            if let Some(&digit) = DIGITS.get(usize::from(nibble)) {
                out.push(char::from(digit));
            }
        }
    }
    out
}

/// Décode une chaîne hexadécimale (majuscules ou minuscules). `None` si la
/// longueur est impaire ou si un caractère n'est pas hexadécimal.
pub fn hex_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let (pairs, rest) = bytes.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    let value = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => c.checked_sub(b'0'),
            b'a'..=b'f' => c.checked_sub(b'a').and_then(|v| v.checked_add(10)),
            b'A'..=b'F' => c.checked_sub(b'A').and_then(|v| v.checked_add(10)),
            _ => None,
        }
    };
    pairs.iter().map(|[hi, lo]| Some((value(*hi)? << 4) | value(*lo)?)).collect()
}

/// Analyse un entier décimal strict : chiffres ASCII uniquement (pas de
/// signe, pas d'espace), au plus 20 caractères, sans débordement.
pub fn parse_decimal_u64(input: &str) -> Option<u64> {
    if input.is_empty() || input.len() > 20 || !input.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    input.parse::<u64>().ok()
}

/// Analyse une taille lisible : `1048576`, `512KiB`, `64MiB`, `20GiB`,
/// `1TiB` (unités binaires, sensibles à la casse), ou `B` explicite.
pub fn parse_byte_size(input: &str) -> Result<u64, String> {
    let trimmed = input.trim();
    let split = trimmed.find(|c: char| !c.is_ascii_digit()).unwrap_or(trimmed.len());
    let (digits, unit) = trimmed.split_at(split);
    let value = parse_decimal_u64(digits).ok_or_else(|| format!("taille invalide : « {input} »"))?;
    let multiplier: u64 = match unit.trim() {
        "" | "B" => 1,
        "KiB" => 1 << 10,
        "MiB" => 1 << 20,
        "GiB" => 1 << 30,
        "TiB" => 1 << 40,
        other => return Err(format!("unité de taille inconnue « {other} » (B, KiB, MiB, GiB, TiB)")),
    };
    value.checked_mul(multiplier).ok_or_else(|| format!("taille trop grande : « {input} »"))
}

/// Analyse une durée lisible : `500ms`, `30s`, `5m`, `2h`.
pub fn parse_duration(input: &str) -> Result<Duration, String> {
    let trimmed = input.trim();
    let split = trimmed.find(|c: char| !c.is_ascii_digit()).unwrap_or(trimmed.len());
    let (digits, unit) = trimmed.split_at(split);
    let value = parse_decimal_u64(digits).ok_or_else(|| format!("durée invalide : « {input} »"))?;
    let seconds = |factor: u64| {
        value.checked_mul(factor).map(Duration::from_secs).ok_or_else(|| format!("durée trop grande : « {input} »"))
    };
    match unit.trim() {
        "ms" => Ok(Duration::from_millis(value)),
        "s" => seconds(1),
        "m" => seconds(60),
        "h" => seconds(3600),
        other => Err(format!("unité de durée inconnue « {other} » (ms, s, m, h)")),
    }
}

/// `u64` → `usize`. Sur les plateformes 64 bits visées, la conversion ne
/// peut pas échouer ; l'erreur existe pour ne jamais tronquer en silence.
pub fn to_usize(value: u64) -> Option<usize> {
    usize::try_from(value).ok()
}

/// `usize` → `u64`, saturé (ne peut pas saturer sur les plateformes visées).
pub fn to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Durée en microsecondes, saturée.
pub fn duration_micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let bytes = [0u8, 1, 0x7f, 0x80, 0xff, 0xab];
        let encoded = hex_encode(&bytes);
        assert_eq!(encoded, "00017f80ffab");
        assert_eq!(hex_decode(&encoded).unwrap(), bytes);
        assert_eq!(hex_decode("00017F80FFAB").unwrap(), bytes);
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
    }

    #[test]
    fn decimal_is_strict() {
        assert_eq!(parse_decimal_u64("0"), Some(0));
        assert_eq!(parse_decimal_u64("18446744073709551615"), Some(u64::MAX));
        assert_eq!(parse_decimal_u64("18446744073709551616"), None);
        assert_eq!(parse_decimal_u64("+1"), None);
        assert_eq!(parse_decimal_u64(" 1"), None);
        assert_eq!(parse_decimal_u64(""), None);
    }

    #[test]
    fn sizes_and_durations() {
        assert_eq!(parse_byte_size("20GiB").unwrap(), 20 << 30);
        assert_eq!(parse_byte_size("512 MiB").unwrap(), 512 << 20);
        assert_eq!(parse_byte_size("1024").unwrap(), 1024);
        assert!(parse_byte_size("20GB").is_err());
        assert!(parse_byte_size("99999999999999999TiB").is_err());
        assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert!(parse_duration("5").is_err());
    }
}
