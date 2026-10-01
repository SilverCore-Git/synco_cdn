//! Authentification des échanges internes API ↔ CDN (cf.
//! docs/plan/03-protocole.md#routes-internes).
//!
//! Chaque requête porte deux en-têtes :
//! - `X-Synco-Timestamp` : secondes Unix, acceptées à ±60 s (anti-rejeu) ;
//! - `X-Synco-Signature` : HMAC-SHA256 en hexadécimal de
//!   `MÉTHODE "\n" CHEMIN "\n" HORODATAGE "\n" CORPS`.
//!
//! La comparaison de la signature se fait en temps constant.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::util::{hex_decode, hex_encode, parse_decimal_u64};

pub const TIMESTAMP_HEADER: &str = "x-synco-timestamp";
pub const SIGNATURE_HEADER: &str = "x-synco-signature";
/// Écart maximal accepté entre l'horodatage et l'horloge locale.
pub const MAX_CLOCK_DRIFT_SECS: u64 = 60;
/// Longueur minimale du secret partagé.
pub const MIN_SECRET_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// Secret partagé. Son contenu n'apparaît jamais dans `Debug`.
#[derive(Clone)]
pub struct InternalSecret(Vec<u8>);

impl fmt::Debug for InternalSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InternalSecret(<masqué>)")
    }
}

impl InternalSecret {
    /// Construit le secret depuis sa forme hexadécimale (≥ 32 octets).
    pub fn from_hex(hex: &str) -> Result<Self, String> {
        let bytes = hex_decode(hex.trim()).ok_or("secret interne : hexadécimal invalide")?;
        if bytes.len() < MIN_SECRET_LEN {
            return Err(format!("secret interne : au moins {MIN_SECRET_LEN} octets requis"));
        }
        Ok(Self(bytes))
    }

    fn mac(&self, method: &str, path: &str, timestamp: &str, body: &[u8]) -> Option<HmacSha256> {
        let mut mac = HmacSha256::new_from_slice(&self.0).ok()?;
        mac.update(method.as_bytes());
        mac.update(b"\n");
        mac.update(path.as_bytes());
        mac.update(b"\n");
        mac.update(timestamp.as_bytes());
        mac.update(b"\n");
        mac.update(body);
        Some(mac)
    }

    /// Signature hexadécimale d'une requête sortante.
    pub fn sign(&self, method: &str, path: &str, timestamp: u64, body: &[u8]) -> String {
        match self.mac(method, path, &timestamp.to_string(), body) {
            Some(mac) => hex_encode(&mac.finalize().into_bytes()),
            // HMAC accepte des clés de toute longueur : branche impossible,
            // mais une signature vide sera simplement refusée par l'API.
            None => String::new(),
        }
    }

    /// Vérifie une requête entrante.
    pub fn verify(
        &self,
        method: &str,
        path: &str,
        timestamp: Option<&str>,
        signature: Option<&str>,
        body: &[u8],
        now: u64,
    ) -> bool {
        let (Some(timestamp), Some(signature)) = (timestamp, signature) else {
            return false;
        };
        let Some(ts) = parse_decimal_u64(timestamp) else {
            return false;
        };
        if ts.abs_diff(now) > MAX_CLOCK_DRIFT_SECS {
            return false;
        }
        let Some(expected) = hex_decode(signature) else {
            return false;
        };
        match self.mac(method, path, timestamp, body) {
            Some(mac) => mac.verify_slice(&expected).is_ok(),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> InternalSecret {
        InternalSecret::from_hex(&"ab".repeat(32)).unwrap()
    }

    #[test]
    fn sign_and_verify() {
        let s = secret();
        let sig = s.sign("POST", "/internal/v1/revocations", 1000, b"{}");
        assert!(s.verify("POST", "/internal/v1/revocations", Some("1000"), Some(&sig), b"{}", 1030));
        // Horodatage trop ancien.
        assert!(!s.verify("POST", "/internal/v1/revocations", Some("1000"), Some(&sig), b"{}", 1061));
        // Corps, chemin ou méthode modifiés.
        assert!(!s.verify("POST", "/internal/v1/revocations", Some("1000"), Some(&sig), b"{ }", 1000));
        assert!(!s.verify("POST", "/internal/v1/uploads", Some("1000"), Some(&sig), b"{}", 1000));
        assert!(!s.verify("DELETE", "/internal/v1/revocations", Some("1000"), Some(&sig), b"{}", 1000));
        assert!(!s.verify("POST", "/internal/v1/revocations", None, Some(&sig), b"{}", 1000));
        assert!(!s.verify("POST", "/internal/v1/revocations", Some("1000"), Some("zz"), b"{}", 1000));
    }

    /// Vecteur partagé avec synco_api (src/cdn/internalAuth.test.ts) : les
    /// deux implémentations doivent produire exactement cette signature.
    #[test]
    fn shared_vector() {
        let path = "/internal/cdn/uploads/6f1c1f3e-1c1a-4a70-9d1f-1b1c1d1e1f20/complete";
        let body = br#"{"tid":"6f1c1f3e-1c1a-4a70-9d1f-1b1c1d1e1f20"}"#;
        assert_eq!(
            secret().sign("POST", path, 1_759_230_000, body),
            "b1e12b4f12e8a7520abb8855452e36d2678e15f580c63e7de7f652e253e3ba51"
        );
    }

    #[test]
    fn secret_rules() {
        assert!(InternalSecret::from_hex("abcd").is_err());
        assert!(InternalSecret::from_hex("not hex").is_err());
        assert!(format!("{:?}", secret()).contains("masqué"));
    }
}
