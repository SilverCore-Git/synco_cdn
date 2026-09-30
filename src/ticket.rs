//! Tickets d'accès signés par synco_api (cf. docs/plan/02-tickets.md).
//!
//! Format : `sct1.<kid>.<payload base64url>.<signature base64url>`, où la
//! signature Ed25519 couvre `"synco-cdn-ticket\0" || "sct1." || kid || "." ||
//! payload`. Ce module ne fait aucune E/S : il reçoit une chaîne non fiable
//! et renvoie soit un ticket validé, soit une erreur. Il est testé par des
//! vecteurs produits par une implémentation Node indépendante et par des
//! entrées aléatoires.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use uuid::Uuid;

use crate::util::parse_decimal_u64;

/// Version du format, premier segment du ticket.
pub const TICKET_PREFIX: &str = "sct1";
/// Préfixe de domaine des octets signés : une signature de ticket n'est
/// jamais valable pour un autre usage de la même clé.
pub const SIGNING_DOMAIN: &[u8] = b"synco-cdn-ticket\x00";
/// Longueur maximale d'un ticket, vérifiée avant tout décodage.
pub const MAX_TICKET_LEN: usize = 2048;
/// Bornes de la taille d'une part d'envoi.
pub const MIN_PART_SIZE: u64 = 64 * 1024;
pub const MAX_PART_SIZE: u64 = 64 * 1024 * 1024;
/// Nombre maximal de parts d'un envoi.
pub const MAX_PARTS: u64 = 100_000;
const MAX_KID_LEN: usize = 32;
const MAX_SUB_LEN: usize = 64;

/// Opération autorisée par un ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Upload,
    Download,
}

/// Paramètres propres à l'opération.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TicketScope {
    Upload {
        /// Taille exacte du fichier stocké.
        size: u64,
        /// Taille d'une part (la dernière est plus courte).
        part_size: u64,
        /// Nombre de parts, déduit de `size` et `part_size`.
        part_count: u64,
    },
    Download {
        /// Taille du fichier au moment de l'émission.
        size: u64,
        /// Date de modification du fichier (ns depuis l'époque) à l'émission.
        mtime_ns: u64,
    },
}

/// Ticket dont la signature et les champs ont été vérifiés.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub tid: Uuid,
    pub fid: Uuid,
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    pub scope: TicketScope,
}

impl Ticket {
    pub fn operation(&self) -> Operation {
        match self.scope {
            TicketScope::Upload { .. } => Operation::Upload,
            TicketScope::Download { .. } => Operation::Download,
        }
    }
}

/// Raison d'un refus. Le code machine est renvoyé au client ; le détail
/// n'est jamais plus précis que nécessaire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TicketError {
    #[error("ticket manquant")]
    Missing,
    #[error("ticket mal formé")]
    Malformed,
    #[error("clé de signature inconnue")]
    UnknownKey,
    #[error("signature invalide")]
    BadSignature,
    #[error("champs invalides")]
    InvalidClaims,
    #[error("ticket expiré")]
    Expired,
    #[error("ticket pas encore valide")]
    NotYetValid,
    #[error("ticket révoqué")]
    Revoked,
    #[error("opération non autorisée par ce ticket")]
    WrongOperation,
    #[error("ressource non couverte par ce ticket")]
    WrongTarget,
}

impl TicketError {
    /// Code machine renvoyé dans le champ `error` de la réponse.
    pub fn code(self) -> &'static str {
        match self {
            Self::Missing => "ticket_missing",
            Self::Malformed | Self::BadSignature | Self::InvalidClaims | Self::NotYetValid => "ticket_invalid",
            Self::UnknownKey => "ticket_unknown_key",
            Self::Expired => "ticket_expired",
            Self::Revoked => "ticket_revoked",
            Self::WrongOperation => "ticket_wrong_operation",
            Self::WrongTarget => "ticket_wrong_target",
        }
    }
}

/// Contenu JSON du ticket, désérialisé strictement : tout champ inconnu
/// est une erreur.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClaims {
    op: String,
    tid: Uuid,
    fid: Uuid,
    sub: String,
    iat: u64,
    exp: u64,
    size: u64,
    #[serde(default)]
    psz: Option<u64>,
    #[serde(default)]
    mtime: Option<String>,
}

/// Paramètres de validation qui ne dépendent pas des clés.
#[derive(Debug, Clone, Copy)]
pub struct TicketPolicy {
    /// Tolérance d'horloge entre l'API et le CDN.
    pub clock_skew_secs: u64,
    /// Durée de vie maximale acceptée (`exp - iat`), garde-fou contre une
    /// erreur de l'API.
    pub max_lifetime_secs: u64,
    /// Taille maximale d'un fichier envoyé.
    pub max_file_bytes: u64,
}

/// Vérificateur de tickets : ensemble de clés publiques (`kid` → clé) et
/// politique de validation. Rechargeable sans redémarrage (rotation).
#[derive(Debug)]
pub struct TicketVerifier {
    keys: HashMap<String, VerifyingKey>,
    policy: TicketPolicy,
}

impl TicketVerifier {
    /// Construit le vérificateur. Les clés sont encodées en base64 (standard
    /// ou url, avec ou sans remplissage) et font 32 octets.
    pub fn new(encoded_keys: &HashMap<String, String>, policy: TicketPolicy) -> Result<Self, String> {
        if encoded_keys.is_empty() {
            return Err("au moins une clé publique de ticket est requise".to_owned());
        }
        let mut keys = HashMap::with_capacity(encoded_keys.len());
        for (kid, encoded) in encoded_keys {
            if !is_valid_kid(kid) {
                return Err(format!("identifiant de clé invalide « {kid} » ([a-z0-9-], 1 à 32 caractères)"));
            }
            let raw = decode_base64_any(encoded.trim()).ok_or_else(|| format!("clé « {kid} » : base64 invalide"))?;
            let bytes: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| format!("clé « {kid} » : 32 octets attendus, {} reçus", raw.len()))?;
            let key = VerifyingKey::from_bytes(&bytes).map_err(|_| format!("clé « {kid} » : clé Ed25519 invalide"))?;
            keys.insert(kid.clone(), key);
        }
        Ok(Self { keys, policy })
    }

    pub fn policy(&self) -> TicketPolicy {
        self.policy
    }

    /// Vérifie un ticket pour l'opération `expected` à l'instant `now`
    /// (secondes Unix). La signature est vérifiée avant toute analyse du
    /// JSON : un attaquant ne peut atteindre le désérialiseur qu'avec un
    /// contenu signé par l'API.
    pub fn verify(&self, token: &str, expected: Operation, now: u64) -> Result<Ticket, TicketError> {
        if token.is_empty() {
            return Err(TicketError::Missing);
        }
        if token.len() > MAX_TICKET_LEN || !token.is_ascii() {
            return Err(TicketError::Malformed);
        }

        let mut parts = token.split('.');
        let (Some(prefix), Some(kid), Some(payload_b64), Some(signature_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(TicketError::Malformed);
        };
        if prefix != TICKET_PREFIX || !is_valid_kid(kid) {
            return Err(TicketError::Malformed);
        }

        let key = self.keys.get(kid).ok_or(TicketError::UnknownKey)?;

        let signature_bytes = URL_SAFE_NO_PAD.decode(signature_b64).map_err(|_| TicketError::Malformed)?;
        let signature = Signature::from_slice(&signature_bytes).map_err(|_| TicketError::Malformed)?;

        let message = signed_message(kid, payload_b64);
        key.verify_strict(&message, &signature).map_err(|_| TicketError::BadSignature)?;

        let payload = URL_SAFE_NO_PAD.decode(payload_b64).map_err(|_| TicketError::Malformed)?;
        let claims: RawClaims = serde_json::from_slice(&payload).map_err(|_| TicketError::InvalidClaims)?;

        let ticket = self.validate_claims(claims)?;
        self.check_time(&ticket, now)?;
        if ticket.operation() != expected {
            return Err(TicketError::WrongOperation);
        }
        Ok(ticket)
    }

    fn validate_claims(&self, claims: RawClaims) -> Result<Ticket, TicketError> {
        let sub_ok =
            !claims.sub.is_empty() && claims.sub.len() <= MAX_SUB_LEN && !claims.sub.chars().any(char::is_control);
        if !sub_ok || claims.iat > claims.exp {
            return Err(TicketError::InvalidClaims);
        }
        let lifetime = claims.exp.checked_sub(claims.iat).ok_or(TicketError::InvalidClaims)?;
        if lifetime > self.policy.max_lifetime_secs {
            return Err(TicketError::InvalidClaims);
        }

        let scope = match (claims.op.as_str(), claims.psz, claims.mtime) {
            ("up", Some(part_size), None) => {
                if !(MIN_PART_SIZE..=MAX_PART_SIZE).contains(&part_size) || claims.size > self.policy.max_file_bytes {
                    return Err(TicketError::InvalidClaims);
                }
                let part_count = part_count(claims.size, part_size).ok_or(TicketError::InvalidClaims)?;
                if part_count > MAX_PARTS {
                    return Err(TicketError::InvalidClaims);
                }
                TicketScope::Upload { size: claims.size, part_size, part_count }
            }
            ("down", None, Some(mtime)) => TicketScope::Download {
                size: claims.size,
                mtime_ns: parse_decimal_u64(&mtime).ok_or(TicketError::InvalidClaims)?,
            },
            _ => return Err(TicketError::InvalidClaims),
        };

        Ok(Ticket { tid: claims.tid, fid: claims.fid, sub: claims.sub, iat: claims.iat, exp: claims.exp, scope })
    }

    fn check_time(&self, ticket: &Ticket, now: u64) -> Result<(), TicketError> {
        let skew = self.policy.clock_skew_secs;
        if ticket.iat > now.saturating_add(skew) {
            return Err(TicketError::NotYetValid);
        }
        if now >= ticket.exp.saturating_add(skew) {
            return Err(TicketError::Expired);
        }
        Ok(())
    }
}

/// Nombre de parts d'un fichier : au moins une (un fichier vide est une
/// part de 0 octet). `None` si `part_size` vaut 0.
pub fn part_count(size: u64, part_size: u64) -> Option<u64> {
    if part_size == 0 {
        return None;
    }
    Some(size.div_ceil(part_size).max(1))
}

/// Octets couverts par la signature.
pub fn signed_message(kid: &str, payload_b64: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        SIGNING_DOMAIN
            .len()
            .saturating_add(TICKET_PREFIX.len())
            .saturating_add(kid.len())
            .saturating_add(payload_b64.len())
            .saturating_add(2),
    );
    message.extend_from_slice(SIGNING_DOMAIN);
    message.extend_from_slice(TICKET_PREFIX.as_bytes());
    message.push(b'.');
    message.extend_from_slice(kid.as_bytes());
    message.push(b'.');
    message.extend_from_slice(payload_b64.as_bytes());
    message
}

fn is_valid_kid(kid: &str) -> bool {
    !kid.is_empty()
        && kid.len() <= MAX_KID_LEN
        && kid.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Décode du base64 standard ou url, avec ou sans remplissage.
pub fn decode_base64_any(input: &str) -> Option<Vec<u8>> {
    let unpadded = input.trim_end_matches('=');
    URL_SAFE_NO_PAD.decode(unpadded).ok().or_else(|| STANDARD.decode(input).ok())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    pub const TEST_SEED: [u8; 32] = [7u8; 32];
    pub const TEST_KID: &str = "test";

    pub fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&TEST_SEED)
    }

    pub fn sign_payload(kid: &str, payload: &serde_json::Value) -> String {
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
        let signature = signing_key().sign(&signed_message(kid, &payload_b64));
        format!("{TICKET_PREFIX}.{kid}.{payload_b64}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    pub fn verifier() -> TicketVerifier {
        let mut keys = HashMap::new();
        keys.insert(TEST_KID.to_owned(), STANDARD.encode(signing_key().verifying_key().to_bytes()));
        TicketVerifier::new(
            &keys,
            TicketPolicy { clock_skew_secs: 30, max_lifetime_secs: 7200, max_file_bytes: 10 << 30 },
        )
        .unwrap()
    }

    fn upload_claims() -> serde_json::Value {
        serde_json::json!({
            "op": "up",
            "tid": "6f1c1f3e-1c1a-4a70-9d1f-1b1c1d1e1f20",
            "fid": "0b7a2d8e-5b1f-4f55-8a33-2e4f5a6b7c8d",
            "sub": "user-1",
            "iat": 1000, "exp": 4600,
            "size": 10_000_000u64, "psz": 4_194_320u64
        })
    }

    #[test]
    fn valid_upload_ticket() {
        let token = sign_payload(TEST_KID, &upload_claims());
        let ticket = verifier().verify(&token, Operation::Upload, 2000).unwrap();
        assert_eq!(ticket.sub, "user-1");
        assert_eq!(ticket.scope, TicketScope::Upload { size: 10_000_000, part_size: 4_194_320, part_count: 3 });
    }

    #[test]
    fn valid_download_ticket() {
        let claims = serde_json::json!({
            "op": "down",
            "tid": "6f1c1f3e-1c1a-4a70-9d1f-1b1c1d1e1f20",
            "fid": "0b7a2d8e-5b1f-4f55-8a33-2e4f5a6b7c8d",
            "sub": "user-1", "iat": 1000, "exp": 1900,
            "size": 42, "mtime": "1759230000123456789"
        });
        let token = sign_payload(TEST_KID, &claims);
        let ticket = verifier().verify(&token, Operation::Download, 1500).unwrap();
        assert_eq!(ticket.scope, TicketScope::Download { size: 42, mtime_ns: 1_759_230_000_123_456_789 });
        assert_eq!(verifier().verify(&token, Operation::Upload, 1500), Err(TicketError::WrongOperation));
    }

    #[test]
    fn time_window() {
        let token = sign_payload(TEST_KID, &upload_claims());
        let v = verifier();
        assert_eq!(v.verify(&token, Operation::Upload, 900), Err(TicketError::NotYetValid));
        assert!(v.verify(&token, Operation::Upload, 975).is_ok(), "tolérance d'horloge");
        assert!(v.verify(&token, Operation::Upload, 4620).is_ok(), "tolérance d'horloge");
        assert_eq!(v.verify(&token, Operation::Upload, 4630), Err(TicketError::Expired));
    }

    #[test]
    fn tampering_is_rejected() {
        let token = sign_payload(TEST_KID, &upload_claims());
        let v = verifier();

        let mut claims = upload_claims();
        claims["size"] = serde_json::json!(20_000_000u64);
        let forged_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let mut pieces: Vec<&str> = token.split('.').collect();
        pieces[2] = &forged_payload;
        assert_eq!(v.verify(&pieces.join("."), Operation::Upload, 2000), Err(TicketError::BadSignature));

        assert_eq!(v.verify(&token.replacen("sct1", "sct2", 1), Operation::Upload, 2000), Err(TicketError::Malformed));
        assert_eq!(
            v.verify(&token.replacen(".test.", ".other.", 1), Operation::Upload, 2000),
            Err(TicketError::UnknownKey)
        );
        assert_eq!(v.verify(&format!("{token}.x"), Operation::Upload, 2000), Err(TicketError::Malformed));
        assert_eq!(v.verify(&"a".repeat(MAX_TICKET_LEN + 1), Operation::Upload, 2000), Err(TicketError::Malformed));
        assert_eq!(v.verify("", Operation::Upload, 2000), Err(TicketError::Missing));
    }

    #[test]
    fn signature_is_domain_separated() {
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&upload_claims()).unwrap());
        // Même payload, signé sans le préfixe de domaine : refusé.
        let raw_message = format!("{TICKET_PREFIX}.{TEST_KID}.{payload_b64}");
        let signature = signing_key().sign(raw_message.as_bytes());
        let token = format!("{raw_message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
        assert_eq!(verifier().verify(&token, Operation::Upload, 2000), Err(TicketError::BadSignature));
    }

    #[test]
    fn claims_are_strict() {
        let v = verifier();
        let check = |mutate: &dyn Fn(&mut serde_json::Value)| {
            let mut claims = upload_claims();
            mutate(&mut claims);
            v.verify(&sign_payload(TEST_KID, &claims), Operation::Upload, 2000)
        };
        assert_eq!(check(&|c| c["extra"] = serde_json::json!(1)), Err(TicketError::InvalidClaims));
        assert_eq!(check(&|c| c["psz"] = serde_json::json!(1024)), Err(TicketError::InvalidClaims));
        assert_eq!(check(&|c| c["size"] = serde_json::json!(11u64 << 30)), Err(TicketError::InvalidClaims));
        assert_eq!(check(&|c| c["exp"] = serde_json::json!(999_999)), Err(TicketError::InvalidClaims));
        assert_eq!(check(&|c| c["sub"] = serde_json::json!("")), Err(TicketError::InvalidClaims));
        assert_eq!(check(&|c| c["mtime"] = serde_json::json!("1")), Err(TicketError::InvalidClaims));
        assert_eq!(check(&|c| c["op"] = serde_json::json!("delete")), Err(TicketError::InvalidClaims));
        assert_eq!(check(&|c| c["tid"] = serde_json::json!("../../etc")), Err(TicketError::InvalidClaims));
        // 64 Kio × 100 001 parts : trop de parts.
        assert_eq!(
            check(&|c| {
                c["psz"] = serde_json::json!(MIN_PART_SIZE);
                c["size"] = serde_json::json!(MIN_PART_SIZE * (MAX_PARTS + 1));
            }),
            Err(TicketError::InvalidClaims)
        );
    }

    #[test]
    fn part_count_geometry() {
        assert_eq!(part_count(0, 10), Some(1));
        assert_eq!(part_count(10, 10), Some(1));
        assert_eq!(part_count(11, 10), Some(2));
        assert_eq!(part_count(u64::MAX, 1 << 20), Some(u64::MAX.div_ceil(1 << 20)));
        assert_eq!(part_count(5, 0), None);
    }

    proptest::proptest! {
        /// Aucune entrée, même absurde, ne fait paniquer le vérificateur.
        #[test]
        fn never_panics_on_arbitrary_input(input in ".{0,3000}") {
            let _ = verifier().verify(&input, Operation::Upload, 2000);
        }

        #[test]
        fn never_panics_on_structured_garbage(
            kid in "[a-z0-9-]{0,40}",
            payload in "[A-Za-z0-9_-]{0,200}",
            signature in "[A-Za-z0-9_-]{0,100}",
        ) {
            let token = format!("sct1.{kid}.{payload}.{signature}");
            let _ = verifier().verify(&token, Operation::Download, 2000);
        }
    }
}
