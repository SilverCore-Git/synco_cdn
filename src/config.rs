//! Configuration (cf. docs/plan/08-exploitation.md#configuration).
//!
//! Source : un fichier TOML, dont chaque clé peut être surchargée par une
//! variable d'environnement `SYNCO_CDN_<SECTION>__<CLÉ>` (double tiret bas
//! entre section et clé, par exemple `SYNCO_CDN_STORAGE__DATA_DIR`). La
//! valeur est lue comme une valeur TOML si possible (`true`, `42`, `["a"]`),
//! sinon comme une chaîne.
//!
//! Tout est validé ici : une valeur invalide empêche le démarrage avec un
//! message qui la nomme. Après le démarrage, la configuration ne peut plus
//! être invalide.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::internal_auth::InternalSecret;
use crate::ticket::{MAX_PART_SIZE, MAX_PARTS, TicketPolicy};
use crate::util::{parse_byte_size, parse_duration};

/// Préfixe des variables d'environnement de surcharge.
pub const ENV_PREFIX: &str = "SYNCO_CDN_";

/// Erreur de configuration, destinée à l'opérateur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn err<T>(message: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(message.into()))
}

/// Mode de service des téléchargements (cf. docs/plan/04-moteur-io.md#téléchargements).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DownloadMode {
    /// Le CDN lit et envoie lui-même les octets.
    Direct,
    /// Le CDN vérifie le ticket puis délègue l'envoi à nginx (`X-Accel-Redirect`).
    Accel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Text,
}

/// Configuration validée.
#[derive(Debug, Clone)]
pub struct Config {
    pub public_addr: SocketAddr,
    pub internal_addr: SocketAddr,

    pub data_dir: PathBuf,
    pub min_free_bytes: u64,
    pub min_free_percent: u8,
    pub strict_durability: bool,

    pub max_file_bytes: u64,
    pub buffer_budget_bytes: u64,
    pub max_connections: usize,
    pub max_parts_in_flight_per_transfer: u32,
    pub max_open_sessions: usize,

    pub worker_threads: usize,
    pub blocking_threads: usize,

    pub header_read_timeout: Duration,
    pub body_idle_timeout: Duration,
    pub shutdown_grace: Duration,

    pub ticket_keys: HashMap<String, String>,
    pub ticket_policy: TicketPolicy,

    pub api_internal_url: String,
    pub internal_secret: InternalSecret,
    pub api_callback_timeout: Duration,

    pub cors_allowed_origins: Vec<String>,

    pub download_mode: DownloadMode,
    pub accel_prefix: String,

    pub log_level: String,
    pub log_format: LogFormat,
}

// ---------------------------------------------------------------------------
// Forme brute, telle qu'écrite dans le fichier
// ---------------------------------------------------------------------------

/// Taille : entier (octets) ou chaîne lisible (`"20GiB"`).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum SizeValue {
    Bytes(u64),
    Text(String),
}

impl SizeValue {
    fn resolve(&self, key: &str) -> Result<u64, ConfigError> {
        match self {
            Self::Bytes(value) => Ok(*value),
            Self::Text(text) => parse_byte_size(text).map_err(|e| ConfigError(format!("{key} : {e}"))),
        }
    }
}

/// Durée : chaîne lisible (`"30s"`).
#[derive(Debug, Clone, Deserialize)]
#[serde(transparent)]
struct DurationValue(String);

impl DurationValue {
    fn resolve(&self, key: &str) -> Result<Duration, ConfigError> {
        let duration = parse_duration(&self.0).map_err(|e| ConfigError(format!("{key} : {e}")))?;
        if duration.is_zero() {
            return err(format!("{key} : doit être strictement positive"));
        }
        Ok(duration)
    }
}

fn dur(text: &str) -> DurationValue {
    DurationValue(text.to_owned())
}

fn size(text: &str) -> SizeValue {
    SizeValue::Text(text.to_owned())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    listen: RawListen,
    storage: RawStorage,
    #[serde(default)]
    limits: RawLimits,
    #[serde(default)]
    runtime: RawRuntime,
    #[serde(default)]
    timeouts: RawTimeouts,
    tickets: RawTickets,
    api: RawApi,
    #[serde(default)]
    cors: RawCors,
    #[serde(default)]
    downloads: RawDownloads,
    #[serde(default)]
    log: RawLog,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawListen {
    public: String,
    internal: String,
}

impl Default for RawListen {
    fn default() -> Self {
        Self { public: "127.0.0.1:9100".to_owned(), internal: "127.0.0.1:9101".to_owned() }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStorage {
    data_dir: PathBuf,
    #[serde(default = "default_min_free_bytes")]
    min_free_bytes: SizeValue,
    #[serde(default = "default_min_free_percent")]
    min_free_percent: u8,
    #[serde(default)]
    strict_durability: bool,
}

fn default_min_free_bytes() -> SizeValue {
    size("20GiB")
}

fn default_min_free_percent() -> u8 {
    5
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawLimits {
    max_file_bytes: SizeValue,
    buffer_budget_bytes: SizeValue,
    max_connections: usize,
    max_parts_in_flight_per_transfer: u32,
    max_open_sessions: usize,
}

impl Default for RawLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: size("10GiB"),
            buffer_budget_bytes: size("512MiB"),
            max_connections: 10_000,
            max_parts_in_flight_per_transfer: 8,
            max_open_sessions: 20_000,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawRuntime {
    /// 0 = nombre de cœurs.
    worker_threads: usize,
    /// 0 = 2 × nombre de cœurs.
    blocking_threads: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawTimeouts {
    header_read: DurationValue,
    body_idle: DurationValue,
    shutdown_grace: DurationValue,
}

impl Default for RawTimeouts {
    fn default() -> Self {
        Self { header_read: dur("10s"), body_idle: dur("30s"), shutdown_grace: dur("30s") }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTickets {
    public_keys: HashMap<String, String>,
    #[serde(default = "default_clock_skew")]
    clock_skew_seconds: u64,
    #[serde(default = "default_max_lifetime")]
    max_lifetime: DurationValue,
}

fn default_clock_skew() -> u64 {
    30
}

fn default_max_lifetime() -> DurationValue {
    dur("2h")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawApi {
    internal_url: String,
    /// Secret en hexadécimal, directement (pratique par variable d'environnement)…
    #[serde(default)]
    internal_secret: Option<String>,
    /// … ou dans un fichier (recommandé).
    #[serde(default)]
    internal_secret_file: Option<PathBuf>,
    #[serde(default = "default_callback_timeout")]
    callback_timeout: DurationValue,
}

fn default_callback_timeout() -> DurationValue {
    dur("5s")
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawCors {
    allowed_origins: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawDownloads {
    mode: DownloadMode,
    accel_prefix: String,
}

impl Default for RawDownloads {
    fn default() -> Self {
        Self { mode: DownloadMode::Direct, accel_prefix: "/_cdn_files/".to_owned() }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawLog {
    level: String,
    format: LogFormat,
}

impl Default for RawLog {
    fn default() -> Self {
        Self { level: "info".to_owned(), format: LogFormat::Json }
    }
}

// ---------------------------------------------------------------------------
// Chargement
// ---------------------------------------------------------------------------

impl Config {
    /// Charge `path`, applique les surcharges de l'environnement du
    /// processus, puis valide.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text =
            std::fs::read_to_string(path).map_err(|e| ConfigError(format!("lecture de {} : {e}", path.display())))?;
        Self::from_toml_str(&text, std::env::vars())
    }

    /// Analyse `text` avec les surcharges `env` (paires nom/valeur ; seules
    /// celles qui commencent par `SYNCO_CDN_` sont prises en compte).
    pub fn from_toml_str(text: &str, env: impl IntoIterator<Item = (String, String)>) -> Result<Self, ConfigError> {
        let mut table: toml::Table = toml::from_str(text).map_err(|e| ConfigError(format!("TOML invalide : {e}")))?;
        apply_env_overrides(&mut table, env)?;
        let raw: RawConfig = table.try_into().map_err(|e| ConfigError(format!("configuration invalide : {e}")))?;
        Self::validate(raw)
    }

    fn validate(raw: RawConfig) -> Result<Self, ConfigError> {
        let addr = |key: &str, value: &str| -> Result<SocketAddr, ConfigError> {
            value.parse().map_err(|_| ConfigError(format!("{key} : adresse invalide « {value} » (attendu ip:port)")))
        };
        let public_addr = addr("listen.public", &raw.listen.public)?;
        let internal_addr = addr("listen.internal", &raw.listen.internal)?;
        if public_addr == internal_addr && public_addr.port() != 0 {
            return err("listen.public et listen.internal doivent être différents");
        }
        if !internal_addr.ip().is_loopback() {
            tracing::warn!(%internal_addr, "l'écouteur interne n'est pas sur une adresse locale");
        }

        if raw.storage.data_dir.as_os_str().is_empty() {
            return err("storage.data_dir est requis");
        }
        if raw.storage.min_free_percent > 50 {
            return err("storage.min_free_percent : 50 au maximum");
        }

        let max_file_bytes = raw.limits.max_file_bytes.resolve("limits.max_file_bytes")?;
        if max_file_bytes == 0 || max_file_bytes > MAX_PART_SIZE.saturating_mul(MAX_PARTS) {
            return err("limits.max_file_bytes : hors bornes");
        }
        let buffer_budget_bytes = raw.limits.buffer_budget_bytes.resolve("limits.buffer_budget_bytes")?;
        if buffer_budget_bytes < (8 << 20) {
            return err("limits.buffer_budget_bytes : au moins 8MiB");
        }
        if raw.limits.max_connections == 0 {
            return err("limits.max_connections : au moins 1");
        }
        if !(1..=64).contains(&raw.limits.max_parts_in_flight_per_transfer) {
            return err("limits.max_parts_in_flight_per_transfer : entre 1 et 64");
        }
        if raw.limits.max_open_sessions == 0 {
            return err("limits.max_open_sessions : au moins 1");
        }

        let cores = std::thread::available_parallelism().map(usize::from).unwrap_or(1);
        let worker_threads = if raw.runtime.worker_threads == 0 { cores } else { raw.runtime.worker_threads };
        let blocking_threads = if raw.runtime.blocking_threads == 0 {
            cores.saturating_mul(2).max(4)
        } else {
            raw.runtime.blocking_threads
        };

        let max_lifetime = raw.tickets.max_lifetime.resolve("tickets.max_lifetime")?;
        if raw.tickets.clock_skew_seconds > 300 {
            return err("tickets.clock_skew_seconds : 300 au maximum");
        }
        let ticket_policy = TicketPolicy {
            clock_skew_secs: raw.tickets.clock_skew_seconds,
            max_lifetime_secs: max_lifetime.as_secs(),
            max_file_bytes,
        };
        // Les clés sont décodées ici pour échouer au démarrage, pas à la
        // première requête.
        crate::ticket::TicketVerifier::new(&raw.tickets.public_keys, ticket_policy)
            .map_err(|e| ConfigError(format!("tickets.public_keys : {e}")))?;

        let api_internal_url = validate_api_url(&raw.api.internal_url)?;
        let secret_hex = match (&raw.api.internal_secret, &raw.api.internal_secret_file) {
            (Some(hex), None) => hex.clone(),
            (None, Some(file)) => std::fs::read_to_string(file)
                .map_err(|e| ConfigError(format!("api.internal_secret_file ({}) : {e}", file.display())))?,
            _ => return err("api : exactement un de internal_secret ou internal_secret_file est requis"),
        };
        let internal_secret = InternalSecret::from_hex(&secret_hex).map_err(ConfigError)?;

        for origin in &raw.cors.allowed_origins {
            validate_origin(origin)?;
        }

        if !raw.downloads.accel_prefix.starts_with('/') || !raw.downloads.accel_prefix.ends_with('/') {
            return err("downloads.accel_prefix : doit commencer et finir par « / »");
        }

        Ok(Self {
            public_addr,
            internal_addr,
            data_dir: raw.storage.data_dir,
            min_free_bytes: raw.storage.min_free_bytes.resolve("storage.min_free_bytes")?,
            min_free_percent: raw.storage.min_free_percent,
            strict_durability: raw.storage.strict_durability,
            max_file_bytes,
            buffer_budget_bytes,
            max_connections: raw.limits.max_connections,
            max_parts_in_flight_per_transfer: raw.limits.max_parts_in_flight_per_transfer,
            max_open_sessions: raw.limits.max_open_sessions,
            worker_threads,
            blocking_threads,
            header_read_timeout: raw.timeouts.header_read.resolve("timeouts.header_read")?,
            body_idle_timeout: raw.timeouts.body_idle.resolve("timeouts.body_idle")?,
            shutdown_grace: raw.timeouts.shutdown_grace.resolve("timeouts.shutdown_grace")?,
            ticket_keys: raw.tickets.public_keys,
            ticket_policy,
            api_internal_url,
            internal_secret,
            api_callback_timeout: raw.api.callback_timeout.resolve("api.callback_timeout")?,
            cors_allowed_origins: raw.cors.allowed_origins,
            download_mode: raw.downloads.mode,
            accel_prefix: raw.downloads.accel_prefix,
            log_level: raw.log.level,
            log_format: raw.log.format,
        })
    }
}

/// Applique les variables `SYNCO_CDN_<SECTION>__<CLÉ>` sur la table TOML.
fn apply_env_overrides(
    table: &mut toml::Table,
    env: impl IntoIterator<Item = (String, String)>,
) -> Result<(), ConfigError> {
    for (name, value) in env {
        let Some(rest) = name.strip_prefix(ENV_PREFIX) else {
            continue;
        };
        let Some((section, key)) = rest.split_once("__") else {
            return err(format!("{name} : forme attendue {ENV_PREFIX}<SECTION>__<CLÉ>"));
        };
        let (section, key) = (section.to_ascii_lowercase(), key.to_ascii_lowercase());
        let parsed = toml::from_str::<toml::Table>(&format!("v = {value}"))
            .ok()
            .and_then(|mut t| t.remove("v"))
            .unwrap_or_else(|| toml::Value::String(value.clone()));
        let entry = table.entry(section.clone()).or_insert_with(|| toml::Value::Table(toml::Table::new()));
        let toml::Value::Table(section_table) = entry else {
            return err(format!("{name} : la section « {section} » n'est pas une table"));
        };
        section_table.insert(key, parsed);
    }
    Ok(())
}

/// L'API interne est jointe en HTTP clair sur le réseau local.
fn validate_api_url(url: &str) -> Result<String, ConfigError> {
    let trimmed = url.trim_end_matches('/');
    let uri: http::Uri =
        trimmed.parse().map_err(|_| ConfigError(format!("api.internal_url : URL invalide « {url} »")))?;
    if uri.scheme_str() != Some("http") || uri.authority().is_none() {
        return err("api.internal_url : URL http://hôte:port attendue");
    }
    if !matches!(uri.path(), "" | "/") || uri.query().is_some() {
        return err("api.internal_url : sans chemin ni paramètres");
    }
    Ok(trimmed.to_owned())
}

/// Une origine CORS est exactement `schéma://hôte[:port]`, sans joker.
fn validate_origin(origin: &str) -> Result<(), ConfigError> {
    let valid = origin.split_once("://").is_some_and(|(scheme, rest)| {
        !scheme.is_empty()
            && scheme.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'+' || b == b'-')
            && !rest.is_empty()
            && !rest.contains(['/', '*', '?', '#', ' '])
    });
    if valid {
        Ok(())
    } else {
        err(format!("cors.allowed_origins : origine invalide « {origin} » (schéma://hôte[:port])"))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Configuration minimale valide, pour les tests.
    pub fn minimal_toml(data_dir: &str, public_key_b64: &str) -> String {
        format!(
            r#"
[storage]
data_dir = "{data_dir}"
min_free_bytes = 0
min_free_percent = 0

[tickets]
public_keys = {{ "test" = "{public_key_b64}" }}

[api]
internal_url = "http://127.0.0.1:9"
internal_secret = "{secret}"
"#,
            secret = "ab".repeat(32)
        )
    }

    fn key() -> String {
        use base64::Engine;
        let key = crate::ticket::tests::signing_key().verifying_key();
        base64::engine::general_purpose::STANDARD.encode(key.to_bytes())
    }

    #[test]
    fn defaults() {
        let c = Config::from_toml_str(&minimal_toml("/srv/data", &key()), []).unwrap();
        assert_eq!(c.public_addr.to_string(), "127.0.0.1:9100");
        assert_eq!(c.max_file_bytes, 10 << 30);
        assert_eq!(c.body_idle_timeout, Duration::from_secs(30));
        assert_eq!(c.download_mode, DownloadMode::Direct);
        assert!(c.worker_threads >= 1);
        assert_eq!(c.ticket_policy.max_lifetime_secs, 7200);
    }

    #[test]
    fn env_overrides() {
        let env = [
            ("SYNCO_CDN_LIMITS__MAX_FILE_BYTES".to_owned(), "\"1GiB\"".to_owned()),
            ("SYNCO_CDN_STORAGE__STRICT_DURABILITY".to_owned(), "true".to_owned()),
            ("SYNCO_CDN_DOWNLOADS__MODE".to_owned(), "accel".to_owned()),
            ("SYNCO_CDN_CORS__ALLOWED_ORIGINS".to_owned(), "[\"https://app.example\"]".to_owned()),
            ("OTHER_VAR".to_owned(), "ignored".to_owned()),
        ];
        let c = Config::from_toml_str(&minimal_toml("/srv/data", &key()), env).unwrap();
        assert_eq!(c.max_file_bytes, 1 << 30);
        assert!(c.strict_durability);
        assert_eq!(c.download_mode, DownloadMode::Accel);
        assert_eq!(c.cors_allowed_origins, vec!["https://app.example".to_owned()]);
    }

    #[test]
    fn invalid_values_are_named() {
        let base = minimal_toml("/srv/data", &key());
        let check = |extra: &str| Config::from_toml_str(&format!("{base}\n{extra}"), []).unwrap_err().0;
        assert!(check("[limits]\nmax_parts_in_flight_per_transfer = 0").contains("max_parts_in_flight"));
        assert!(check("[cors]\nallowed_origins = [\"https://*.example\"]").contains("origine invalide"));
        assert!(check("[cors]\nallowed_origins = [\"https://app.example/\"]").contains("origine invalide"));
        assert!(check("[downloads]\naccel_prefix = \"files\"").contains("accel_prefix"));
        assert!(check("[log]\nunknown = 1").contains("unknown"));

        let bad_key = minimal_toml("/srv/data", "AAAA");
        assert!(Config::from_toml_str(&bad_key, []).unwrap_err().0.contains("public_keys"));
        let bad_url = base.replace("http://127.0.0.1:9", "https://api.example/x");
        assert!(Config::from_toml_str(&bad_url, []).unwrap_err().0.contains("internal_url"));
        let no_secret = base.replace(&format!("internal_secret = \"{}\"", "ab".repeat(32)), "");
        assert!(Config::from_toml_str(&no_secret, []).unwrap_err().0.contains("internal_secret"));
    }
}
