//! Outillage des tests d'intégration : serveur CDN réel sur un répertoire
//! temporaire, fausse API synco_api (qui vérifie la signature HMAC des
//! rappels), clients HTTP/1.1 et HTTP/2, signature de tickets.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Value, json};
use synco_cdn::internal_auth::{InternalSecret, SIGNATURE_HEADER, TIMESTAMP_HEADER};
use synco_cdn::state::AppState;
use synco_cdn::{Config, Server};
use tokio::sync::oneshot;
use uuid::Uuid;

pub const SECRET_HEX: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
pub const ORIGIN: &str = "https://app.test";
pub const PART: u64 = 256 * 1024;

pub fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

/// Identifiant unique par appel (sans dépendre de la fonction « v4 » d'uuid).
pub fn fresh_id() -> Uuid {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    Uuid::from_u128((nanos << 32) ^ u128::from(n) ^ 0x4000_0000_0000_4000_8000_0000_0000_0000)
}

pub fn now() -> u64 {
    synco_cdn::util::now_unix()
}

// ---------------------------------------------------------------------------
// Tickets
// ---------------------------------------------------------------------------

pub fn sign(claims: &Value) -> String {
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let message = synco_cdn::ticket::signed_message("k1", &payload);
    let signature = signing_key().sign(&message);
    format!("sct1.k1.{payload}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

pub fn upload_ticket(tid: Uuid, fid: Uuid, size: u64, sub: &str) -> String {
    let now = now();
    sign(&json!({
        "op": "up", "tid": tid, "fid": fid, "sub": sub,
        "iat": now, "exp": now + 3600, "size": size, "psz": PART
    }))
}

pub fn download_ticket(fid: Uuid, path: &Path, sub: &str) -> String {
    let meta = std::fs::metadata(path).unwrap();
    let mtime = (meta.mtime() as u64) * 1_000_000_000 + meta.mtime_nsec() as u64;
    let now = now();
    sign(&json!({
        "op": "down", "tid": fresh_id(), "fid": fid, "sub": sub,
        "iat": now, "exp": now + 900, "size": meta.len(), "mtime": mtime.to_string()
    }))
}

// ---------------------------------------------------------------------------
// Fausse API
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiMode {
    Accept,
    Reject,
    Unavailable,
}

#[derive(Debug, Clone)]
pub struct ApiCall {
    pub path: String,
    pub body: Value,
    pub signature_valid: bool,
}

#[derive(Clone)]
pub struct FakeApi {
    pub addr: SocketAddr,
    pub mode: Arc<Mutex<ApiMode>>,
    pub calls: Arc<Mutex<Vec<ApiCall>>>,
}

impl FakeApi {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let api = Self { addr, mode: Arc::new(Mutex::new(ApiMode::Accept)), calls: Arc::new(Mutex::new(Vec::new())) };
        let handler = api.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { break };
                let handler = handler.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        let handler = handler.clone();
                        async move { Ok::<_, Infallible>(handler.handle(req).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        api
    }

    async fn handle(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        let (parts, body) = request.into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        let header = |n: &str| parts.headers.get(n).and_then(|v| v.to_str().ok()).map(str::to_owned);
        let secret = InternalSecret::from_hex(SECRET_HEX).unwrap();
        let signature_valid = secret.verify(
            parts.method.as_str(),
            parts.uri.path(),
            header(TIMESTAMP_HEADER).as_deref(),
            header(SIGNATURE_HEADER).as_deref(),
            &body,
            now(),
        );
        let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        self.calls.lock().unwrap().push(ApiCall {
            path: parts.uri.path().to_owned(),
            body: parsed.clone(),
            signature_valid,
        });

        let (status, response) = match *self.mode.lock().unwrap() {
            ApiMode::Accept => {
                (StatusCode::CREATED, json!({ "id": parsed["fid"], "size": parsed["size"], "isE2EE": true }))
            }
            ApiMode::Reject => (StatusCode::CONFLICT, json!({ "error": "transfer_expired" })),
            ApiMode::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, json!({ "error": "down" })),
        };
        let mut r = Response::new(Full::new(Bytes::from(serde_json::to_vec(&response).unwrap())));
        *r.status_mut() = status;
        r
    }

    pub fn set_mode(&self, mode: ApiMode) {
        *self.mode.lock().unwrap() = mode;
    }

    pub fn calls(&self) -> Vec<ApiCall> {
        self.calls.lock().unwrap().clone()
    }
}

// ---------------------------------------------------------------------------
// Serveur CDN
// ---------------------------------------------------------------------------

pub struct Cdn {
    pub public: SocketAddr,
    pub internal: SocketAddr,
    pub state: Arc<AppState>,
    pub data_dir: PathBuf,
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Cdn {
    pub async fn start(data_dir: &Path, api: &FakeApi, extra_toml: &str) -> Self {
        let config = format!(
            r#"
[listen]
public = "127.0.0.1:0"
internal = "127.0.0.1:0"

[storage]
data_dir = "{data}"
min_free_bytes = 0
min_free_percent = 0

[limits]
buffer_budget_bytes = "64MiB"

[timeouts]
body_idle = "3s"
shutdown_grace = "2s"

[tickets]
public_keys = {{ "k1" = "{key}" }}

[api]
internal_url = "http://{api}"
internal_secret = "{secret}"
callback_timeout = "2s"

[cors]
allowed_origins = ["{origin}"]
{extra_toml}
"#,
            data = data_dir.display(),
            key = STANDARD.encode(signing_key().verifying_key().to_bytes()),
            api = api.addr,
            secret = SECRET_HEX,
            origin = ORIGIN,
        );
        let config = Config::from_toml_str(&config, []).unwrap();
        let server = Server::build(config).await.unwrap();
        let (public, internal, state) =
            (server.public_addr().unwrap(), server.internal_addr().unwrap(), server.state());
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(server.run(async move {
            let _ = stopped.await;
        }));
        Self { public, internal, state, data_dir: data_dir.to_path_buf(), stop: Some(stop), task: Some(task) }
    }

    pub async fn stop(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.await.unwrap();
        }
    }

    pub fn final_path(&self, fid: Uuid) -> PathBuf {
        self.data_dir.join(format!("{fid}.enc"))
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct HttpClient {
    client: Client<HttpConnector, Full<Bytes>>,
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: http::HeaderMap,
    pub body: Bytes,
}

impl Reply {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    pub fn error_code(&self) -> String {
        self.json()["error"].as_str().unwrap_or_default().to_owned()
    }
}

impl HttpClient {
    pub fn http1() -> Self {
        Self { client: Client::builder(TokioExecutor::new()).build(HttpConnector::new()) }
    }

    /// HTTP/2 en clair avec connaissance préalable (comme nginx → CDN en h2c).
    pub fn http2() -> Self {
        Self { client: Client::builder(TokioExecutor::new()).http2_only(true).build(HttpConnector::new()) }
    }

    pub async fn send(&self, method: Method, url: String, headers: &[(&str, String)], body: Bytes) -> Reply {
        let mut request = Request::builder().method(method).uri(url);
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        let response = self.client.request(request.body(Full::new(body)).unwrap()).await.unwrap();
        let (parts, body) = response.into_parts();
        Reply { status: parts.status, headers: parts.headers, body: body.collect().await.unwrap().to_bytes() }
    }
}

pub fn bearer(ticket: &str) -> (&'static str, String) {
    ("authorization", format!("Bearer {ticket}"))
}

/// Données pseudo-aléatoires reproductibles.
pub fn pattern(len: usize, seed: u8) -> Vec<u8> {
    let mut state = u32::from(seed).wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state & 0xff) as u8
        })
        .collect()
}
