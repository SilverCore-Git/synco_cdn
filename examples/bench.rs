//! Mesure de débit : envoie puis télécharge plusieurs fichiers en parallèle
//! contre un serveur réel (même processus, boucle locale, disque réel).
//!
//! ```text
//! cargo run --release --example bench
//! BENCH_DIR=/srv/test BENCH_FILES=16 BENCH_SIZE_MIB=512 BENCH_PARTS=8 cargo run --release --example bench
//! ```
//!
//! | Variable          | Défaut            | Sens                                    |
//! |-------------------|-------------------|-----------------------------------------|
//! | `BENCH_DIR`       | `target/bench-data` | Répertoire de stockage (disque à mesurer) |
//! | `BENCH_FILES`     | 8                 | Fichiers envoyés en même temps          |
//! | `BENCH_SIZE_MIB`  | 256               | Taille de chaque fichier                |
//! | `BENCH_PARTS`     | 4                 | Parts en vol par fichier                |
//! | `BENCH_HTTP2`     | 0                 | 1 = HTTP/2 (h2c)                        |
//!
//! La boucle locale ne limite pas le débit : le résultat mesure le moteur
//! du CDN et le disque. Pour la référence disque : `fio` ou
//! `dd if=/dev/zero of=… bs=1M count=… conv=fdatasync`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::print_stdout
)]

use std::convert::Infallible;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::time::Instant;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
use http::{Method, Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::json;
use synco_cdn::{Config, Server};
use uuid::Uuid;

const PART: u64 = 4 * 1024 * 1024 + 16; // part E2EE v2 : 4 Mio + tag GCM
const SECRET: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn ticket(key: &SigningKey, claims: serde_json::Value) -> String {
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signature = key.sign(&synco_cdn::ticket::signed_message("b", &payload));
    format!("sct1.b.{payload}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

fn id(n: u64) -> Uuid {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    Uuid::from_u128((nanos << 16) ^ u128::from(n) ^ 0x4000_0000_0000_4000_8000_0000_0000_0000)
}

/// Requête avec ticket ; le corps de réponse est lu puis jeté.
async fn send(
    client: &Client<HttpConnector, Full<Bytes>>,
    method: Method,
    url: String,
    ticket: &str,
    part_index: Option<u64>,
    body: Bytes,
) -> http::StatusCode {
    let mut request = Request::builder().method(method).uri(url).header("authorization", format!("Bearer {ticket}"));
    if let Some(index) = part_index {
        request = request.header("x-part-index", index.to_string());
    }
    let response = client.request(request.body(Full::new(body)).unwrap()).await.unwrap();
    let status = response.status();
    let _ = response.into_body().collect().await;
    status
}

/// Fausse API qui accepte tous les rappels.
async fn fake_api() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let service = service_fn(|_req| async {
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"{}"))))
                });
                let _ =
                    hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service).await;
            });
        }
    });
    addr
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let files = env("BENCH_FILES", 8);
    let size = env("BENCH_SIZE_MIB", 256) * 1024 * 1024;
    let parts_in_flight = env("BENCH_PARTS", 4) as usize;
    let http2 = env("BENCH_HTTP2", 0) == 1;
    let dir = std::env::var("BENCH_DIR").unwrap_or_else(|_| "target/bench-data".into());
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let key = SigningKey::from_bytes(&[3u8; 32]);
    let api = fake_api().await;
    let config = Config::from_toml_str(
        &format!(
            r#"
[listen]
public = "127.0.0.1:0"
internal = "127.0.0.1:0"
[storage]
data_dir = "{dir}"
min_free_bytes = 0
min_free_percent = 0
[limits]
max_parts_in_flight_per_transfer = 64
[tickets]
public_keys = {{ "b" = "{key}" }}
[api]
internal_url = "http://{api}"
internal_secret = "{SECRET}"
[log]
level = "warn"
"#,
            key = STANDARD.encode(key.verifying_key().to_bytes()),
        ),
        [],
    )
    .unwrap();
    let server = Server::build(config).await.unwrap();
    let base = format!("http://{}", server.public_addr().unwrap());
    tokio::spawn(server.run(std::future::pending()));

    let client: Client<HttpConnector, Full<Bytes>> = if http2 {
        Client::builder(TokioExecutor::new()).http2_only(true).build(HttpConnector::new())
    } else {
        Client::builder(TokioExecutor::new()).pool_max_idle_per_host(256).build(HttpConnector::new())
    };
    let part_data = Bytes::from((0..PART).map(|i| (i % 251) as u8).collect::<Vec<u8>>());
    let part_count = size.div_ceil(PART);
    let total = size * files;

    println!(
        "{files} fichiers × {} Mio, parts de {} octets, {parts_in_flight} parts en vol par fichier, {}",
        size >> 20,
        PART,
        if http2 { "HTTP/2" } else { "HTTP/1.1" }
    );

    // --- Envoi --------------------------------------------------------------
    let now = synco_cdn::util::now_unix();
    let started = Instant::now();
    let mut uploads = Vec::new();
    let mut fids = Vec::new();
    for n in 0..files {
        let (tid, fid) = (id(n * 2), id(n * 2 + 1));
        fids.push(fid);
        let t = ticket(
            &key,
            json!({"op":"up","tid":tid,"fid":fid,"sub":"bench","iat":now,"exp":now+3600,"size":size,"psz":PART}),
        );
        let (client, base, part_data) = (client.clone(), base.clone(), part_data.clone());
        uploads.push(tokio::spawn(async move {
            let open = send(&client, Method::POST, format!("{base}/v1/uploads"), &t, None, Bytes::new()).await;
            assert!(open.is_success(), "ouverture : {open}");
            let next = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let mut workers = Vec::new();
            for _ in 0..parts_in_flight {
                let (next, client, t, base, part_data) =
                    (Arc::clone(&next), client.clone(), t.clone(), base.clone(), part_data.clone());
                workers.push(tokio::spawn(async move {
                    loop {
                        let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if index >= part_count {
                            break;
                        }
                        let len = (size - index * PART).min(PART) as usize;
                        let url = format!("{base}/v1/uploads/{tid}/part");
                        let status = send(&client, Method::PUT, url, &t, Some(index), part_data.slice(..len)).await;
                        assert_eq!(status, 204);
                    }
                }));
            }
            for w in workers {
                w.await.unwrap();
            }
            let done =
                send(&client, Method::POST, format!("{base}/v1/uploads/{tid}/complete"), &t, None, Bytes::new()).await;
            assert!(done.is_success(), "finalisation : {done}");
        }));
    }
    for u in uploads {
        u.await.unwrap();
    }
    let upload_secs = started.elapsed().as_secs_f64();
    println!(
        "envoi         : {:>8.2} Gio en {upload_secs:>6.2} s = {:>7.0} Mio/s",
        total as f64 / 1073741824.0,
        total as f64 / 1048576.0 / upload_secs
    );

    // --- Téléchargement (plages de 4 Mio en parallèle) ----------------------
    let started = Instant::now();
    let mut downloads = Vec::new();
    for fid in fids {
        let path = format!("{dir}/{fid}.enc");
        let meta = std::fs::metadata(&path).unwrap();
        let mtime = (meta.mtime() as u64) * 1_000_000_000 + meta.mtime_nsec() as u64;
        let t = ticket(
            &key,
            json!({"op":"down","tid":id(99),"fid":fid,"sub":"bench","iat":now,"exp":now+900,"size":size,"mtime":mtime.to_string()}),
        );
        let (client, base) = (client.clone(), base.clone());
        downloads.push(tokio::spawn(async move {
            let next = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let mut workers = Vec::new();
            for _ in 0..parts_in_flight {
                let (next, client, t, base) = (Arc::clone(&next), client.clone(), t.clone(), base.clone());
                workers.push(tokio::spawn(async move {
                    let mut received = 0u64;
                    loop {
                        let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if index >= part_count {
                            break;
                        }
                        let start = index * PART;
                        let end = (start + PART).min(size) - 1;
                        let req = Request::builder()
                            .uri(format!("{base}/v1/files/{fid}"))
                            .header("authorization", format!("Bearer {t}"))
                            .header("range", format!("bytes={start}-{end}"))
                            .body(Full::new(Bytes::new()))
                            .unwrap();
                        let response = client.request(req).await.unwrap();
                        assert_eq!(response.status(), 206);
                        // Octets comptés au fil de l'eau, sans les recopier.
                        let mut body = response.into_body();
                        while let Some(frame) = body.frame().await {
                            if let Ok(data) = frame.unwrap().into_data() {
                                received += data.len() as u64;
                            }
                        }
                    }
                    received
                }));
            }
            let mut total = 0;
            for w in workers {
                total += w.await.unwrap();
            }
            assert_eq!(total, size);
        }));
    }
    for d in downloads {
        d.await.unwrap();
    }
    let download_secs = started.elapsed().as_secs_f64();
    println!(
        "téléchargement: {:>8.2} Gio en {download_secs:>6.2} s = {:>7.0} Mio/s",
        total as f64 / 1073741824.0,
        total as f64 / 1048576.0 / download_secs
    );

    let _ = std::fs::remove_dir_all(&dir);
}
