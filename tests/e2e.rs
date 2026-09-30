//! Tests de bout en bout : serveur réel, disque réel, fausse API synco_api.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

mod common;

use bytes::Bytes;
use common::*;
use http::Method;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Envoie les parts de `data` (toutes, ou `only`) en parallèle et dans le désordre.
async fn put_parts(client: &HttpClient, cdn: &Cdn, tid: Uuid, ticket: &str, data: &[u8], only: Option<&[u64]>) {
    let count = (data.len() as u64).div_ceil(PART).max(1);
    let indexes: Vec<u64> = match only {
        Some(list) => list.to_vec(),
        None => (0..count).rev().collect(),
    };
    let mut tasks = Vec::new();
    for index in indexes {
        let start = (index * PART) as usize;
        let end = ((index + 1) * PART).min(data.len() as u64) as usize;
        let body = Bytes::copy_from_slice(&data[start..end]);
        let (client, url, ticket) =
            (client.clone(), format!("http://{}/v1/uploads/{tid}/part", cdn.public), ticket.to_owned());
        tasks.push(tokio::spawn(async move {
            client.send(Method::PUT, url, &[bearer(&ticket), ("x-part-index", index.to_string())], body).await
        }));
    }
    for task in tasks {
        let reply = task.await.unwrap();
        assert_eq!(reply.status, 204, "{}", String::from_utf8_lossy(&reply.body));
    }
}

async fn open(client: &HttpClient, cdn: &Cdn, ticket: &str) -> Reply {
    client.send(Method::POST, format!("http://{}/v1/uploads", cdn.public), &[bearer(ticket)], Bytes::new()).await
}

async fn complete(client: &HttpClient, cdn: &Cdn, tid: Uuid, ticket: &str) -> Reply {
    client
        .send(Method::POST, format!("http://{}/v1/uploads/{tid}/complete", cdn.public), &[bearer(ticket)], Bytes::new())
        .await
}

/// Envoi complet, puis téléchargements entier et par plages parallèles.
async fn round_trip(client: HttpClient) {
    let dir = tempfile::tempdir().unwrap();
    let api = FakeApi::start().await;
    let cdn = Cdn::start(dir.path(), &api, "").await;

    let data = pattern((PART * 5 + 12_345) as usize, 1);
    let (tid, fid) = (fresh_id(), fresh_id());
    let ticket = upload_ticket(tid, fid, data.len() as u64, "alice");

    let opened = open(&client, &cdn, &ticket).await;
    assert_eq!(opened.status, 201);
    assert_eq!(opened.json()["partCount"], 6);
    assert_eq!(opened.json()["receivedParts"], json!([]));

    put_parts(&client, &cdn, tid, &ticket, &data, None).await;

    let done = complete(&client, &cdn, tid, &ticket).await;
    assert_eq!(done.status, 201, "{}", String::from_utf8_lossy(&done.body));
    assert_eq!(done.json()["id"], json!(fid), "réponse de l'API relayée");

    // Rappel signé, avec taille et empreinte correctes.
    let calls = api.calls();
    let call = calls.iter().find(|c| c.path.ends_with("/complete")).unwrap();
    assert!(call.signature_valid, "signature HMAC du rappel");
    assert_eq!(call.body["size"], json!(data.len()));
    let mut tree = Sha256::new();
    for chunk in data.chunks(PART as usize) {
        tree.update(Sha256::digest(chunk));
    }
    assert_eq!(call.body["hash"], json!(format!("sha256p:{}", synco_cdn::util::hex_encode(&tree.finalize()))));

    // Fichier à sa place définitive, identique, plus rien en cours.
    assert_eq!(std::fs::read(cdn.final_path(fid)).unwrap(), data);
    assert_eq!(
        std::fs::read_dir(dir.path().join(".cdn-uploads"))
            .unwrap()
            .filter(|e| { e.as_ref().unwrap().file_name().to_string_lossy().ends_with(".data") })
            .count(),
        0
    );

    // `complete` rejoué : même réponse, sans nouvel appel à l'API.
    let again = complete(&client, &cdn, tid, &ticket).await;
    assert_eq!(again.status, 201);
    assert_eq!(api.calls().len(), calls.len());

    // Téléchargement entier.
    let dticket = download_ticket(fid, &cdn.final_path(fid), "alice");
    let url = format!("http://{}/v1/files/{fid}", cdn.public);
    let full = client.send(Method::GET, url.clone(), &[bearer(&dticket)], Bytes::new()).await;
    assert_eq!(full.status, 200);
    assert_eq!(full.body.as_ref(), data.as_slice());
    assert_eq!(full.headers["content-type"], "application/octet-stream");
    assert_eq!(full.headers["accept-ranges"], "bytes");

    // Plages en parallèle, recomposées.
    let mut tasks = Vec::new();
    let block = 100_000usize;
    for start in (0..data.len()).step_by(block) {
        let end = (start + block).min(data.len());
        let (client, url, dticket) = (client.clone(), url.clone(), dticket.clone());
        tasks.push(tokio::spawn(async move {
            let reply = client
                .send(
                    Method::GET,
                    url,
                    &[bearer(&dticket), ("range", format!("bytes={start}-{}", end - 1))],
                    Bytes::new(),
                )
                .await;
            (start, reply)
        }));
    }
    let mut rebuilt = vec![0u8; data.len()];
    for task in tasks {
        let (start, reply) = task.await.unwrap();
        assert_eq!(reply.status, 206);
        rebuilt[start..start + reply.body.len()].copy_from_slice(&reply.body);
    }
    assert_eq!(rebuilt, data);

    // HEAD, plage hors fichier, plage ignorée par If-Range.
    let head = client.send(Method::HEAD, url.clone(), &[bearer(&dticket)], Bytes::new()).await;
    assert_eq!(head.status, 200);
    assert_eq!(head.headers["content-length"], data.len().to_string());
    assert!(head.body.is_empty());
    let beyond = client
        .send(Method::GET, url.clone(), &[bearer(&dticket), ("range", format!("bytes={}-", data.len()))], Bytes::new())
        .await;
    assert_eq!(beyond.status, 416);
    assert_eq!(beyond.headers["content-range"], format!("bytes */{}", data.len()));
    let stale = client
        .send(
            Method::GET,
            url,
            &[bearer(&dticket), ("range", "bytes=0-9".into()), ("if-range", "\"autre\"".into())],
            Bytes::new(),
        )
        .await;
    assert_eq!(stale.status, 200);

    cdn.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn round_trip_http1() {
    round_trip(HttpClient::http1()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn round_trip_http2() {
    round_trip(HttpClient::http2()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parts_are_validated_and_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let api = FakeApi::start().await;
    let cdn = Cdn::start(dir.path(), &api, "").await;
    let client = HttpClient::http1();

    let data = pattern((PART * 2) as usize, 2);
    let (tid, fid) = (fresh_id(), fresh_id());
    let ticket = upload_ticket(tid, fid, data.len() as u64, "bob");
    assert_eq!(open(&client, &cdn, &ticket).await.status, 201);
    assert_eq!(open(&client, &cdn, &ticket).await.status, 200, "réouverture = reprise");

    let url = format!("http://{}/v1/uploads/{tid}/part", cdn.public);
    let send = |index: &str, body: Vec<u8>, extra: Vec<(&'static str, String)>| {
        let (client, url, ticket, index) = (client.clone(), url.clone(), ticket.clone(), index.to_owned());
        async move {
            let mut headers = vec![bearer(&ticket), ("x-part-index", index)];
            headers.extend(extra);
            client.send(Method::PUT, url, &headers, Bytes::from(body)).await
        }
    };

    assert_eq!(send("0", vec![0; 10], vec![]).await.error_code(), "bad_part_length");
    assert_eq!(send("2", vec![0; 10], vec![]).await.error_code(), "bad_part_index");
    assert_eq!(send("abc", vec![0; 10], vec![]).await.error_code(), "bad_part_index");
    let first = data[..PART as usize].to_vec();
    let wrong_sum = vec![("x-part-sha256", "00".repeat(32))];
    assert_eq!(send("0", first.clone(), wrong_sum).await.error_code(), "part_checksum_mismatch");
    let good_sum = vec![("x-part-sha256", synco_cdn::util::hex_encode(&Sha256::digest(&first)))];
    assert_eq!(send("0", first.clone(), good_sum).await.status, 204);
    // Réessai d'une part déjà reçue : accepté sans réécriture.
    assert_eq!(send("0", first, vec![]).await.status, 204);

    assert_eq!(complete(&client, &cdn, tid, &ticket).await.error_code(), "parts_missing");
    let status = client
        .send(Method::GET, format!("http://{}/v1/uploads/{tid}", cdn.public), &[bearer(&ticket)], Bytes::new())
        .await;
    assert_eq!(status.json()["receivedParts"], json!([[0, 0]]));

    // Un ticket valide ne donne accès qu'à son propre transfert.
    let other = upload_ticket(fresh_id(), fid, data.len() as u64, "bob");
    let denied = client
        .send(Method::GET, format!("http://{}/v1/uploads/{tid}", cdn.public), &[bearer(&other)], Bytes::new())
        .await;
    assert_eq!(denied.status, 403);
    assert_eq!(denied.error_code(), "ticket_wrong_target");

    // Abandon : fichiers supprimés.
    let aborted = client
        .send(Method::DELETE, format!("http://{}/v1/uploads/{tid}", cdn.public), &[bearer(&ticket)], Bytes::new())
        .await;
    assert_eq!(aborted.status, 204);
    assert!(
        std::fs::read_dir(dir.path().join(".cdn-uploads"))
            .unwrap()
            .all(|e| { e.unwrap().file_name().to_string_lossy() == "revocations.json" })
    );
    cdn.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_resumes_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let api = FakeApi::start().await;
    let client = HttpClient::http1();
    let data = pattern((PART * 4 + 7) as usize, 3);
    let (tid, fid) = (fresh_id(), fresh_id());
    let ticket = upload_ticket(tid, fid, data.len() as u64, "carol");

    let cdn = Cdn::start(dir.path(), &api, "").await;
    assert_eq!(open(&client, &cdn, &ticket).await.status, 201);
    put_parts(&client, &cdn, tid, &ticket, &data, Some(&[0, 3])).await;
    cdn.stop().await;

    // Nouveau processus sur le même disque : les parts reçues sont connues.
    let cdn = Cdn::start(dir.path(), &api, "").await;
    let status = client
        .send(Method::GET, format!("http://{}/v1/uploads/{tid}", cdn.public), &[bearer(&ticket)], Bytes::new())
        .await;
    assert_eq!(status.status, 200);
    assert_eq!(status.json()["receivedParts"], json!([[0, 0], [3, 3]]));

    put_parts(&client, &cdn, tid, &ticket, &data, Some(&[1, 2, 4])).await;
    assert_eq!(complete(&client, &cdn, tid, &ticket).await.status, 201);
    assert_eq!(std::fs::read(cdn.final_path(fid)).unwrap(), data);
    cdn.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_unavailable_then_background_registration() {
    let dir = tempfile::tempdir().unwrap();
    let api = FakeApi::start().await;
    let cdn = Cdn::start(dir.path(), &api, "").await;
    let client = HttpClient::http1();

    let data = pattern(1000, 4);
    let (tid, fid) = (fresh_id(), fresh_id());
    let ticket = upload_ticket(tid, fid, data.len() as u64, "dave");
    open(&client, &cdn, &ticket).await;
    put_parts(&client, &cdn, tid, &ticket, &data, None).await;

    api.set_mode(ApiMode::Unavailable);
    let pending = complete(&client, &cdn, tid, &ticket).await;
    assert_eq!(pending.status, 503);
    assert_eq!(pending.error_code(), "api_unavailable");
    assert!(pending.headers.contains_key("retry-after"));
    assert!(cdn.final_path(fid).exists(), "fichier déjà en place, en attente d'enregistrement");

    // Le client disparaît ; le balayage termine l'enregistrement.
    api.set_mode(ApiMode::Accept);
    synco_cdn::server::sweep(&cdn.state).await;
    for _ in 0..50 {
        if cdn
            .state
            .storage
            .sessions()
            .get(tid)
            .is_some_and(|s| s.phase_kind() == synco_cdn::storage::session::PhaseKind::Completed)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let done = complete(&client, &cdn, tid, &ticket).await;
    assert_eq!(done.status, 201);
    assert_eq!(done.json()["id"], json!(fid));
    cdn.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_rejection_deletes_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let api = FakeApi::start().await;
    let cdn = Cdn::start(dir.path(), &api, "").await;
    let client = HttpClient::http1();

    let data = pattern(5000, 5);
    let (tid, fid) = (fresh_id(), fresh_id());
    let ticket = upload_ticket(tid, fid, data.len() as u64, "erin");
    open(&client, &cdn, &ticket).await;
    put_parts(&client, &cdn, tid, &ticket, &data, None).await;

    api.set_mode(ApiMode::Reject);
    let rejected = complete(&client, &cdn, tid, &ticket).await;
    assert_eq!(rejected.status, 409);
    assert_eq!(rejected.error_code(), "upload_rejected");
    assert!(!cdn.final_path(fid).exists());
    assert!(cdn.state.storage.sessions().get(tid).is_none());
    cdn.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tickets_are_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let api = FakeApi::start().await;
    let cdn = Cdn::start(dir.path(), &api, "").await;
    let client = HttpClient::http1();
    let uploads = format!("http://{}/v1/uploads", cdn.public);

    let missing = client.send(Method::POST, uploads.clone(), &[], Bytes::new()).await;
    assert_eq!((missing.status.as_u16(), missing.error_code().as_str()), (401, "ticket_missing"));

    let now = now();
    let expired = sign(&json!({
        "op": "up", "tid": fresh_id(), "fid": fresh_id(), "sub": "x",
        "iat": now - 4000, "exp": now - 400, "size": 10, "psz": PART
    }));
    let reply = client.send(Method::POST, uploads.clone(), &[bearer(&expired)], Bytes::new()).await;
    assert_eq!(reply.error_code(), "ticket_expired");

    let forged = format!("{}x", upload_ticket(fresh_id(), fresh_id(), 10, "x"));
    let reply = client.send(Method::POST, uploads.clone(), &[bearer(&forged)], Bytes::new()).await;
    assert_eq!(reply.status, 401);

    // Ticket de téléchargement présenté pour un envoi.
    let path = dir.path().join("some.enc");
    std::fs::write(&path, b"x").unwrap();
    let down = download_ticket(fresh_id(), &path, "x");
    let reply = client.send(Method::POST, uploads, &[bearer(&down)], Bytes::new()).await;
    assert_eq!((reply.status.as_u16(), reply.error_code().as_str()), (403, "ticket_wrong_operation"));

    // Fichier modifié après l'émission du ticket.
    let fid = fresh_id();
    let final_path = cdn.final_path(fid);
    std::fs::write(&final_path, b"version 1").unwrap();
    let ticket = download_ticket(fid, &final_path, "x");
    std::thread::sleep(std::time::Duration::from_millis(20));
    std::fs::write(&final_path, b"version 2!").unwrap();
    let changed = client
        .send(Method::GET, format!("http://{}/v1/files/{fid}", cdn.public), &[bearer(&ticket)], Bytes::new())
        .await;
    assert_eq!(changed.error_code(), "file_changed");

    // Ticket pour un autre fichier.
    let other = client
        .send(Method::GET, format!("http://{}/v1/files/{}", cdn.public, fresh_id()), &[bearer(&ticket)], Bytes::new())
        .await;
    assert_eq!(other.error_code(), "ticket_wrong_target");

    // Chemins invalides.
    for path in ["/v1/files/../../etc/passwd", "/v1/files/not-a-uuid", "/v1/unknown"] {
        let reply = client.send(Method::GET, format!("http://{}{path}", cdn.public), &[], Bytes::new()).await;
        assert_eq!(reply.status, 404, "{path}");
    }
    let wrong_method = client.send(Method::PATCH, format!("http://{}/v1/uploads", cdn.public), &[], Bytes::new()).await;
    assert_eq!(wrong_method.status, 405);
    cdn.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cors_and_health() {
    let dir = tempfile::tempdir().unwrap();
    let api = FakeApi::start().await;
    let cdn = Cdn::start(dir.path(), &api, "").await;
    let client = HttpClient::http1();
    let url = format!("http://{}/v1/uploads/{}/part", cdn.public, fresh_id());

    let preflight = |origin: &str| {
        let (client, url, origin) = (client.clone(), url.clone(), origin.to_owned());
        async move {
            client
                .send(
                    Method::OPTIONS,
                    url,
                    &[("origin", origin), ("access-control-request-method", "PUT".into())],
                    Bytes::new(),
                )
                .await
        }
    };
    let allowed = preflight(ORIGIN).await;
    assert_eq!(allowed.status, 204);
    assert_eq!(allowed.headers["access-control-allow-origin"], ORIGIN);
    assert!(allowed.headers["access-control-allow-headers"].to_str().unwrap().contains("x-part-index"));
    let denied = preflight("https://evil.test").await;
    assert_eq!(denied.status, 403);
    assert!(!denied.headers.contains_key("access-control-allow-origin"));

    let health = client
        .send(Method::GET, format!("http://{}/healthz", cdn.public), &[("origin", ORIGIN.into())], Bytes::new())
        .await;
    assert_eq!(health.status, 200);
    assert_eq!(health.headers["access-control-allow-origin"], ORIGIN);
    assert_eq!(health.headers["x-content-type-options"], "nosniff");

    let ready = client.send(Method::GET, format!("http://{}/readyz", cdn.internal), &[], Bytes::new()).await;
    assert_eq!(ready.status, 200);
    let metrics = client.send(Method::GET, format!("http://{}/metrics", cdn.internal), &[], Bytes::new()).await;
    let text = String::from_utf8(metrics.body.to_vec()).unwrap();
    assert!(text.contains("cdn_requests_total{route=\"preflight\",status=\"2xx\"} 1"));
    assert!(text.contains("cdn_panics_total 0"));
    cdn.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn internal_routes_require_signature() {
    let dir = tempfile::tempdir().unwrap();
    let api = FakeApi::start().await;
    let cdn = Cdn::start(dir.path(), &api, "").await;
    let client = HttpClient::http1();
    let secret = synco_cdn::internal_auth::InternalSecret::from_hex(SECRET_HEX).unwrap();

    let signed = |method: &str, path: &str, body: &[u8]| -> Vec<(&'static str, String)> {
        let ts = now();
        vec![("x-synco-timestamp", ts.to_string()), ("x-synco-signature", secret.sign(method, path, ts, body))]
    };

    // Ticket valide avant révocation.
    let ticket = upload_ticket(fresh_id(), fresh_id(), 10, "mallory");
    assert_eq!(open(&client, &cdn, &ticket).await.status, 201);

    let body = serde_json::to_vec(&json!({ "sub": "mallory", "until": now() })).unwrap();
    let url = format!("http://{}/internal/v1/revocations", cdn.internal);
    let unsigned = client.send(Method::POST, url.clone(), &[], Bytes::from(body.clone())).await;
    assert_eq!(unsigned.status, 403);
    let mut bad = signed("POST", "/internal/v1/revocations", &body);
    bad[1].1 = "00".repeat(32);
    assert_eq!(client.send(Method::POST, url.clone(), &bad, Bytes::from(body.clone())).await.status, 403);

    let headers = signed("POST", "/internal/v1/revocations", &body);
    assert_eq!(client.send(Method::POST, url, &headers, Bytes::from(body)).await.status, 204);
    let revoked = open(&client, &cdn, &ticket).await;
    assert_eq!(revoked.error_code(), "ticket_revoked");

    // Annulation d'un envoi par l'API : session supprimée, ticket inutilisable.
    let (tid, fid) = (fresh_id(), fresh_id());
    let ticket = upload_ticket(tid, fid, 10, "trent");
    assert_eq!(open(&client, &cdn, &ticket).await.status, 201);
    let path = format!("/internal/v1/uploads/{tid}");
    let reply = client
        .send(Method::DELETE, format!("http://{}{path}", cdn.internal), &signed("DELETE", &path, b""), Bytes::new())
        .await;
    assert_eq!(reply.status, 204);
    assert!(cdn.state.storage.sessions().get(tid).is_none());
    assert_eq!(open(&client, &cdn, &ticket).await.error_code(), "ticket_revoked");

    // Les révocations survivent au redémarrage.
    cdn.stop().await;
    let cdn = Cdn::start(dir.path(), &api, "").await;
    assert_eq!(open(&client, &cdn, &ticket).await.error_code(), "ticket_revoked");
    cdn.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accel_mode_delegates_to_nginx() {
    let dir = tempfile::tempdir().unwrap();
    let api = FakeApi::start().await;
    let cdn = Cdn::start(dir.path(), &api, "[downloads]\nmode = \"accel\"").await;
    let client = HttpClient::http1();

    let fid = fresh_id();
    std::fs::write(cdn.final_path(fid), b"contenu").unwrap();
    let ticket = download_ticket(fid, &cdn.final_path(fid), "x");
    let reply = client
        .send(Method::GET, format!("http://{}/v1/files/{fid}", cdn.public), &[bearer(&ticket)], Bytes::new())
        .await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.headers["x-accel-redirect"], format!("/_cdn_files/{fid}.enc"));
    assert!(reply.body.is_empty());
    cdn.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn empty_file() {
    let dir = tempfile::tempdir().unwrap();
    let api = FakeApi::start().await;
    let cdn = Cdn::start(dir.path(), &api, "").await;
    let client = HttpClient::http2();
    let (tid, fid) = (fresh_id(), fresh_id());
    let ticket = upload_ticket(tid, fid, 0, "x");
    assert_eq!(open(&client, &cdn, &ticket).await.json()["partCount"], 1);
    put_parts(&client, &cdn, tid, &ticket, &[], Some(&[0])).await;
    assert_eq!(complete(&client, &cdn, tid, &ticket).await.status, 201);
    let dticket = download_ticket(fid, &cdn.final_path(fid), "x");
    let reply = client
        .send(Method::GET, format!("http://{}/v1/files/{fid}", cdn.public), &[bearer(&dticket)], Bytes::new())
        .await;
    assert_eq!(reply.status, 200);
    assert!(reply.body.is_empty());
    cdn.stop().await;
}
