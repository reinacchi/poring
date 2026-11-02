//! End-to-end: a running Poring server keeps serving native and guest routes while the
//! guest artefact is replaced on disk (partial write, valid update, garbage, forbidden
//! capability), without restarting the host process.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use http_body_util::{BodyExt, Empty};
use poring::descriptor::Method;
use poring::dynamic::DynPolicy;
use poring::prelude::*;
use poring::wasm::guest_kit::{Behaviour, GuestSpec};
use poring::wasm::watch::{WatchConfig, watch};
use poring::wasm::{GuestConfig, GuestRoute, GuestSlot, ReloadEvent, WasmHost};

#[derive(Clone)]
struct Tokens;
impl Authenticator for Tokens {
    async fn authenticate(&self, r: &AuthRequest<'_>) -> Result<Option<Identity>, AuthError> {
        Ok(r.bearer_token()
            .filter(|t| *t == "ok")
            .map(|t| Identity::new(t, Credential::Bearer)))
    }
}

#[poring::get("/native", public(reason = "test probe"))]
async fn native() -> &'static str {
    "native ok"
}

poring_app! {
    Live {
        auth: Tokens,
        defaults: policy(deny_anonymous),
        routes: [native],
    }
}

async fn get(
    sender: &mut hyper::client::conn::http1::SendRequest<Empty<bytes::Bytes>>,
    method: &str,
    path: &str,
) -> (u16, String) {
    let req = http::Request::builder()
        .method(method)
        .uri(path)
        .header("host", "t")
        .header("authorization", "Bearer ok")
        .body(Empty::new())
        .unwrap();
    let res = sender.send_request(req).await.expect("request");
    let status = res.status().as_u16();
    let ver = res
        .headers()
        .get("x-poring-guest")
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let _ = res.into_body().collect().await.unwrap();
    (status, ver)
}

fn seq_of(tag: &str) -> u64 {
    tag.rsplit('#')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

async fn wait_for(slot: &GuestSlot, pred: impl Fn(&GuestSlot) -> bool) {
    for _ in 0..100 {
        if pred(slot) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("condition not reached; events: {:?}", slot.events());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_reload_under_concurrent_traffic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("guest.wasm");
    std::fs::write(&path, GuestSpec::echo("live", "1").build().unwrap()).unwrap();
    let slot =
        GuestSlot::from_file(WasmHost::new().unwrap(), GuestConfig::new("live"), &path).unwrap();
    let watcher = watch(
        slot.clone(),
        &path,
        WatchConfig {
            debounce: Duration::from_millis(60),
            settle: Duration::from_millis(60),
            poll: Duration::from_millis(100),
        },
    )
    .unwrap();
    let app = Live::builder()
        .authenticator(Tokens)
        .mount_dynamic(GuestRoute::mount(
            slot.clone(),
            Method::Get,
            "/guest/{*rest}",
            DynPolicy::default(),
        ))
        .build()
        .unwrap();
    let server = app.bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr();

    let stop = Arc::new(AtomicBool::new(false));
    let mut clients = Vec::new();
    for c in 0..4 {
        let stop = stop.clone();
        clients.push(tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                    .await
                    .unwrap();
            tokio::spawn(conn);
            let mut seen = Vec::new();
            let mut i = 0u64;
            while !stop.load(Ordering::Relaxed) {
                i += 1;
                let (s, v) = if i.is_multiple_of(5) {
                    get(&mut sender, "GET", "/native").await
                } else {
                    get(&mut sender, "GET", &format!("/guest/c{c}/{i}")).await
                };
                seen.push((s, v));
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            seen
        }));
    }

    tokio::time::sleep(Duration::from_millis(300)).await;
    // 1) Partial write: half the bytes, pause longer than the settle interval, then the rest.
    let v2 = GuestSpec::echo("live", "2").build().unwrap();
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        f.write_all(&v2[..v2.len() / 2]).unwrap();
        f.flush().unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;
        f.write_all(&v2[v2.len() / 2..]).unwrap();
        f.flush().unwrap();
    }
    wait_for(&slot, |s| s.current().version == "2").await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 2) Garbage and 3) a guest that imports a capability the host did not grant.
    std::fs::write(&path, b"definitely not wasm").unwrap();
    wait_for(&slot, |s| s.events().iter().filter(|e| matches!(e, ReloadEvent::Rejected { .. })).count() >= 1 && s.events().iter().any(|e| matches!(e, ReloadEvent::Rejected { reason } if reason.contains("invalid component") && !reason.contains("unexpected end")))).await;
    std::fs::write(
        &path,
        GuestSpec::echo("live", "3")
            .behaviour(Behaviour::LogThenEcho)
            .build()
            .unwrap(),
    )
    .unwrap();
    wait_for(&slot, |s| {
        s.events().iter().any(
            |e| matches!(e, ReloadEvent::Rejected { reason } if reason.contains("not granted")),
        )
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        slot.current().version,
        "2",
        "rejected candidates never become active"
    );

    stop.store(true, Ordering::Relaxed);
    let mut total = 0;
    let mut saw = std::collections::BTreeSet::new();
    for c in clients {
        let seen = c.await.unwrap();
        let mut last = 0;
        for (status, ver) in &seen {
            assert_eq!(
                *status, 200,
                "every request succeeded during reloads: {seen:?}"
            );
            if !ver.is_empty() {
                let s = seq_of(ver);
                assert!(s >= last, "versions are monotonic per client: {seen:?}");
                last = s;
                saw.insert(ver.clone());
            }
        }
        total += seen.len();
    }
    assert!(
        saw.contains("live/1#1") && saw.contains("live/2#2"),
        "{saw:?}"
    );
    assert!(
        saw.iter().all(|v| v == "live/1#1" || v == "live/2#2"),
        "{saw:?}"
    );
    eprintln!(
        "{total} requests served across reloads; events: {:?}",
        slot.events()
    );

    // Manual rollback (production API) while the server keeps running.
    slot.rollback().unwrap();
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(conn);
    assert_eq!(
        get(&mut sender, "GET", "/guest/after-rollback").await,
        (200, "live/1#1".to_owned())
    );
    // Graph metadata reflects the live guest version.
    let m = Live::builder()
        .authenticator(Tokens)
        .mount_dynamic(GuestRoute::mount(
            slot.clone(),
            Method::Get,
            "/guest/{*rest}",
            DynPolicy::default(),
        ))
        .build()
        .unwrap()
        .manifest();
    let e = m.find("GET /guest/{*rest}").unwrap();
    assert!(
        e.meta
            .contains(&("guest_version".to_owned(), "1#1".to_owned())),
        "{:?}",
        e.meta
    );
    drop(sender);
    watcher.stop();
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_route_is_behind_the_policy_pipeline() {
    let slot = GuestSlot::new(
        WasmHost::new().unwrap(),
        GuestConfig::new("p"),
        &GuestSpec::echo("p", "1").build().unwrap(),
    )
    .unwrap();
    let app = Live::builder()
        .authenticator(Tokens)
        .mount_dynamic(GuestRoute::mount(
            slot.clone(),
            Method::Post,
            "/p/{x}",
            DynPolicy {
                body_limit: Some(16),
                ..Default::default()
            },
        ))
        .build()
        .unwrap();
    let c = app.client();
    assert_eq!(
        c.post("/p/1").send().await.status,
        401,
        "deny_anonymous applies to guests"
    );
    assert_eq!(
        c.post("/p/1")
            .bearer("ok")
            .body(vec![0u8; 64])
            .send()
            .await
            .status,
        413
    );
    let calls = slot.calls();
    assert_eq!(c.post("/p/1").bearer("ok").send().await.status, 200);
    assert_eq!(
        slot.calls(),
        calls + 1,
        "only the authorised request reached guest code"
    );
}
