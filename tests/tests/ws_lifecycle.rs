//! WebSocket session lifecycle over real TCP (Phase 3): admission, accounting, permit
//! reclamation and bounded shutdown.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use poring::prelude::*;
use poring::ws::WebSocketUpgrade;
use poring_tests::status_of;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

/// Sends a raw request and returns the response head (or "" on timeout/close).
async fn head(addr: SocketAddr, request: String, wait: Duration) -> String {
    let Ok(mut s) = tokio::net::TcpStream::connect(addr).await else {
        return String::new();
    };
    if s.write_all(request.as_bytes()).await.is_err() {
        return String::new();
    }
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let _ = tokio::time::timeout(wait, async {
        loop {
            let n = s.read(&mut chunk).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
    })
    .await;
    String::from_utf8_lossy(&buf).into_owned()
}

fn ws_req(addr: SocketAddr, path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {KEY}\r\n\r\n"
    )
}

fn get_req(addr: SocketAddr, path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")
}

async fn client(
    addr: SocketAddr,
    path: &str,
) -> tokio_tungstenite::WebSocketStream<tokio::net::TcpStream> {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (ws, resp) = tokio_tungstenite::client_async(format!("ws://{addr}{path}"), tcp)
        .await
        .unwrap();
    assert_eq!(resp.status(), 101);
    ws
}

/// Live session counter plus a flag set when a session's future is dropped.
#[derive(Clone, Default)]
struct Probe {
    live: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
}

struct LiveGuard(Probe);
impl Drop for LiveGuard {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
        self.0.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

/// Echo-less session that runs until the peer closes.
fn until_closed(
    probe: Probe,
) -> impl Fn(WebSocketUpgrade) -> std::future::Ready<Response> + Clone + Send + Sync + 'static {
    move |ws: WebSocketUpgrade| {
        let probe = probe.clone();
        std::future::ready(ws.on_upgrade(move |mut sock| async move {
            probe.live.fetch_add(1, Ordering::SeqCst);
            let _g = LiveGuard(probe);
            while let Some(Ok(_)) = sock.next().await {}
        }))
    }
}

/// Session that ignores its socket and never finishes on its own.
fn forever(
    probe: Probe,
) -> impl Fn(WebSocketUpgrade) -> std::future::Ready<Response> + Clone + Send + Sync + 'static {
    move |ws: WebSocketUpgrade| {
        let probe = probe.clone();
        std::future::ready(ws.on_upgrade(move |_sock| async move {
            probe.live.fetch_add(1, Ordering::SeqCst);
            let _g = LiveGuard(probe);
            std::future::pending::<()>().await;
        }))
    }
}

async fn wait_until(mut f: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    f()
}

#[tokio::test]
async fn upgraded_sessions_keep_their_connection_slot() {
    let probe = Probe::default();
    let server = Poring::new()
        .limits(poring::Limits {
            max_connections: 1,
            ..Default::default()
        })
        .get("/ws", until_closed(probe.clone()))
        .get("/data", || async { "data" })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();

    let mut ws = client(addr, "/ws").await;
    assert!(wait_until(|| probe.live.load(Ordering::SeqCst) == 1).await);
    // The only connection slot belongs to the live WebSocket: a new connection waits.
    let blocked = head(addr, get_req(addr, "/data"), Duration::from_millis(400)).await;
    assert_eq!(
        status_of(&blocked),
        0,
        "served while the slot was taken: {blocked}"
    );

    ws.close(None).await.unwrap();
    while ws.next().await.is_some() {}
    assert!(wait_until(|| probe.live.load(Ordering::SeqCst) == 0).await);
    let served = head(addr, get_req(addr, "/data"), Duration::from_secs(3)).await;
    assert_eq!(status_of(&served), 200, "{served}");
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn ws_session_limit_is_enforced_before_101_and_reclaimed() {
    let probe = Probe::default();
    let server = Poring::new()
        .limits(poring::Limits {
            max_ws_sessions: 1,
            ..Default::default()
        })
        .get("/ws", until_closed(probe.clone()))
        .get("/data", || async { "data" })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();

    let mut first = client(addr, "/ws").await;
    assert!(wait_until(|| probe.live.load(Ordering::SeqCst) == 1).await);
    let refused = head(addr, ws_req(addr, "/ws"), Duration::from_secs(3)).await;
    assert_eq!(status_of(&refused), 503, "{refused}");
    assert!(
        !refused
            .to_ascii_lowercase()
            .contains("sec-websocket-accept"),
        "{refused}"
    );
    // Plain HTTP is not limited by the WebSocket session limit.
    assert_eq!(
        status_of(&head(addr, get_req(addr, "/data"), Duration::from_secs(3)).await),
        200
    );

    first.close(None).await.unwrap();
    while first.next().await.is_some() {}
    assert!(wait_until(|| probe.live.load(Ordering::SeqCst) == 0).await);
    let again = head(addr, ws_req(addr, "/ws"), Duration::from_secs(3)).await;
    assert_eq!(status_of(&again), 101, "{again}");
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn panicking_and_disconnected_sessions_release_their_permits() {
    let panics = Arc::new(AtomicUsize::new(0));
    let p = panics.clone();
    let probe = Probe::default();
    let server = Poring::new()
        .limits(poring::Limits {
            max_ws_sessions: 1,
            max_connections: 2,
            ..Default::default()
        })
        .get("/panic", move |ws: WebSocketUpgrade| {
            let p = p.clone();
            async move {
                ws.on_upgrade(move |_sock| async move {
                    p.fetch_add(1, Ordering::SeqCst);
                    panic!("session handler panic (expected by the test)");
                })
            }
        })
        .get("/ws", until_closed(probe.clone()))
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();

    for _ in 0..3 {
        let h = head(addr, ws_req(addr, "/panic"), Duration::from_secs(3)).await;
        assert_eq!(status_of(&h), 101, "{h}");
        let n = panics.load(Ordering::SeqCst);
        assert!(wait_until(|| panics.load(Ordering::SeqCst) >= n).await);
    }
    // A client that disappears without a close frame also frees its session.
    for _ in 0..3 {
        let ws = client(addr, "/ws").await;
        assert!(wait_until(|| probe.live.load(Ordering::SeqCst) == 1).await);
        drop(ws);
        assert!(wait_until(|| probe.live.load(Ordering::SeqCst) == 0).await);
    }
    let h = head(addr, ws_req(addr, "/ws"), Duration::from_secs(3)).await;
    assert_eq!(status_of(&h), 101, "permits leaked: {h}");
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_is_bounded_and_cancels_lingering_sessions() {
    let probe = Probe::default();
    let server = Poring::new()
        .limits(poring::Limits {
            shutdown_grace: Duration::from_millis(200),
            ..Default::default()
        })
        .get("/ws", forever(probe.clone()))
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    let mut sockets = Vec::new();
    for _ in 0..3 {
        sockets.push(client(addr, "/ws").await);
    }
    assert!(wait_until(|| probe.live.load(Ordering::SeqCst) == 3).await);

    let started = Instant::now();
    tokio::time::timeout(Duration::from_secs(5), server.shutdown())
        .await
        .expect("shutdown hung")
        .unwrap();
    let took = started.elapsed();
    // Every session future was dropped by the time shutdown returned.
    assert_eq!(probe.live.load(Ordering::SeqCst), 0);
    assert_eq!(probe.dropped.load(Ordering::SeqCst), 3);
    assert!(took < Duration::from_secs(3), "shutdown took {took:?}");
    // And the server side closed the TCP streams.
    for mut s in sockets {
        let next = tokio::time::timeout(Duration::from_secs(3), s.next())
            .await
            .unwrap();
        assert!(
            matches!(next, None | Some(Err(_)) | Some(Ok(_))),
            "{next:?}"
        );
    }
}

#[tokio::test]
async fn shutdown_without_sessions_is_not_delayed() {
    let server = Poring::new()
        .get("/ws", forever(Probe::default()))
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let started = Instant::now();
    server.shutdown().await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[allow(dead_code)]
fn _unused(_: AtomicBool) {}

// ---- P3.2: graceful shutdown -----------------------------------------------------------

use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

#[derive(Debug, serde::Deserialize, serde::Serialize, PoringSchema)]
struct Chat {
    text: String,
}

fn grace(ms: u64) -> poring::Limits {
    poring::Limits {
        shutdown_grace: Duration::from_millis(ms),
        ..Default::default()
    }
}

/// Reads until a close frame (returns its code) or the end of the stream (`None`).
async fn close_code(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
) -> Option<CloseCode> {
    let read = async {
        while let Some(m) = ws.next().await {
            match m {
                Ok(Message::Close(f)) => return f.map(|f| f.code),
                Ok(_) => continue,
                Err(_) => return None,
            }
        }
        None
    };
    tokio::time::timeout(Duration::from_secs(5), read)
        .await
        .ok()
        .flatten()
}

#[tokio::test]
async fn raw_handlers_can_observe_shutdown_and_close_cleanly() {
    let probe = Probe::default();
    let p = probe.clone();
    // Served through `App::serve` directly, with a caller-provided shutdown future.
    let app = Poring::new()
        .limits(grace(10_000))
        .get("/ws", move |ws: WebSocketUpgrade| {
            let probe = p.clone();
            async move {
                let mut stop = ws.shutdown_signal();
                assert!(!stop.is_shutting_down());
                ws.on_upgrade(move |mut sock| async move {
                    probe.live.fetch_add(1, Ordering::SeqCst);
                    let _g = LiveGuard(probe);
                    tokio::select! {
                        _ = async { while let Some(Ok(_)) = sock.next().await {} } => {}
                        _ = stop.wait() => {
                            let _ = sock
                                .close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
                                    code: CloseCode::Away,
                                    reason: "server shutting down".into(),
                                }))
                                .await;
                        }
                    }
                })
            }
        })
        .build()
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(app.serve(listener, async move {
        let _ = rx.await;
    }));
    let mut a = client(addr, "/ws").await;
    let mut b = client(addr, "/ws").await;
    assert!(wait_until(|| probe.live.load(Ordering::SeqCst) == 2).await);

    let started = Instant::now();
    tx.send(()).unwrap();
    assert_eq!(close_code(&mut a).await, Some(CloseCode::Away));
    assert_eq!(close_code(&mut b).await, Some(CloseCode::Away));
    tokio::time::timeout(Duration::from_secs(5), serving)
        .await
        .expect("serve hung")
        .unwrap()
        .unwrap();
    // Cooperative sessions end long before the 10 s grace period.
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(probe.live.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn typed_sockets_send_going_away_on_shutdown() {
    let server = Poring::new()
        .limits(grace(10_000))
        .get("/chat", |ws: WebSocketUpgrade| async move {
            ws.typed::<Chat, Chat>().on_upgrade(|mut sock| async move {
                // An ordinary echo loop with no shutdown handling of its own.
                while let Some(Ok(m)) = sock.recv().await {
                    if sock.send(&m).await.is_err() {
                        break;
                    }
                }
            })
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    let mut ws = client(addr, "/chat").await;
    use futures_util::SinkExt;
    ws.send(Message::text(r#"{"text":"hi"}"#)).await.unwrap();
    assert!(matches!(ws.next().await, Some(Ok(Message::Text(_)))));

    let started = Instant::now();
    let shutdown = tokio::spawn(server.shutdown());
    assert_eq!(close_code(&mut ws).await, Some(CloseCode::Away));
    drop(ws);
    tokio::time::timeout(Duration::from_secs(5), shutdown)
        .await
        .expect("shutdown hung")
        .unwrap()
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn upgrades_cannot_start_once_shutdown_has_begun() {
    let probe = Probe::default();
    let p = probe.clone();
    let app = Poring::new()
        .limits(grace(1_000))
        .get("/ws", move |ws: WebSocketUpgrade| {
            let probe = p.clone();
            async move {
                let mut stop = ws.shutdown_signal();
                ws.on_upgrade(move |_sock| async move {
                    probe.live.fetch_add(1, Ordering::SeqCst);
                    let _g = LiveGuard(probe);
                    // Keeps the server in its grace period until shutdown is signalled.
                    stop.wait().await;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                })
            }
        })
        .build()
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(app.serve(listener, async move {
        let _ = rx.await;
    }));
    let _held = client(addr, "/ws").await;
    // An idle connection opened before shutdown, used for an upgrade after it began.
    let mut idle = tokio::net::TcpStream::connect(addr).await.unwrap();
    assert!(wait_until(|| probe.live.load(Ordering::SeqCst) == 1).await);

    tx.send(()).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = idle.write_all(ws_req(addr, "/ws").as_bytes()).await;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), idle.read_to_end(&mut buf)).await;
    let late = String::from_utf8_lossy(&buf);
    assert_ne!(
        status_of(&late),
        101,
        "late upgrade escaped shutdown: {late}"
    );

    tokio::time::timeout(Duration::from_secs(5), serving)
        .await
        .expect("serve hung")
        .unwrap()
        .unwrap();
    assert_eq!(probe.live.load(Ordering::SeqCst), 0);
    assert_eq!(
        probe.dropped.load(Ordering::SeqCst),
        1,
        "only the early session ran"
    );
}

// ---- P3.3: liveness (managed sessions) and lifetime ------------------------------------

use poring::ws::ManagedSocket;

async fn serve_managed<F, Fut>(f: F) -> poring::Server
where
    F: Fn(WebSocketUpgrade) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response> + Send + 'static,
{
    Poring::new()
        .limits(grace(300))
        .get("/m", f)
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap()
}

#[tokio::test]
async fn managed_sessions_ping_and_stay_alive_while_the_app_is_not_reading() {
    let probe = Probe::default();
    let p = probe.clone();
    let server = serve_managed(move |ws: WebSocketUpgrade| {
        let probe = p.clone();
        async move {
            ws.managed()
                .ping_interval(Duration::from_millis(100))
                .idle_timeout(Duration::from_millis(300))
                .on_upgrade(move |mut sock: ManagedSocket| async move {
                    probe.live.fetch_add(1, Ordering::SeqCst);
                    let _g = LiveGuard(probe);
                    // The application does not read for well over the idle timeout.
                    tokio::time::sleep(Duration::from_millis(1_200)).await;
                    sock.send(Message::text("still here")).await.unwrap();
                    while let Some(m) = sock.recv().await {
                        if sock.send(m).await.is_err() {
                            break;
                        }
                    }
                })
        }
    })
    .await;
    let addr = server.local_addr();
    let mut ws = client(addr, "/m").await;
    // A normal client: reading answers pings automatically.
    let mut pings = 0;
    let text = loop {
        match tokio::time::timeout(Duration::from_secs(3), ws.next()).await {
            Ok(Some(Ok(Message::Ping(_)))) => pings += 1,
            Ok(Some(Ok(Message::Text(t)))) => break t,
            other => panic!("session ended early after {pings} pings: {other:?}"),
        }
    };
    assert_eq!(text.as_str(), "still here");
    assert!(
        pings >= 5,
        "only {pings} pings in 1.2 s at a 100 ms interval"
    );
    use futures_util::SinkExt;
    ws.send(Message::text("echo")).await.unwrap();
    loop {
        match ws.next().await {
            Some(Ok(Message::Text(t))) => {
                assert_eq!(t.as_str(), "echo");
                break;
            }
            Some(Ok(Message::Ping(_))) => continue,
            other => panic!("{other:?}"),
        }
    }
    ws.close(None).await.unwrap();
    while ws.next().await.is_some() {}
    assert!(wait_until(|| probe.live.load(Ordering::SeqCst) == 0).await);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn silent_peers_are_closed_after_the_idle_timeout() {
    let probe = Probe::default();
    let p = probe.clone();
    let server = serve_managed(move |ws: WebSocketUpgrade| {
        let probe = p.clone();
        async move {
            ws.managed()
                .ping_interval(Duration::from_millis(100))
                .idle_timeout(Duration::from_millis(300))
                // A dead peer never answers the close frame: do not wait long for it.
                .close_timeout(Duration::from_millis(200))
                .on_upgrade(move |mut sock: ManagedSocket| async move {
                    probe.live.fetch_add(1, Ordering::SeqCst);
                    let _g = LiveGuard(probe);
                    while sock.recv().await.is_some() {}
                })
        }
    })
    .await;
    let addr = server.local_addr();
    // Handshake by hand, then never read or write again (a dead or stuck peer).
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.write_all(ws_req(addr, "/m").as_bytes()).await.unwrap();
    let started = Instant::now();
    assert!(wait_until(|| probe.live.load(Ordering::SeqCst) == 1).await);
    assert!(
        wait_until(|| probe.dropped.load(Ordering::SeqCst) == 1).await,
        "session never ended"
    );
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(250) && took < Duration::from_secs(2),
        "{took:?}"
    );
    // The server sent pings and a close frame (opcode 0x8), then closed the stream.
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), tcp.read_to_end(&mut buf)).await;
    let body = &buf[buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4..];
    assert!(body.contains(&0x89), "no ping frame: {body:?}");
    assert!(body.contains(&0x88), "no close frame: {body:?}");
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn max_lifetime_ends_raw_and_managed_sessions() {
    let probe = Probe::default();
    let (p1, p2) = (probe.clone(), probe.clone());
    let server = Poring::new()
        .get("/raw", move |ws: WebSocketUpgrade| {
            let probe = p1.clone();
            async move {
                ws.max_lifetime(Duration::from_millis(300))
                    .on_upgrade(move |_sock| async move {
                        probe.live.fetch_add(1, Ordering::SeqCst);
                        let _g = LiveGuard(probe);
                        std::future::pending::<()>().await;
                    })
            }
        })
        .get("/managed", move |ws: WebSocketUpgrade| {
            let probe = p2.clone();
            async move {
                ws.max_lifetime(Duration::from_millis(300))
                    .managed()
                    .on_upgrade(move |mut sock: ManagedSocket| async move {
                        probe.live.fetch_add(1, Ordering::SeqCst);
                        let _g = LiveGuard(probe);
                        while sock.recv().await.is_some() {}
                    })
            }
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    let mut raw = client(addr, "/raw").await;
    let mut managed = client(addr, "/managed").await;
    assert!(wait_until(|| probe.live.load(Ordering::SeqCst) == 2).await);
    // The managed session closes with a frame (reading it lets the client reply); the raw
    // one is simply dropped.
    assert_eq!(close_code(&mut managed).await, Some(CloseCode::Away));
    // Keep reading so the client flushes its close reply.
    let _ = tokio::time::timeout(Duration::from_secs(3), async {
        while managed.next().await.is_some() {}
    })
    .await;
    assert!(wait_until(|| probe.dropped.load(Ordering::SeqCst) == 2).await);
    let raw_end = tokio::time::timeout(Duration::from_secs(3), raw.next())
        .await
        .unwrap();
    assert!(
        !matches!(raw_end, Some(Ok(Message::Text(_)))),
        "{raw_end:?}"
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn managed_sessions_close_normally_and_on_shutdown_even_if_the_app_is_stuck() {
    let server = serve_managed(|ws: WebSocketUpgrade| async move {
        ws.managed()
            .on_upgrade(|mut sock: ManagedSocket| async move {
                match sock.recv().await {
                    // "stuck": never returns and never reads again.
                    Some(Message::Text(t)) if t.as_str() == "hang" => {
                        std::future::pending::<()>().await
                    }
                    // Otherwise reply once and finish: the pump closes with 1000.
                    Some(m) => {
                        let _ = sock.send(m).await;
                    }
                    None => {}
                }
            })
    })
    .await;
    let addr = server.local_addr();
    use futures_util::SinkExt;

    let mut done = client(addr, "/m").await;
    done.send(Message::text("bye")).await.unwrap();
    assert!(matches!(done.next().await, Some(Ok(Message::Text(_)))));
    assert_eq!(close_code(&mut done).await, Some(CloseCode::Normal));

    let mut stuck = client(addr, "/m").await;
    stuck.send(Message::text("hang")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let started = Instant::now();
    let shutdown = tokio::spawn(server.shutdown());
    assert_eq!(close_code(&mut stuck).await, Some(CloseCode::Away));
    drop(stuck);
    tokio::time::timeout(Duration::from_secs(5), shutdown)
        .await
        .expect("shutdown hung")
        .unwrap()
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
}

// ---- P3.4: close semantics -------------------------------------------------------------

/// Server with a managed (`/m`) and a typed (`/t`) echo endpoint, both limited to 1 KiB
/// messages. `ended` counts handlers that observed the end of their session.
async fn serve_close_endpoints(ended: Arc<AtomicUsize>) -> poring::Server {
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    let e1 = ended.clone();
    let e2 = ended;
    Poring::new()
        .limits(grace(300))
        .get("/m", move |ws: WebSocketUpgrade| {
            let ended = e1.clone();
            async move {
                ws.max_message_size(1024).managed().on_upgrade(
                    move |mut sock: ManagedSocket| async move {
                        while let Some(m) = sock.recv().await {
                            let frame = |code: u16, reason: String| {
                                Some(CloseFrame {
                                    code: CloseCode::from(code),
                                    reason: reason.into(),
                                })
                            };
                            match m.to_text().unwrap_or("") {
                                "close-custom" => {
                                    sock.close(frame(4000, "done".into())).await;
                                    break;
                                }
                                "close-reserved" => {
                                    let _ =
                                        sock.send(Message::Close(frame(1005, "x".into()))).await;
                                }
                                "close-out-of-range" => {
                                    sock.close(frame(5000, "x".into())).await;
                                    break;
                                }
                                "close-long" => {
                                    sock.close(frame(4001, "é".repeat(100))).await;
                                    break;
                                }
                                _ => {
                                    if sock.send(m).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        ended.fetch_add(1, Ordering::SeqCst);
                    },
                )
            }
        })
        .get("/t", move |ws: WebSocketUpgrade| {
            let ended = e2.clone();
            async move {
                ws.max_message_size(1024).typed::<Chat, Chat>().on_upgrade(
                    move |mut sock| async move {
                        // Keeps going after errors: `recv` itself must end the session.
                        while let Some(r) = sock.recv().await {
                            if let Ok(m) = r
                                && sock.send(&m).await.is_err()
                            {
                                break;
                            }
                        }
                        ended.fetch_add(1, Ordering::SeqCst);
                    },
                )
            }
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap()
}

/// Performs the handshake by hand; the returned stream is positioned at the first frame.
async fn raw_ws(addr: SocketAddr, path: &str) -> tokio::net::TcpStream {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.write_all(ws_req(addr, path).as_bytes()).await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(tcp.read_u8().await.unwrap());
    }
    assert!(
        head.starts_with(b"HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    tcp
}

/// Writes one masked client frame. `first` is the first header byte (FIN + opcode).
async fn send_frame(tcp: &mut tokio::net::TcpStream, first: u8, payload: &[u8]) {
    let mask = [0x12u8, 0x34, 0x56, 0x78];
    let mut f = vec![first];
    match payload.len() {
        n if n < 126 => f.push(0x80 | n as u8),
        n if n <= 0xffff => {
            f.push(0x80 | 126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            f.push(0x80 | 127);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    f.extend_from_slice(&mask);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    tcp.write_all(&f).await.unwrap();
}

/// Reads one unfragmented server frame: (opcode, payload); `None` on EOF.
async fn read_frame(tcp: &mut tokio::net::TcpStream) -> Option<(u8, Vec<u8>)> {
    let b0 = tcp.read_u8().await.ok()?;
    let b1 = tcp.read_u8().await.ok()?;
    assert_eq!(b1 & 0x80, 0, "server frames must not be masked");
    let len = match b1 & 0x7f {
        126 => tcp.read_u16().await.ok()? as usize,
        127 => tcp.read_u64().await.ok()? as usize,
        n => n as usize,
    };
    let mut p = vec![0; len];
    tcp.read_exact(&mut p).await.ok()?;
    Some((b0 & 0x0f, p))
}

/// Reads server frames until a close frame; returns its payload (`None` on EOF/timeout).
/// Also returns the payloads of data frames seen before it.
async fn read_until_close(tcp: &mut tokio::net::TcpStream) -> (Vec<Vec<u8>>, Option<Vec<u8>>) {
    let mut data = Vec::new();
    let read = async {
        loop {
            match read_frame(tcp).await? {
                (0x8, p) => return Some(p),
                (0x1 | 0x2, p) => data.push(p),
                _ => {}
            }
        }
    };
    let close = tokio::time::timeout(Duration::from_secs(5), read)
        .await
        .ok()
        .flatten();
    (data, close)
}

fn code_of(payload: &[u8]) -> u16 {
    assert!(
        payload.len() >= 2,
        "close frame without a code: {payload:?}"
    );
    u16::from_be_bytes([payload[0], payload[1]])
}

/// The server's close code after `frames` were sent on a fresh session, and that the
/// connection is then closed by the server.
async fn close_after(addr: SocketAddr, path: &str, frames: &[(u8, Vec<u8>)]) -> u16 {
    let mut tcp = raw_ws(addr, path).await;
    for (first, payload) in frames {
        send_frame(&mut tcp, *first, payload).await;
    }
    let (_, close) = read_until_close(&mut tcp).await;
    let close = close.unwrap_or_else(|| panic!("{path}: no close frame"));
    let mut rest = Vec::new();
    let eof = tokio::time::timeout(Duration::from_secs(8), tcp.read_to_end(&mut rest)).await;
    assert!(
        eof.is_ok(),
        "{path}: server did not close the TCP connection"
    );
    code_of(&close)
}

fn close_payload(code: u16, reason: &[u8]) -> Vec<u8> {
    let mut p = code.to_be_bytes().to_vec();
    p.extend_from_slice(reason);
    p
}

#[tokio::test]
async fn peer_close_is_echoed_and_ends_the_handler() {
    let ended = Arc::new(AtomicUsize::new(0));
    let server = serve_close_endpoints(ended.clone()).await;
    let addr = server.local_addr();
    for (n, path) in ["/m", "/t"].into_iter().enumerate() {
        let mut ws = client(addr, path).await;
        let started = Instant::now();
        ws.close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
            code: CloseCode::from(4002),
            reason: "bye".into(),
        }))
        .await
        .unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .unwrap_or_else(|_| panic!("{path}: no close reply"));
        match echoed {
            Some(Ok(Message::Close(Some(f)))) => assert_eq!(u16::from(f.code), 4002, "{path}"),
            other => panic!("{path}: {other:?}"),
        }
        assert!(
            wait_until(|| ended.load(Ordering::SeqCst) == n + 1).await,
            "{path}: handler did not see the end of the session"
        );
        assert!(started.elapsed() < Duration::from_secs(2), "{path}");
    }
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn app_close_codes_are_sent_and_reserved_codes_never_reach_the_wire() {
    let server = serve_close_endpoints(Arc::new(AtomicUsize::new(0))).await;
    let addr = server.local_addr();
    use futures_util::SinkExt;
    for (cmd, want) in [
        ("close-custom", 4000u16),
        ("close-reserved", 1011),
        ("close-out-of-range", 1011),
        ("close-long", 4001),
    ] {
        let mut tcp = raw_ws(addr, "/m").await;
        send_frame(&mut tcp, 0x81, cmd.as_bytes()).await;
        let (_, close) = read_until_close(&mut tcp).await;
        let close = close.unwrap_or_else(|| panic!("{cmd}: no close frame"));
        assert!(close.len() <= 125, "{cmd}: control frame too big");
        assert_eq!(code_of(&close), want, "{cmd}");
        let reason = std::str::from_utf8(&close[2..]).expect("reason must be UTF-8");
        if cmd == "close-custom" {
            assert_eq!(reason, "done");
        }
        if cmd == "close-long" {
            assert!(
                !reason.is_empty() && reason.chars().all(|c| c == 'é'),
                "{reason:?}"
            );
        }
    }
    // The same through a normal client: the reply frame is acceptable to it.
    let mut ws = client(addr, "/m").await;
    ws.send(Message::text("close-custom")).await.unwrap();
    assert_eq!(close_code(&mut ws).await, Some(CloseCode::from(4000)));
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn invalid_close_frames_from_the_peer_fail_with_protocol_error() {
    let ended = Arc::new(AtomicUsize::new(0));
    let server = serve_close_endpoints(ended.clone()).await;
    let addr = server.local_addr();
    let mut sessions = 0;
    for path in ["/m", "/t"] {
        // Codes that must never appear on the wire, and out-of-range codes.
        for code in [
            0u16, 999, 1004, 1005, 1006, 1014, 1015, 1016, 2999, 5000, 65535,
        ] {
            let got = close_after(addr, path, &[(0x88, close_payload(code, b""))]).await;
            assert_eq!(got, 1002, "{path}: peer close code {code}");
            sessions += 1;
        }
        // A one-byte close payload.
        let got = close_after(addr, path, &[(0x88, vec![0x03])]).await;
        assert_eq!(got, 1002, "{path}: 1-byte close payload");
        // A reason that is not UTF-8.
        let got = close_after(addr, path, &[(0x88, close_payload(1000, &[0xff, 0xfe]))]).await;
        assert!(
            got == 1002 || got == 1007,
            "{path}: invalid UTF-8 reason gave {got}"
        );
        // A fragmented close frame.
        let got = close_after(addr, path, &[(0x08, close_payload(1000, b""))]).await;
        assert_eq!(got, 1002, "{path}: fragmented control frame");
        sessions += 3;
    }
    assert!(wait_until(|| ended.load(Ordering::SeqCst) == sessions).await);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn invalid_utf8_text_fails_with_1007_and_fragments_are_reassembled() {
    let ended = Arc::new(AtomicUsize::new(0));
    let server = serve_close_endpoints(ended.clone()).await;
    let addr = server.local_addr();
    for path in ["/m", "/t"] {
        assert_eq!(
            close_after(addr, path, &[(0x81, vec![0x68, 0xc3, 0x28])]).await,
            1007,
            "{path}"
        );
        // Invalid UTF-8 split across fragments.
        let frames = [(0x01, vec![0x68, 0xe2, 0x82]), (0x80, vec![0x28])];
        assert_eq!(
            close_after(addr, path, &frames).await,
            1007,
            "{path}: fragmented"
        );
    }
    // A valid fragmented message (UTF-8 sequence split between frames) is reassembled.
    let mut tcp = raw_ws(addr, "/m").await;
    send_frame(&mut tcp, 0x01, &[b'h', 0xc3]).await;
    send_frame(&mut tcp, 0x00, &[0xa9]).await;
    send_frame(&mut tcp, 0x80, b"!").await;
    let echo = tokio::time::timeout(Duration::from_secs(3), read_frame(&mut tcp))
        .await
        .unwrap();
    assert_eq!(echo, Some((0x1, "hé!".as_bytes().to_vec())));
    send_frame(&mut tcp, 0x88, &close_payload(1000, b"")).await;
    let (_, close) = read_until_close(&mut tcp).await;
    assert_eq!(code_of(&close.unwrap()), 1000);
    assert!(wait_until(|| ended.load(Ordering::SeqCst) == 5).await);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn oversized_messages_fail_with_1009() {
    let ended = Arc::new(AtomicUsize::new(0));
    let server = serve_close_endpoints(ended.clone()).await;
    let addr = server.local_addr();
    let json = |n: usize| format!(r#"{{"text":"{}"}}"#, "a".repeat(n)).into_bytes();
    for path in ["/m", "/t"] {
        // One frame over the limit.
        assert_eq!(
            close_after(addr, path, &[(0x81, json(2000))]).await,
            1009,
            "{path}"
        );
        // Fragments that are each under the limit but exceed it together.
        let big = json(1500);
        let frames = [(0x01, big[..800].to_vec()), (0x80, big[800..].to_vec())];
        assert_eq!(
            close_after(addr, path, &frames).await,
            1009,
            "{path}: fragmented"
        );
        // A message at the limit still works.
        let mut ws = client(addr, path).await;
        use futures_util::SinkExt;
        let ok = String::from_utf8(json(1000)).unwrap();
        ws.send(Message::text(ok.clone())).await.unwrap();
        match ws.next().await {
            Some(Ok(Message::Text(t))) => assert_eq!(t.as_str(), ok, "{path}"),
            other => panic!("{path}: {other:?}"),
        }
        ws.close(None).await.unwrap();
        while ws.next().await.is_some() {}
    }
    assert!(wait_until(|| ended.load(Ordering::SeqCst) == 6).await);
    server.shutdown().await.unwrap();
}

// ---- P4.4 finding: large outbound messages (tungstenite write-buffer bound) -------------

#[tokio::test]
async fn large_outbound_messages_are_sent_and_explicit_buffer_bounds_fail_cleanly() {
    use futures_util::SinkExt;
    let failed = Arc::new(AtomicBool::new(false));
    let f = failed.clone();
    let server = Poring::new()
        .get("/big", |ws: WebSocketUpgrade| async move {
            ws.on_upgrade(|mut sock| async move {
                let _ = sock.send(Message::binary(vec![9u8; 1 << 20])).await;
                let _ = sock.close(None).await;
            })
        })
        .get("/bounded", move |ws: WebSocketUpgrade| {
            let failed = f.clone();
            async move {
                ws.max_write_buffer(256 * 1024)
                    .on_upgrade(move |mut sock| async move {
                        if sock
                            .send(Message::binary(vec![9u8; 512 * 1024]))
                            .await
                            .is_err()
                        {
                            failed.store(true, Ordering::SeqCst);
                        }
                    })
            }
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    // Default configuration: a 1 MiB message arrives intact (it failed with the old
    // 256 KiB default bound).
    let mut ws = client(addr, "/big").await;
    match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
        Ok(Some(Ok(Message::Binary(b)))) => assert_eq!(b.len(), 1 << 20),
        other => panic!("{other:?}"),
    }
    // An explicit bound smaller than the message: `send` returns an error, nothing hangs.
    let _ws2 = client(addr, "/bounded").await;
    assert!(wait_until(|| failed.load(Ordering::SeqCst)).await);
    let _ = ws.send(Message::Close(None)).await;
    server.shutdown().await.unwrap();
}
