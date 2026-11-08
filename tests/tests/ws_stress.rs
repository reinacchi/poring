//! WebSocket stress tests over real TCP: many concurrent sessions,
//! non-reading clients, vanishing clients, panicking/cancelled handlers, fragment floods and
//! shutdown under load. Every test asserts that session counts and connection slots return
//! to zero and that nothing waits without a bound.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use poring::prelude::*;
use poring::ws::{ManagedSocket, WebSocketUpgrade};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

type Client = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

fn ws_req(addr: SocketAddr, path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {KEY}\r\n\r\n"
    )
}

async fn client(addr: SocketAddr, path: &str) -> Client {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (ws, resp) = tokio_tungstenite::client_async(format!("ws://{addr}{path}"), tcp)
        .await
        .unwrap();
    assert_eq!(resp.status(), 101);
    ws
}

/// Live/ended session counters.
#[derive(Clone, Default)]
struct Probe {
    live: Arc<AtomicUsize>,
    ended: Arc<AtomicUsize>,
}

impl Probe {
    fn enter(&self) -> Guard {
        self.live.fetch_add(1, Ordering::SeqCst);
        Guard(self.clone())
    }
    fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }
    fn ended(&self) -> usize {
        self.ended.load(Ordering::SeqCst)
    }
}

/// Decrements `live` when the session future finishes, panics or is cancelled.
struct Guard(Probe);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
        self.0.ended.fetch_add(1, Ordering::SeqCst);
    }
}

async fn wait_until(secs: u64, mut f: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    f()
}

fn limits(f: impl FnOnce(&mut poring::Limits)) -> poring::Limits {
    let mut l = poring::Limits {
        shutdown_grace: Duration::from_millis(500),
        ..Default::default()
    };
    f(&mut l);
    l
}

/// Managed echo endpoint at `/echo`.
fn echo(
    probe: Probe,
) -> impl Fn(WebSocketUpgrade) -> std::future::Ready<Response> + Clone + Send + Sync + 'static {
    move |ws: WebSocketUpgrade| {
        let probe = probe.clone();
        std::future::ready(ws.max_message_size(1024).managed().on_upgrade(
            move |mut sock: ManagedSocket| async move {
                let _g = probe.enter();
                while let Some(m) = sock.recv().await {
                    if sock.send(m).await.is_err() {
                        break;
                    }
                }
            },
        ))
    }
}

async fn close_code(ws: &mut Client) -> Option<CloseCode> {
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
    tokio::time::timeout(Duration::from_secs(10), read)
        .await
        .ok()
        .flatten()
}

/// One client session: `n` echoes, then a normal close.
async fn echo_session(addr: SocketAddr, n: usize) {
    let mut ws = client(addr, "/echo").await;
    for i in 0..n {
        let text = format!("message {i}");
        ws.send(Message::text(text.clone())).await.unwrap();
        match ws.next().await {
            Some(Ok(Message::Text(t))) => assert_eq!(t.as_str(), text),
            other => panic!("{other:?}"),
        }
    }
    ws.close(None).await.unwrap();
    while ws.next().await.is_some() {}
}

/// Concurrent sessions per round (default 500, override with `PORING_STRESS_SESSIONS`).
fn sessions() -> usize {
    std::env::var("PORING_STRESS_SESSIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(500)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hundreds_of_concurrent_sessions_echo_and_release_everything() {
    let sessions = sessions();
    let probe = Probe::default();
    let server = Poring::new()
        .limits(limits(|l| {
            l.max_ws_sessions = sessions;
            l.max_connections = sessions + 8;
        }))
        .get("/echo", echo(probe.clone()))
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    // Two full rounds at the session limit: the second only succeeds if every permit and
    // connection slot of the first was returned.
    for round in 1..=2 {
        let started = Instant::now();
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..sessions {
            set.spawn(echo_session(addr, 5));
        }
        while let Some(r) = set.join_next().await {
            r.unwrap();
        }
        assert!(
            wait_until(5, || probe.live() == 0).await,
            "round {round}: {} sessions still live",
            probe.live()
        );
        assert_eq!(probe.ended(), sessions * round);
        eprintln!(
            "round {round}: {sessions} sessions x 5 echoes in {:?}",
            started.elapsed()
        );
    }
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_reading_clients_stall_senders_and_are_disconnected() {
    let managed = Probe::default();
    let raw = Probe::default();
    let sent_managed = Arc::new(AtomicUsize::new(0));
    let sent_raw = Arc::new(AtomicUsize::new(0));
    let (pm, pr) = (managed.clone(), raw.clone());
    let (sm, sr) = (sent_managed.clone(), sent_raw.clone());
    const CHUNK: usize = 16 * 1024;
    let server = Poring::new()
        .limits(limits(|_| {}))
        .get("/managed", move |ws: WebSocketUpgrade| {
            let (probe, sent) = (pm.clone(), sm.clone());
            async move {
                ws.managed()
                    .no_ping()
                    .idle_timeout(Duration::from_millis(1_500))
                    .on_upgrade(move |mut sock: ManagedSocket| async move {
                        let _g = probe.enter();
                        let chunk = vec![7u8; CHUNK];
                        while sock.send(Message::binary(chunk.clone())).await.is_ok() {
                            sent.fetch_add(1, Ordering::SeqCst);
                        }
                    })
            }
        })
        .get("/raw", move |ws: WebSocketUpgrade| {
            let (probe, sent) = (pr.clone(), sr.clone());
            async move {
                ws.max_lifetime(Duration::from_millis(1_500)).on_upgrade(
                    move |mut sock| async move {
                        let _g = probe.enter();
                        let chunk = vec![7u8; CHUNK];
                        while sock.send(Message::binary(chunk.clone())).await.is_ok() {
                            sent.fetch_add(1, Ordering::SeqCst);
                        }
                    },
                )
            }
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    for (path, probe, sent) in [
        ("/managed", &managed, &sent_managed),
        ("/raw", &raw, &sent_raw),
    ] {
        // A peer that completes the handshake and then never reads or writes.
        let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        tcp.write_all(ws_req(addr, path).as_bytes()).await.unwrap();
        let started = Instant::now();
        assert!(wait_until(3, || probe.live() == 1).await, "{path}");
        // The sender stalls: the count stops growing once buffers are full.
        tokio::time::sleep(Duration::from_millis(600)).await;
        let a = sent.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let b = sent.load(Ordering::SeqCst);
        assert_eq!(a, b, "{path}: sender did not stall");
        assert!(b > 0, "{path}: nothing was sent");
        // And the session is ended by the idle bound (managed) or lifetime (raw).
        assert!(
            wait_until(5, || probe.ended() == 1).await,
            "{path}: session never ended"
        );
        let took = started.elapsed();
        assert!(took < Duration::from_secs(4), "{path}: {took:?}");
        eprintln!(
            "{path}: sender stalled after {b} x {CHUNK} B (~{} KiB buffered by server queues + kernel); ended after {took:?}",
            b * CHUNK / 1024
        );
        drop(tcp);
    }
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vanishing_clients_release_connection_slots_and_sessions() {
    const SLOTS: usize = 16;
    let probe = Probe::default();
    let server = Poring::new()
        .limits(limits(|l| {
            l.max_connections = SLOTS;
            l.header_read_timeout = Duration::from_millis(500);
        }))
        .get("/echo", echo(probe.clone()))
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    let full = ws_req(addr, "/echo");
    let mut set = tokio::task::JoinSet::new();
    for i in 0..150 {
        let full = full.clone();
        set.spawn(async move {
            let Ok(mut tcp) = tokio::net::TcpStream::connect(addr).await else {
                return;
            };
            match i % 3 {
                // Connect and vanish.
                0 => {}
                // Half a handshake request, then vanish.
                1 => {
                    let _ = tcp.write_all(&full.as_bytes()[..full.len() / 2]).await;
                }
                // Full handshake, then half a frame (header claims 1000 bytes), then vanish.
                _ => {
                    if tcp.write_all(full.as_bytes()).await.is_err() {
                        return;
                    }
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        match tcp.read_u8().await {
                            Ok(b) => head.push(b),
                            Err(_) => return,
                        }
                    }
                    let mut frame = vec![0x82, 0x80 | 126, 0x03, 0xe8, 1, 2, 3, 4];
                    frame.extend_from_slice(&[0u8; 10]);
                    let _ = tcp.write_all(&frame).await;
                }
            }
            drop(tcp);
        });
        // Keep at most SLOTS attempts in flight so every kind actually reaches the server.
        if set.len() >= SLOTS {
            set.join_next().await.unwrap().unwrap();
        }
    }
    while let Some(r) = set.join_next().await {
        r.unwrap();
    }
    assert!(
        wait_until(5, || probe.live() == 0).await,
        "{} sessions still live",
        probe.live()
    );
    assert!(probe.ended() > 0, "no upgraded session was started");
    eprintln!(
        "mid-message disconnects that reached a handler: {}",
        probe.ended()
    );
    // Every connection slot is free again: SLOTS concurrent sessions all upgrade.
    let mut clients = Vec::new();
    for _ in 0..SLOTS {
        let r = tokio::time::timeout(Duration::from_secs(5), client(addr, "/echo")).await;
        clients.push(r.expect("slot was not released"));
    }
    for mut c in clients {
        c.close(None).await.unwrap();
        while c.next().await.is_some() {}
    }
    assert!(wait_until(5, || probe.live() == 0).await);
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn panicking_and_cancelled_handlers_under_load_release_permits() {
    const N: usize = 100;
    let probe = Probe::default();
    let p = probe.clone();
    let server = Poring::new()
        .limits(limits(|l| l.max_ws_sessions = N))
        .get("/panic", move |ws: WebSocketUpgrade| {
            let probe = p.clone();
            async move {
                ws.max_lifetime(Duration::from_millis(300))
                    .on_upgrade(move |mut sock| async move {
                        let _g = probe.enter();
                        match sock.next().await {
                            Some(Ok(Message::Text(t))) if t.as_str() == "panic" => {
                                panic!("handler panic (expected by test)")
                            }
                            // Otherwise hang until max_lifetime cancels the session.
                            _ => std::future::pending::<()>().await,
                        }
                    })
            }
        })
        .get("/echo", echo(probe.clone()))
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    let mut set = tokio::task::JoinSet::new();
    for i in 0..N {
        set.spawn(async move {
            let mut ws = client(addr, "/panic").await;
            let msg = if i % 2 == 0 { "panic" } else { "hang" };
            ws.send(Message::text(msg)).await.unwrap();
            // Either way the server side ends: read until the stream does.
            let ended = tokio::time::timeout(Duration::from_secs(5), async {
                while let Some(Ok(_)) = ws.next().await {}
            })
            .await;
            assert!(ended.is_ok(), "session {i} was never ended");
        });
    }
    while let Some(r) = set.join_next().await {
        r.unwrap();
    }
    assert!(wait_until(5, || probe.live() == 0).await);
    assert_eq!(probe.ended(), N);
    // All N permits are back: N new sessions are admitted.
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..N {
        set.spawn(echo_session(addr, 1));
    }
    while let Some(r) = set.join_next().await {
        r.unwrap();
    }
    assert!(wait_until(5, || probe.live() == 0).await);
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn endless_fragments_are_cut_off_at_the_message_limit() {
    let probe = Probe::default();
    let server = Poring::new()
        .limits(limits(|_| {}))
        .get("/echo", echo(probe.clone()))
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.write_all(ws_req(addr, "/echo").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(tcp.read_u8().await.unwrap());
    }
    // A text message that never ends: one-byte masked continuation frames, 1 KiB limit.
    let (mut rd, mut wr) = tcp.into_split();
    let writer = tokio::spawn(async move {
        let mut frames = vec![0x01, 0x81, 0, 0, 0, 0, b'a'];
        for _ in 0..4_000 {
            frames.extend_from_slice(&[0x00, 0x81, 0, 0, 0, 0, b'a']);
        }
        // The server may close the connection before everything is written.
        let _ = wr.write_all(&frames).await;
    });
    let mut buf = Vec::new();
    let r = tokio::time::timeout(Duration::from_secs(5), rd.read_to_end(&mut buf)).await;
    assert!(r.is_ok(), "server did not close the connection");
    // Server frame: 0x88, len, code (big-endian).
    let pos = buf.iter().position(|&b| b == 0x88).expect("no close frame");
    let code = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
    assert_eq!(code, 1009);
    let _ = writer.await;
    assert!(wait_until(5, || probe.live() == 0).await);
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_with_hundreds_of_open_sessions_is_bounded() {
    const MANAGED: usize = 300;
    const STUCK: usize = 50;
    let probe = Probe::default();
    let p = probe.clone();
    let server = Poring::new()
        .limits(limits(|l| l.shutdown_grace = Duration::from_secs(1)))
        .get("/echo", echo(probe.clone()))
        .get("/stuck", move |ws: WebSocketUpgrade| {
            let probe = p.clone();
            async move {
                // Ignores shutdown entirely: must be cancelled at the grace deadline.
                ws.on_upgrade(move |_sock| async move {
                    let _g = probe.enter();
                    std::future::pending::<()>().await;
                })
            }
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    let mut managed = Vec::new();
    for _ in 0..MANAGED {
        managed.push(client(addr, "/echo").await);
    }
    let mut stuck = Vec::new();
    for _ in 0..STUCK {
        stuck.push(client(addr, "/stuck").await);
    }
    assert!(wait_until(5, || probe.live() == MANAGED + STUCK).await);
    let started = Instant::now();
    let shutdown = tokio::spawn(server.shutdown());
    // Every managed client gets 1001 and completes its side of the close.
    let mut set = tokio::task::JoinSet::new();
    for mut ws in managed {
        set.spawn(async move { close_code(&mut ws).await });
    }
    let mut away = 0;
    while let Some(r) = set.join_next().await {
        if r.unwrap() == Some(CloseCode::Away) {
            away += 1;
        }
    }
    assert_eq!(away, MANAGED);
    tokio::time::timeout(Duration::from_secs(5), shutdown)
        .await
        .expect("shutdown hung")
        .unwrap()
        .unwrap();
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(900) && took < Duration::from_secs(3),
        "{took:?}"
    );
    assert_eq!(probe.live(), 0);
    assert_eq!(probe.ended(), MANAGED + STUCK);
    eprintln!("shutdown with {MANAGED} managed + {STUCK} stuck sessions took {took:?} (grace 1 s)");
    drop(stuck);
}
