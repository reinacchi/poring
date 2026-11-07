//! Managed-session reliability over real TCP: session cleanup when the transport ends
//! first, handler panics, heartbeat (ping/pong) enforcement, zero and maximum session
//! limits, and outbound backpressure against slow and vanished clients.
//!
//! Every wait is bounded. Heartbeat tests use a raw frame-level client, because a
//! tungstenite client answers pings automatically and so cannot "ignore" one.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use poring::prelude::*;
use poring::ws::{ManagedSocket, WebSocketUpgrade, WsError};
use poring_tests::status_of;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const BOUND: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------------------
// Helpers

fn ws_req(addr: SocketAddr, path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {KEY}\r\n\r\n"
    )
}

/// Response head of a raw request ("" on timeout/close).
async fn head(addr: SocketAddr, request: String) -> String {
    let Ok(mut s) = tokio::net::TcpStream::connect(addr).await else {
        return String::new();
    };
    let _ = s.write_all(request.as_bytes()).await;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let _ = tokio::time::timeout(BOUND, async {
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

/// Polls `cond` until it holds (bounded).
async fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
    let start = Instant::now();
    while !cond() {
        assert!(start.elapsed() < BOUND, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A frame-level WebSocket client that never answers anything on its own.
struct Raw {
    s: tokio::net::TcpStream,
    buf: Vec<u8>,
}

#[derive(Debug, PartialEq)]
struct Frame {
    opcode: u8,
    payload: Vec<u8>,
}

const TEXT: u8 = 0x1;
const CLOSE: u8 = 0x8;
const PING: u8 = 0x9;
const PONG: u8 = 0xA;

impl Raw {
    async fn connect(addr: SocketAddr, path: &str) -> Raw {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(ws_req(addr, path).as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let end = loop {
            let n = tokio::time::timeout(BOUND, s.read(&mut chunk))
                .await
                .expect("handshake response")
                .unwrap();
            assert!(n > 0, "closed during handshake");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
        assert_eq!(status_of(&head), 101, "{head}");
        buf.drain(..end);
        Raw { s, buf }
    }

    /// Sends one masked frame.
    async fn send(&mut self, opcode: u8, payload: &[u8]) {
        let mask = [0x12u8, 0x34, 0x56, 0x78];
        let mut f = vec![0x80 | opcode];
        match payload.len() {
            n if n < 126 => f.push(0x80 | n as u8),
            n => {
                f.push(0x80 | 126);
                f.extend_from_slice(&(n as u16).to_be_bytes());
            }
        }
        f.extend_from_slice(&mask);
        f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        let _ = self.s.write_all(&f).await;
    }

    /// The next frame from the server, or `None` on EOF or after `wait`.
    async fn next(&mut self, wait: Duration) -> Option<Frame> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            if let Some(f) = self.parse() {
                return Some(f);
            }
            let mut chunk = [0u8; 4096];
            let n = tokio::time::timeout_at(deadline, self.s.read(&mut chunk))
                .await
                .ok()?
                .unwrap_or(0);
            if n == 0 {
                return None;
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    fn parse(&mut self) -> Option<Frame> {
        let b = &self.buf;
        if b.len() < 2 {
            return None;
        }
        let opcode = b[0] & 0x0f;
        let (len, at) = match b[1] & 0x7f {
            126 if b.len() >= 4 => (u16::from_be_bytes([b[2], b[3]]) as usize, 4),
            127 if b.len() >= 10 => (
                u64::from_be_bytes(b[2..10].try_into().unwrap()) as usize,
                10,
            ),
            126 | 127 => return None,
            n => (n as usize, 2),
        };
        if b.len() < at + len {
            return None;
        }
        let payload = b[at..at + len].to_vec();
        self.buf.drain(..at + len);
        Some(Frame { opcode, payload })
    }

    /// Reads until a close frame; returns its code and reason, counting pings seen.
    async fn until_close(&mut self, wait: Duration) -> (Option<u16>, String, usize) {
        let deadline = Instant::now() + wait;
        let mut pings = 0;
        while let Some(f) = self
            .next(deadline.saturating_duration_since(Instant::now()))
            .await
        {
            match f.opcode {
                PING => pings += 1,
                CLOSE => {
                    let code = (f.payload.len() >= 2)
                        .then(|| u16::from_be_bytes([f.payload[0], f.payload[1]]));
                    let reason =
                        String::from_utf8_lossy(f.payload.get(2..).unwrap_or(&[])).into_owned();
                    return (code, reason, pings);
                }
                _ => {}
            }
        }
        (None, String::new(), pings)
    }
}

/// Counts handler starts, normal returns and drops (cancellation included).
#[derive(Clone, Default)]
struct Probe {
    started: Arc<AtomicUsize>,
    returned: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
}

struct DropGuard(Arc<AtomicUsize>);
impl Drop for DropGuard {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl Probe {
    fn get(c: &AtomicUsize) -> usize {
        c.load(Ordering::SeqCst)
    }
}

async fn echo(mut sock: ManagedSocket) {
    while let Some(m) = sock.recv().await {
        if sock.send(m).await.is_err() {
            break;
        }
    }
}

// ---------------------------------------------------------------------------------------
// Session cleanup

async fn cleanup_server(probe: Probe, limits: poring::Limits) -> poring::Server {
    let stuck = probe.clone();
    let reader = probe.clone();
    Poring::new()
        .limits(limits)
        .get("/plain", || async { "plain" })
        // Holds the socket and never reads or returns.
        .ws("/stuck", move |ws: WebSocketUpgrade| {
            let p = stuck.clone();
            async move {
                ws.managed()
                    .close_timeout(Duration::from_millis(200))
                    .on_upgrade(move |sock| async move {
                        p.started.fetch_add(1, Ordering::SeqCst);
                        let _guard = DropGuard(p.dropped.clone());
                        let _sock = sock;
                        std::future::pending::<()>().await;
                    })
            }
        })
        // Reads until the session ends, then returns normally.
        .ws("/reader", move |ws: WebSocketUpgrade| {
            let p = reader.clone();
            async move {
                ws.managed()
                    .close_timeout(Duration::from_millis(200))
                    .on_upgrade(move |mut sock| async move {
                        p.started.fetch_add(1, Ordering::SeqCst);
                        let _guard = DropGuard(p.dropped.clone());
                        while sock.recv().await.is_some() {}
                        p.returned.fetch_add(1, Ordering::SeqCst);
                    })
            }
        })
        .ws("/bye", |ws: WebSocketUpgrade| async move {
            ws.managed().on_upgrade(|mut sock| async move {
                let _ = sock.send(Message::text("bye")).await;
            })
        })
        .ws("/panic", |ws: WebSocketUpgrade| async move {
            ws.managed().on_upgrade(|sock| async move {
                // Holds the socket while it panics, like a real mid-session bug.
                let _sock = sock;
                tokio::task::yield_now().await;
                panic!("handler bug (expected by the test)");
            })
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap()
}

#[tokio::test]
async fn pending_handler_is_released_when_the_client_disconnects() {
    let probe = Probe::default();
    let server = cleanup_server(
        probe.clone(),
        poring::Limits {
            max_ws_sessions: 1,
            ..Default::default()
        },
    )
    .await;
    let addr = server.local_addr();

    // Abrupt disconnect (no close frame).
    let ws = client(addr, "/stuck").await;
    eventually("session started", || Probe::get(&probe.started) == 1).await;
    assert_eq!(status_of(&head(addr, ws_req(addr, "/stuck")).await), 503);
    drop(ws);
    eventually("session released", || {
        server.ws_stats().active_sessions == 0
    })
    .await;
    assert_eq!(
        Probe::get(&probe.dropped),
        1,
        "the stuck handler was cancelled"
    );

    // The permit came back without any shutdown: a new session is admitted.
    let mut ws = client(addr, "/stuck").await;
    eventually("second session", || Probe::get(&probe.started) == 2).await;

    // Clean close from the client: same outcome.
    ws.close(None).await.unwrap();
    eventually("closed session released", || {
        server.ws_stats().active_sessions == 0
    })
    .await;
    assert_eq!(Probe::get(&probe.dropped), 2);
    let _third = client(addr, "/stuck").await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn transport_ending_first_lets_a_reading_handler_return_normally() {
    let probe = Probe::default();
    let server = cleanup_server(probe.clone(), poring::Limits::default()).await;
    let addr = server.local_addr();
    let ws = client(addr, "/reader").await;
    eventually("started", || Probe::get(&probe.started) == 1).await;
    drop(ws);
    eventually("returned", || Probe::get(&probe.returned) == 1).await;
    eventually("released", || server.ws_stats().active_sessions == 0).await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn handler_completing_first_closes_normally() {
    let server = cleanup_server(Probe::default(), poring::Limits::default()).await;
    let addr = server.local_addr();
    let mut ws = client(addr, "/bye").await;
    let first = tokio::time::timeout(BOUND, ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first, Message::text("bye"));
    match tokio::time::timeout(BOUND, ws.next()).await.unwrap() {
        Some(Ok(Message::Close(Some(f)))) => assert_eq!(f.code, CloseCode::Normal),
        other => panic!("expected a 1000 close, got {other:?}"),
    }
    drop(ws);
    eventually("released", || server.ws_stats().active_sessions == 0).await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn handler_panic_closes_with_1011_and_releases_the_session() {
    let server = cleanup_server(Probe::default(), poring::Limits::default()).await;
    let addr = server.local_addr();
    let mut ws = client(addr, "/panic").await;
    let close = loop {
        match tokio::time::timeout(BOUND, ws.next()).await.unwrap() {
            Some(Ok(Message::Close(f))) => break f,
            Some(Ok(_)) => continue,
            other => panic!("expected a close frame, got {other:?}"),
        }
    };
    assert_eq!(close.map(|f| f.code), Some(CloseCode::Error));
    drop(ws);
    eventually("released", || server.ws_stats().active_sessions == 0).await;
    assert_eq!(server.ws_stats().sessions_panicked, 1);
    // The server is unaffected.
    let _ws = client(addr, "/reader").await;
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_sessions_ending_concurrently_are_all_released() {
    let probe = Probe::default();
    let server = cleanup_server(
        probe.clone(),
        poring::Limits {
            max_ws_sessions: 64,
            ..Default::default()
        },
    )
    .await;
    let addr = server.local_addr();
    let mut clients = Vec::new();
    for i in 0..50 {
        clients.push(client(addr, if i % 2 == 0 { "/stuck" } else { "/reader" }).await);
    }
    eventually("all started", || Probe::get(&probe.started) == 50).await;
    assert_eq!(server.ws_stats().active_sessions, 50);
    drop(clients);
    eventually("all released", || server.ws_stats().active_sessions == 0).await;
    assert_eq!(Probe::get(&probe.dropped), 50);
    assert_eq!(server.ws_stats().sessions_ended, 50);
    // Capacity is fully available again.
    let mut again = Vec::new();
    for _ in 0..64 {
        again.push(client(addr, "/reader").await);
    }
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_racing_ordinary_disconnects_completes() {
    let probe = Probe::default();
    let server = cleanup_server(
        probe.clone(),
        poring::Limits {
            shutdown_grace: Duration::from_millis(300),
            ..Default::default()
        },
    )
    .await;
    let addr = server.local_addr();
    let mut clients = Vec::new();
    for i in 0..20 {
        clients.push(client(addr, if i % 2 == 0 { "/stuck" } else { "/reader" }).await);
    }
    eventually("all started", || Probe::get(&probe.started) == 20).await;
    let half: Vec<_> = clients.drain(..10).collect();
    let disconnect = tokio::spawn(async move { drop(half) });
    let started = Instant::now();
    tokio::time::timeout(BOUND, server.shutdown())
        .await
        .expect("shutdown is bounded")
        .unwrap();
    disconnect.await.unwrap();
    assert!(started.elapsed() < BOUND);
    // Every handler future is gone once `shutdown` returned: nothing outlives the server.
    assert_eq!(Probe::get(&probe.dropped), 20);
    drop(clients);
}

#[tokio::test]
async fn completed_sessions_leave_nothing_behind_while_idle() {
    let probe = Probe::default();
    let server = cleanup_server(probe.clone(), poring::Limits::default()).await;
    let addr = server.local_addr();
    for _ in 0..200 {
        let mut ws = client(addr, "/reader").await;
        ws.close(None).await.unwrap();
        while let Some(Ok(_)) = ws.next().await {}
    }
    // No further handshake arrives; the server sits idle.
    eventually("all ended", || server.ws_stats().sessions_ended == 200).await;
    let s = server.ws_stats();
    assert_eq!(s.active_sessions, 0);
    assert_eq!(Probe::get(&probe.returned), 200);
    assert_eq!(Probe::get(&probe.dropped), 200);
    server.shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------------------
// Session limits: zero, one, maximum

#[tokio::test]
async fn zero_session_limit_admits_no_session() {
    let probe = Probe::default();
    let server = cleanup_server(
        probe.clone(),
        poring::Limits {
            max_ws_sessions: 0,
            ..Default::default()
        },
    )
    .await;
    let addr = server.local_addr();
    for _ in 0..3 {
        assert_eq!(status_of(&head(addr, ws_req(addr, "/reader")).await), 503);
    }
    let plain = head(
        addr,
        format!("GET /plain HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert_eq!(status_of(&plain), 200, "plain HTTP is unaffected");
    assert_eq!(server.ws_stats().rejected_session_limit, 3);
    assert_eq!(Probe::get(&probe.started), 0);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn zero_per_ip_limit_refuses_every_client() {
    let server = cleanup_server(
        Probe::default(),
        poring::Limits {
            max_ws_sessions_per_ip: 0,
            ..Default::default()
        },
    )
    .await;
    let addr = server.local_addr();
    assert_eq!(status_of(&head(addr, ws_req(addr, "/reader")).await), 429);
    assert_eq!(server.ws_stats().rejected_client_cap, 1);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn limit_of_one_is_exhausted_and_reclaimed() {
    let server = cleanup_server(
        Probe::default(),
        poring::Limits {
            max_ws_sessions: 1,
            ..Default::default()
        },
    )
    .await;
    let addr = server.local_addr();
    let mut ws = client(addr, "/reader").await;
    assert_eq!(status_of(&head(addr, ws_req(addr, "/reader")).await), 503);
    ws.close(None).await.unwrap();
    while let Some(Ok(_)) = ws.next().await {}
    eventually("released", || server.ws_stats().active_sessions == 0).await;
    let _ws = client(addr, "/reader").await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn maximum_configurable_limits_do_not_panic() {
    let server = cleanup_server(
        Probe::default(),
        poring::Limits {
            max_ws_sessions: usize::MAX,
            max_connections: usize::MAX,
            ..Default::default()
        },
    )
    .await;
    let addr = server.local_addr();
    let _ws = client(addr, "/reader").await;
    server.shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------------------
// Heartbeats

async fn heartbeat_server() -> poring::Server {
    Poring::new()
        .ws("/hb", |ws: WebSocketUpgrade| async move {
            ws.managed()
                .ping_interval(Duration::from_millis(100))
                .pong_timeout(Duration::from_millis(200))
                .on_upgrade(echo)
        })
        .ws("/hb-off", |ws: WebSocketUpgrade| async move {
            ws.managed().no_ping().on_upgrade(echo)
        })
        .ws("/hb-no-pong", |ws: WebSocketUpgrade| async move {
            ws.managed()
                .ping_interval(Duration::from_millis(100))
                .no_pong_timeout()
                .on_upgrade(echo)
        })
        .ws("/hb-long", |ws: WebSocketUpgrade| async move {
            ws.managed()
                .ping_interval(Duration::from_millis(100))
                .pong_timeout(Duration::from_secs(30))
                .on_upgrade(echo)
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap()
}

#[tokio::test]
async fn a_client_answering_pings_stays_connected() {
    let server = heartbeat_server().await;
    let addr = server.local_addr();
    // tungstenite answers pings while it reads.
    let mut ws = client(addr, "/hb").await;
    for i in 0..10 {
        ws.send(Message::text(format!("m{i}"))).await.unwrap();
        loop {
            match tokio::time::timeout(BOUND, ws.next()).await.unwrap() {
                Some(Ok(Message::Text(t))) => {
                    assert_eq!(t.as_str(), format!("m{i}"));
                    break;
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                other => panic!("session ended: {other:?}"),
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(server.ws_stats().heartbeat_timeouts, 0);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_raw_client_echoing_the_challenge_stays_connected() {
    let server = heartbeat_server().await;
    let addr = server.local_addr();
    let mut raw = Raw::connect(addr, "/hb").await;
    let mut pings = 0;
    let deadline = Instant::now() + Duration::from_millis(900);
    while let Some(f) = raw
        .next(deadline.saturating_duration_since(Instant::now()))
        .await
    {
        assert_ne!(f.opcode, CLOSE, "closed although every ping was answered");
        if f.opcode == PING {
            pings += 1;
            assert_eq!(f.payload.len(), 8, "challenge payload");
            raw.send(PONG, &f.payload).await;
        }
    }
    assert!(pings >= 3, "challenges keep coming: {pings}");
    raw.send(TEXT, b"still here").await;
    // Pings keep coming every 100 ms and may arrive before the echo: keep answering them.
    let f = loop {
        let f = raw.next(BOUND).await.expect("echo");
        assert_ne!(f.opcode, CLOSE, "closed although every ping was answered");
        if f.opcode == PING {
            raw.send(PONG, &f.payload).await;
            continue;
        }
        break f;
    };
    assert_eq!((f.opcode, f.payload.as_slice()), (TEXT, &b"still here"[..]));
    assert_eq!(server.ws_stats().heartbeat_timeouts, 0);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn ignoring_pings_closes_the_session() {
    let server = heartbeat_server().await;
    let addr = server.local_addr();
    let mut raw = Raw::connect(addr, "/hb").await;
    let started = Instant::now();
    let (code, reason, pings) = raw.until_close(BOUND).await;
    assert_eq!(code, Some(1001), "{reason}");
    assert_eq!(reason, "heartbeat timeout");
    assert_eq!(pings, 1, "only one challenge is outstanding at a time");
    assert!(started.elapsed() < Duration::from_secs(2));
    eventually("counted", || server.ws_stats().heartbeat_timeouts == 1).await;
    eventually("released", || server.ws_stats().active_sessions == 0).await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn data_traffic_does_not_satisfy_the_heartbeat() {
    let server = heartbeat_server().await;
    let addr = server.local_addr();
    let mut raw = Raw::connect(addr, "/hb").await;
    let deadline = Instant::now() + BOUND;
    let mut echoes = 0;
    let code = loop {
        assert!(Instant::now() < deadline, "never closed");
        raw.send(TEXT, b"busy").await;
        match raw.next(Duration::from_millis(50)).await {
            Some(Frame { opcode: TEXT, .. }) => echoes += 1,
            Some(Frame {
                opcode: CLOSE,
                payload,
            }) => break u16::from_be_bytes([payload[0], payload[1]]),
            _ => {}
        }
    };
    assert_eq!(code, 1001);
    assert!(echoes > 0, "data was flowing");
    eventually("counted", || server.ws_stats().heartbeat_timeouts == 1).await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn wrong_or_unsolicited_pongs_do_not_count() {
    let server = heartbeat_server().await;
    let addr = server.local_addr();
    let mut raw = Raw::connect(addr, "/hb").await;
    raw.send(PONG, b"unsolicited").await;
    let deadline = Instant::now() + BOUND;
    let code = loop {
        let f = raw
            .next(deadline.saturating_duration_since(Instant::now()))
            .await
            .expect("closed with a frame");
        match f.opcode {
            PING => raw.send(PONG, b"wrong payload").await,
            CLOSE => break u16::from_be_bytes([f.payload[0], f.payload[1]]),
            _ => {}
        }
    };
    assert_eq!(code, 1001);
    eventually("counted", || server.ws_stats().heartbeat_timeouts == 1).await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_late_pong_does_not_save_the_session() {
    let server = heartbeat_server().await;
    let addr = server.local_addr();
    let mut raw = Raw::connect(addr, "/hb").await;
    let ping = loop {
        let f = raw.next(BOUND).await.expect("a ping");
        if f.opcode == PING {
            break f.payload;
        }
    };
    // 300 ms after the ping: past its 200 ms deadline, while the server is still draining
    // input for its close reply (another 200 ms), so the late pong is delivered and must
    // not count.
    tokio::time::sleep(Duration::from_millis(300)).await;
    raw.send(PONG, &ping).await;
    let (code, reason, _) = raw.until_close(BOUND).await;
    assert_eq!((code, reason.as_str()), (Some(1001), "heartbeat timeout"));
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn disabled_heartbeats_send_no_pings_and_enforce_nothing() {
    let server = heartbeat_server().await;
    let addr = server.local_addr();
    let mut raw = Raw::connect(addr, "/hb-off").await;
    assert_eq!(
        raw.next(Duration::from_millis(600)).await,
        None,
        "no frames"
    );
    raw.send(TEXT, b"hi").await;
    assert_eq!(
        raw.next(BOUND).await,
        Some(Frame {
            opcode: TEXT,
            payload: b"hi".to_vec()
        })
    );

    // Pings without pong enforcement: ignoring them is fine.
    let mut raw = Raw::connect(addr, "/hb-no-pong").await;
    let deadline = Instant::now() + Duration::from_millis(600);
    let mut pings = 0;
    while let Some(f) = raw
        .next(deadline.saturating_duration_since(Instant::now()))
        .await
    {
        assert_ne!(f.opcode, CLOSE);
        pings += usize::from(f.opcode == PING);
    }
    assert!(pings >= 3, "{pings}");
    assert_eq!(server.ws_stats().heartbeat_timeouts, 0);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_while_waiting_for_a_pong() {
    let server = heartbeat_server().await;
    let addr = server.local_addr();
    let mut raw = Raw::connect(addr, "/hb-long").await;
    loop {
        if raw.next(BOUND).await.expect("a ping").opcode == PING {
            break;
        }
    }
    // A challenge is outstanding (30 s deadline) when shutdown begins.
    let shutdown = tokio::spawn(server.shutdown());
    let (code, reason, _) = raw.until_close(BOUND).await;
    assert_eq!(
        (code, reason.as_str()),
        (Some(1001), "server shutting down")
    );
    raw.send(CLOSE, &1000u16.to_be_bytes()).await;
    tokio::time::timeout(BOUND, shutdown)
        .await
        .expect("bounded")
        .unwrap()
        .unwrap();
}

// ---------------------------------------------------------------------------------------
// Outbound backpressure against real sockets

#[derive(Clone, Default)]
struct Flood {
    accepted: Arc<AtomicUsize>,
    failed: Arc<AtomicUsize>,
    oversized: Arc<AtomicUsize>,
}

async fn flood_server(flood: Flood) -> poring::Server {
    Poring::new()
        .ws("/flood", move |ws: WebSocketUpgrade| {
            let f = flood.clone();
            async move {
                ws.managed()
                    .queue_messages(4)
                    .max_queued_bytes(256 * 1024)
                    .max_outbound_message(128 * 1024)
                    .close_timeout(Duration::from_millis(200))
                    .on_upgrade(move |mut sock| async move {
                        // Above the per-message limit: refused at once, session continues.
                        if let Err(WsError::Socket(_)) =
                            sock.send(Message::binary(vec![0u8; 200 * 1024])).await
                        {
                            f.oversized.fetch_add(1, Ordering::SeqCst);
                        }
                        // 64 MiB in 64 KiB messages: far more than may ever be queued.
                        for _ in 0..1024 {
                            if sock
                                .send(Message::binary(vec![7u8; 64 * 1024]))
                                .await
                                .is_err()
                            {
                                f.failed.fetch_add(1, Ordering::SeqCst);
                                return;
                            }
                            f.accepted.fetch_add(64 * 1024, Ordering::SeqCst);
                        }
                    })
            }
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap()
}

#[tokio::test]
async fn a_slow_client_stalls_the_sender_and_a_vanished_one_releases_it() {
    let flood = Flood::default();
    let server = flood_server(flood.clone()).await;
    let addr = server.local_addr();
    let mut ws = client(addr, "/flood").await;

    // The client does not read: once kernel buffers and the byte budget are full, `send`
    // must stop completing.
    let stalled = {
        let mut last = usize::MAX;
        let start = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let now = Probe::get(&flood.accepted);
            if now == last {
                break now;
            }
            last = now;
            assert!(start.elapsed() < BOUND, "sender never stalled");
        }
    };
    assert_eq!(Probe::get(&flood.oversized), 1);
    assert!(
        stalled < 1024 * 64 * 1024,
        "backpressure bounded the queue (accepted {stalled} bytes)"
    );

    // Reading lets the sender progress again.
    for _ in 0..32 {
        match tokio::time::timeout(BOUND, ws.next()).await.unwrap() {
            Some(Ok(Message::Binary(b))) => assert_eq!(b.len(), 64 * 1024),
            other => panic!("{other:?}"),
        }
    }
    eventually("sender resumed", || Probe::get(&flood.accepted) > stalled).await;

    // The client vanishes mid-flood: the blocked send fails (or the handler is cancelled)
    // and the session is released.
    drop(ws);
    eventually("released", || server.ws_stats().active_sessions == 0).await;
    server.shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------------------
// Blocked outbound writes: a client that completes the handshake and then stops reading

/// What a flooding handler managed to queue, and whether it is still running.
#[derive(Clone, Default)]
struct Stall {
    queued: Arc<AtomicUsize>,
    started: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
}

/// Sends 64 KiB binary messages until `send` fails (or `limit` messages were sent).
async fn flood(mut sock: ManagedSocket, s: Stall, limit: usize) {
    s.started.fetch_add(1, Ordering::SeqCst);
    let _guard = DropGuard(s.dropped.clone());
    for _ in 0..limit {
        if sock
            .send(Message::binary(vec![7u8; 64 * 1024]))
            .await
            .is_err()
        {
            return;
        }
        s.queued.fetch_add(1, Ordering::SeqCst);
    }
}

async fn stall_server(s: Stall, limits: poring::Limits) -> poring::Server {
    let (a, b, c, d) = (s.clone(), s.clone(), s.clone(), s.clone());
    Poring::new()
        .limits(limits)
        // No idle timeout, no heartbeat: only shutdown (or the peer) ends the session.
        .ws("/no-timers", move |ws: WebSocketUpgrade| {
            let s = a.clone();
            async move {
                ws.managed()
                    .no_idle_timeout()
                    .no_ping()
                    .queue_messages(4)
                    .max_queued_bytes(256 * 1024)
                    .close_timeout(Duration::from_millis(200))
                    .on_upgrade(move |sock| flood(sock, s, usize::MAX))
            }
        })
        // Heartbeat only (no idle timeout): an unanswered ping must end the session even
        // while a data write is blocked.
        .ws("/heartbeat", move |ws: WebSocketUpgrade| {
            let s = b.clone();
            async move {
                ws.managed()
                    .no_idle_timeout()
                    .ping_interval(Duration::from_millis(100))
                    .pong_timeout(Duration::from_millis(300))
                    .queue_messages(4)
                    .max_queued_bytes(256 * 1024)
                    .close_timeout(Duration::from_millis(200))
                    .on_upgrade(move |sock| flood(sock, s, usize::MAX))
            }
        })
        // Idle timeout only.
        .ws("/idle", move |ws: WebSocketUpgrade| {
            let s = c.clone();
            async move {
                ws.managed()
                    .idle_timeout(Duration::from_millis(300))
                    .no_ping()
                    .queue_messages(4)
                    .max_queued_bytes(256 * 1024)
                    .close_timeout(Duration::from_millis(200))
                    .on_upgrade(move |sock| flood(sock, s, usize::MAX))
            }
        })
        // A bounded burst that a reading client receives in full.
        .ws("/burst", move |ws: WebSocketUpgrade| {
            let s = d.clone();
            async move {
                ws.managed()
                    .no_idle_timeout()
                    .ping_interval(Duration::from_millis(50))
                    .pong_timeout(Duration::from_millis(300))
                    .queue_messages(4)
                    .max_queued_bytes(256 * 1024)
                    .on_upgrade(move |sock| flood(sock, s, 256))
            }
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap()
}

/// Waits until the flooding handler stops making progress (its writes are blocked).
async fn until_stalled(s: &Stall) -> usize {
    let start = Instant::now();
    let mut last = usize::MAX;
    loop {
        tokio::time::sleep(Duration::from_millis(150)).await;
        let now = Probe::get(&s.queued);
        if now == last && now > 0 {
            return now;
        }
        last = now;
        assert!(start.elapsed() < BOUND, "the writer never stalled");
    }
}

#[tokio::test]
async fn shutdown_is_not_held_up_by_a_blocked_write() {
    let s = Stall::default();
    let server = stall_server(
        s.clone(),
        poring::Limits {
            // Far longer than the test bound: shutdown must not need it.
            shutdown_grace: Duration::from_secs(30),
            ..Default::default()
        },
    )
    .await;
    let addr = server.local_addr();
    let _raw = Raw::connect(addr, "/no-timers").await;
    let queued = until_stalled(&s).await;
    assert!(queued < 1024, "backpressure bounded the sender ({queued})");
    let start = Instant::now();
    tokio::time::timeout(BOUND, server.shutdown())
        .await
        .expect("shutdown did not wait for the blocked write")
        .unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(Probe::get(&s.dropped), 1, "handler finished or cancelled");
}

#[tokio::test]
async fn heartbeat_is_enforced_while_a_write_is_blocked() {
    let s = Stall::default();
    let server = stall_server(s.clone(), poring::Limits::default()).await;
    let addr = server.local_addr();
    let _raw = Raw::connect(addr, "/heartbeat").await;
    eventually("heartbeat timeout counted", || {
        server.ws_stats().heartbeat_timeouts == 1
    })
    .await;
    eventually("session released", || {
        server.ws_stats().active_sessions == 0
    })
    .await;
    eventually("handler ended", || Probe::get(&s.dropped) == 1).await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn idle_timeout_is_enforced_while_a_write_is_blocked() {
    let s = Stall::default();
    let server = stall_server(s.clone(), poring::Limits::default()).await;
    let addr = server.local_addr();
    let _raw = Raw::connect(addr, "/idle").await;
    eventually("idle timeout counted", || {
        server.ws_stats().idle_timeouts == 1
    })
    .await;
    eventually("session released", || {
        server.ws_stats().active_sessions == 0
    })
    .await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_client_vanishing_during_a_blocked_write_releases_the_session() {
    let s = Stall::default();
    let server = stall_server(s.clone(), poring::Limits::default()).await;
    let addr = server.local_addr();
    let raw = Raw::connect(addr, "/no-timers").await;
    until_stalled(&s).await;
    drop(raw);
    eventually("session released", || {
        server.ws_stats().active_sessions == 0
    })
    .await;
    eventually("handler ended", || Probe::get(&s.dropped) == 1).await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_reading_client_receives_every_message() {
    let s = Stall::default();
    let server = stall_server(s.clone(), poring::Limits::default()).await;
    let addr = server.local_addr();
    let mut ws = client(addr, "/burst").await;
    let mut got = 0;
    while got < 256 {
        match tokio::time::timeout(BOUND, ws.next()).await.unwrap() {
            Some(Ok(Message::Binary(b))) => {
                assert_eq!(b.len(), 64 * 1024);
                got += 1;
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            other => panic!("after {got} messages: {other:?}"),
        }
    }
    // The handler returned: the session closes normally.
    loop {
        match tokio::time::timeout(BOUND, ws.next()).await.unwrap() {
            Some(Ok(Message::Close(Some(f)))) => {
                assert_eq!(f.code, CloseCode::Normal);
                break;
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(server.ws_stats().heartbeat_timeouts, 0);
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_slow_clients_are_all_released_and_the_limit_recovers() {
    const N: usize = 16;
    let s = Stall::default();
    let server = stall_server(
        s.clone(),
        poring::Limits {
            max_ws_sessions: N,
            ..Default::default()
        },
    )
    .await;
    let addr = server.local_addr();
    let mut raws = Vec::new();
    for _ in 0..N {
        raws.push(Raw::connect(addr, "/heartbeat").await);
    }
    eventually("all started", || Probe::get(&s.started) == N).await;
    // None of them reads or answers pings: every session ends on its own.
    eventually("all heartbeats timed out", || {
        server.ws_stats().heartbeat_timeouts == N as u64
    })
    .await;
    eventually("all released", || server.ws_stats().active_sessions == 0).await;
    eventually("all handlers ended", || Probe::get(&s.dropped) == N).await;
    // Every permit came back: a full set of new sessions is admitted again.
    drop(raws);
    let mut again = Vec::new();
    for _ in 0..N {
        again.push(client(addr, "/burst").await);
    }
    drop(again);
    eventually("released again", || server.ws_stats().active_sessions == 0).await;
    server.shutdown().await.unwrap();
}

async fn write_timeout_server(s: Stall) -> poring::Server {
    let (a, b) = (s.clone(), s.clone());
    Poring::new()
        // Only the write timeout can end a stuck session here.
        .ws("/write-timeout", move |ws: WebSocketUpgrade| {
            let s = a.clone();
            async move {
                ws.managed()
                    .no_idle_timeout()
                    .no_ping()
                    .write_timeout(Duration::from_millis(300))
                    .queue_messages(4)
                    .max_queued_bytes(256 * 1024)
                    .on_upgrade(move |sock| flood(sock, s, usize::MAX))
            }
        })
        // Heartbeats and a write timeout, for a client that reads slowly but steadily.
        .ws("/slow-reader", move |ws: WebSocketUpgrade| {
            let s = b.clone();
            async move {
                ws.managed()
                    .no_idle_timeout()
                    .ping_interval(Duration::from_millis(100))
                    .pong_timeout(Duration::from_secs(2))
                    .write_timeout(Duration::from_secs(2))
                    .queue_messages(4)
                    .max_queued_bytes(256 * 1024)
                    .on_upgrade(move |sock| flood(sock, s, usize::MAX))
            }
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap()
}

#[tokio::test]
async fn a_write_that_cannot_complete_ends_the_session_at_its_deadline() {
    let s = Stall::default();
    let server = write_timeout_server(s.clone()).await;
    let addr = server.local_addr();
    let _raw = Raw::connect(addr, "/write-timeout").await;
    eventually("write timeout counted", || {
        server.ws_stats().write_timeouts == 1
    })
    .await;
    eventually("session released", || {
        server.ws_stats().active_sessions == 0
    })
    .await;
    eventually("handler ended", || Probe::get(&s.dropped) == 1).await;
    let stats = server.ws_stats();
    assert_eq!((stats.heartbeat_timeouts, stats.idle_timeouts), (0, 0));
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_slow_but_steady_reader_is_not_mistaken_for_a_dead_one() {
    let s = Stall::default();
    let server = write_timeout_server(s.clone()).await;
    let addr = server.local_addr();
    // tungstenite answers each ping when it reads it.
    let mut ws = client(addr, "/slow-reader").await;
    let until = Instant::now() + Duration::from_millis(1500);
    let mut got = 0;
    while Instant::now() < until {
        match tokio::time::timeout(BOUND, ws.next()).await.unwrap() {
            Some(Ok(Message::Binary(_))) => got += 1,
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            other => panic!("session ended after {got} messages: {other:?}"),
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(got > 10, "data kept flowing ({got})");
    let stats = server.ws_stats();
    assert_eq!(
        (
            stats.heartbeat_timeouts,
            stats.write_timeouts,
            stats.active_sessions
        ),
        (0, 0, 1)
    );
    drop(ws);
    eventually("released", || server.ws_stats().active_sessions == 0).await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_during_a_blocked_write_with_a_write_timeout_disabled() {
    // Same as `shutdown_is_not_held_up_by_a_blocked_write`, but with the client gone
    // half-way: the pending write fails and shutdown still finishes promptly.
    let s = Stall::default();
    let server = stall_server(
        s.clone(),
        poring::Limits {
            shutdown_grace: Duration::from_secs(30),
            ..Default::default()
        },
    )
    .await;
    let addr = server.local_addr();
    let raws = [
        Raw::connect(addr, "/no-timers").await,
        Raw::connect(addr, "/no-timers").await,
    ];
    eventually("both started", || Probe::get(&s.started) == 2).await;
    until_stalled(&s).await;
    let [_keep, gone] = raws;
    drop(gone);
    let start = Instant::now();
    tokio::time::timeout(BOUND, server.shutdown())
        .await
        .expect("bounded")
        .unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(Probe::get(&s.dropped), 2);
}
