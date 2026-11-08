//! Production-hardening regressions for WebSocket sessions over real TCP:
//!
//! * inbound stall: a managed handler that stops taking messages can no longer hold its
//!   session, connection and per-client slots indefinitely (`stall_timeout`, `1013`).
//! * origin scheme: `http://` origins are refused for endpoints known to be HTTPS (a
//!   trusted proxy's `X-Forwarded-Proto`) and everywhere with `WsOrigins::https_only`.
//!   The native-TLS case lives in `tls.rs`.
//! * typed `recv`: a terminal transport error is reported exactly once, then `None`.
//! * metrics: message counts are published while sessions run. Queue pressure and close
//!   reasons are counted.
//!
//! Every wait is bounded.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use poring::policy::WsOrigins;
use poring::prelude::*;
use poring::ws::{ManagedSocket, TypedSocket, WebSocketUpgrade, WsError};
use poring_tests::status_of;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const BOUND: Duration = Duration::from_secs(10);

fn ws_req(addr: SocketAddr, path: &str, extra: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {KEY}\r\n{extra}\r\n"
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

async fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
    let start = Instant::now();
    while !cond() {
        assert!(start.elapsed() < BOUND, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The close code the peer sent, reading (and discarding) data until it arrives.
async fn close_code(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
) -> Option<CloseCode> {
    tokio::time::timeout(BOUND, async {
        while let Some(m) = ws.next().await {
            match m {
                Ok(Message::Close(f)) => return f.map(|f| f.code),
                Ok(_) => {}
                Err(_) => return None,
            }
        }
        None
    })
    .await
    .expect("no close frame in time")
}

// ---------------------------------------------------------------------------------------
// inbound stall deadline

#[derive(Clone, Default)]
struct Probe {
    started: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
}

struct DropGuard(Arc<AtomicUsize>);

impl Drop for DropGuard {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// `/stall` takes one message and then never reads again (it keeps the socket, like a
/// handler stuck on a slow downstream call). `/off` is the same with the deadline disabled.
/// `/sender` drops its receiver and only sends. `/slow` reads, slowly but within the
/// deadline.
async fn stall_server(probe: Probe, limits: poring::Limits) -> poring::Server {
    let stall = probe.clone();
    let off = probe.clone();
    Poring::new()
        .limits(limits)
        .ws("/stall", move |ws: WebSocketUpgrade| {
            let p = stall.clone();
            async move {
                ws.managed()
                    .queue_messages(2)
                    .stall_timeout(Duration::from_millis(300))
                    .close_timeout(Duration::from_millis(300))
                    .on_upgrade(move |mut sock: ManagedSocket| async move {
                        p.started.fetch_add(1, Ordering::SeqCst);
                        let _guard = DropGuard(p.dropped.clone());
                        let _first = sock.recv().await;
                        std::future::pending::<()>().await;
                    })
            }
        })
        .ws("/off", move |ws: WebSocketUpgrade| {
            let p = off.clone();
            async move {
                ws.managed()
                    .queue_messages(2)
                    .no_stall_timeout()
                    .on_upgrade(move |sock: ManagedSocket| async move {
                        p.started.fetch_add(1, Ordering::SeqCst);
                        let _guard = DropGuard(p.dropped.clone());
                        let _sock = sock;
                        std::future::pending::<()>().await;
                    })
            }
        })
        .ws("/sender", |ws: WebSocketUpgrade| async move {
            ws.managed()
                .queue_messages(1)
                .stall_timeout(Duration::from_millis(200))
                .on_upgrade(|sock: ManagedSocket| async move {
                    let (rx, tx) = sock.split();
                    drop(rx);
                    for i in 0..20 {
                        if tx.send(Message::text(format!("tick {i}"))).await.is_err() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                })
        })
        .ws("/slow", |ws: WebSocketUpgrade| async move {
            ws.managed()
                .queue_messages(1)
                .stall_timeout(Duration::from_millis(500))
                .on_upgrade(|mut sock: ManagedSocket| async move {
                    while let Some(m) = sock.recv().await {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        if sock.send(m).await.is_err() {
                            break;
                        }
                    }
                })
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap()
}

#[tokio::test]
async fn a_stalled_receiver_is_closed_and_releases_every_slot() {
    let probe = Probe::default();
    let server = stall_server(
        probe.clone(),
        poring::Limits {
            max_ws_sessions: 1,
            max_ws_sessions_per_ip: 1,
            ..Default::default()
        },
    )
    .await;
    let addr = server.local_addr();
    let mut ws = client(addr, "/stall").await;
    // More messages than the handler queue (2) plus the pump's one pending message.
    for i in 0..8 {
        ws.send(Message::text(format!("m{i}"))).await.unwrap();
    }
    let started = Instant::now();
    assert_eq!(close_code(&mut ws).await, Some(CloseCode::Again));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "stall deadline took {:?}",
        started.elapsed()
    );
    // The handler was cancelled after close_timeout and every slot came back.
    eventually("handler dropped", || {
        probe.dropped.load(Ordering::SeqCst) == 1
    })
    .await;
    eventually("session released", || {
        server.ws_stats().active_sessions == 0
    })
    .await;
    let stats = server.ws_stats();
    assert_eq!(stats.inbound_stalls, 1, "{stats:?}");
    assert!(stats.inbound_backpressure >= 1, "{stats:?}");
    // The session cap (1) and per-IP cap (1) admit a new client at once.
    let again = head(addr, ws_req(addr, "/slow", "")).await;
    assert_eq!(status_of(&again), 101, "{again}");
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn disabling_the_stall_deadline_keeps_the_old_behaviour() {
    let probe = Probe::default();
    let server = stall_server(
        probe.clone(),
        poring::Limits {
            shutdown_grace: Duration::from_millis(300),
            ..Default::default()
        },
    )
    .await;
    let addr = server.local_addr();
    let mut ws = client(addr, "/off").await;
    for i in 0..8 {
        ws.send(Message::text(format!("m{i}"))).await.unwrap();
    }
    // Well past the 300 ms deadline of `/stall`: still open, nothing counted.
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(server.ws_stats().active_sessions, 1);
    assert_eq!(server.ws_stats().inbound_stalls, 0);
    // Only shutdown (or lifetime, or a failed heartbeat write) ends it now.
    drop(ws);
    server.shutdown().await.unwrap();
    assert_eq!(probe.dropped.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_send_only_handler_never_stalls() {
    let server = stall_server(Probe::default(), poring::Limits::default()).await;
    let mut ws = client(server.local_addr(), "/sender").await;
    let mut got = 0;
    // The client keeps sending while it reads. The dropped receiver discards them.
    let deadline = Instant::now() + BOUND;
    while got < 20 && Instant::now() < deadline {
        ws.send(Message::text("ignored")).await.unwrap();
        match tokio::time::timeout(Duration::from_secs(2), ws.next()).await {
            Ok(Some(Ok(Message::Text(_)))) => got += 1,
            Ok(Some(Ok(Message::Close(f)))) => panic!("closed early: {f:?}"),
            other => panic!("unexpected: {other:?}"),
        }
    }
    assert_eq!(got, 20);
    assert_eq!(server.ws_stats().inbound_stalls, 0);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_slow_but_reading_handler_is_not_closed() {
    let server = stall_server(Probe::default(), poring::Limits::default()).await;
    let mut ws = client(server.local_addr(), "/slow").await;
    for i in 0..10 {
        ws.send(Message::text(format!("m{i}"))).await.unwrap();
    }
    for i in 0..10 {
        let m = tokio::time::timeout(BOUND, ws.next()).await.unwrap();
        assert_eq!(m.unwrap().unwrap(), Message::text(format!("m{i}")));
    }
    assert_eq!(server.ws_stats().inbound_stalls, 0);
    ws.close(None).await.unwrap();
    server.shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------------------
// origin scheme (plain listener, native TLS is covered in tls.rs)

async fn origin_server(origins: WsOrigins) -> poring::Server {
    Poring::new()
        .trusted_proxies(["127.0.0.1"])
        .ws_origins(origins)
        .ws("/ws", |ws: WebSocketUpgrade| async move {
            ws.on_upgrade(|mut sock| async move {
                let _ = sock.close(None).await;
            })
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap()
}

#[tokio::test]
async fn a_trusted_proxy_reporting_https_makes_http_origins_cross_origin() {
    let server = origin_server(WsOrigins::new()).await;
    let addr = server.local_addr();
    let host = "app.example";
    let req = |origin: &str, proto: &str| {
        format!(
            "GET /ws HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {KEY}\r\nOrigin: {origin}\r\n\
             X-Forwarded-Proto: {proto}\r\n\r\n"
        )
    };
    // The test client connects from 127.0.0.1, which is a trusted proxy here.
    let cases = [
        ("https://app.example", "https", 101),
        // The regression: same host, but a plain-HTTP page for an HTTPS endpoint.
        ("http://app.example", "https", 403),
        ("http://app.example:443", "https", 403),
        ("http://app.example", "http", 101),
        ("https://app.example", "http", 403),
    ];
    for (origin, proto, want) in cases {
        let h = head(addr, req(origin, proto)).await;
        assert_eq!(status_of(&h), want, "{origin} via {proto}: {h}");
    }
    assert_eq!(server.ws_stats().origin_denied, 3);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn https_only_refuses_plain_http_origins_everywhere() {
    let strict = origin_server(WsOrigins::new().https_only()).await;
    let addr = strict.local_addr();
    let same_http = format!("Origin: http://{addr}\r\n");
    assert_eq!(
        status_of(&head(addr, ws_req(addr, "/ws", &same_http)).await),
        403
    );
    let same_https = format!("Origin: https://{addr}\r\n");
    assert_eq!(
        status_of(&head(addr, ws_req(addr, "/ws", &same_https)).await),
        101
    );
    // Non-browser clients (no Origin) are unaffected.
    assert_eq!(status_of(&head(addr, ws_req(addr, "/ws", "")).await), 101);
    strict.shutdown().await.unwrap();

    // Without it, a plain listener with no scheme report keeps accepting same-host http
    // origins (development servers, plain-HTTP deployments).
    let lax = origin_server(WsOrigins::new()).await;
    let addr = lax.local_addr();
    let same_http = format!("Origin: http://{addr}\r\n");
    assert_eq!(
        status_of(&head(addr, ws_req(addr, "/ws", &same_http)).await),
        101
    );
    lax.shutdown().await.unwrap();
}

#[test]
fn https_only_configuration_errors_are_reported_by_build() {
    let Err(err) = Poring::new()
        .ws_origins(WsOrigins::new().https_only().allow(["http://a.example"]))
        .build()
    else {
        panic!("http allow entry with https_only must fail");
    };
    assert!(err.to_string().contains("https_only"), "{err}");
    assert!(
        Poring::new()
            .ws_origins(WsOrigins::any().https_only())
            .build()
            .is_err()
    );
}

// ---------------------------------------------------------------------------------------
// typed recv reports a terminal transport error once

#[derive(Debug, Deserialize, Serialize, PoringSchema)]
struct Ping {
    n: u32,
}

#[derive(Clone, Default)]
struct Calls {
    errors: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
    ended: Arc<AtomicUsize>,
}

async fn typed_server(calls: Calls) -> poring::Server {
    Poring::new()
        .ws("/typed", move |ws: WebSocketUpgrade| {
            let c = calls.clone();
            async move {
                ws.typed::<Ping, Ping>().on_upgrade(
                    move |mut sock: TypedSocket<Ping, Ping>| async move {
                        // A handler that skips errors, as many do.
                        loop {
                            c.calls.fetch_add(1, Ordering::SeqCst);
                            match sock.recv().await {
                                Some(Ok(p)) => {
                                    let _ = sock.send(&p).await;
                                }
                                Some(Err(WsError::Socket(_))) => {
                                    c.errors.fetch_add(1, Ordering::SeqCst);
                                }
                                Some(Err(_)) => {}
                                None => break,
                            }
                            if c.calls.load(Ordering::SeqCst) > 1_000 {
                                break;
                            }
                        }
                        c.ended.fetch_add(1, Ordering::SeqCst);
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

#[tokio::test]
async fn typed_recv_reports_an_abrupt_disconnect_once_then_ends() {
    let calls = Calls::default();
    let server = typed_server(calls.clone()).await;
    let addr = server.local_addr();
    // Raw handshake, one valid message, then the TCP connection ends with no close frame.
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(ws_req(addr, "/typed", "").as_bytes())
        .await
        .unwrap();
    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(BOUND, s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status_of(&String::from_utf8_lossy(&buf[..n])), 101);
    // Masked text frame {"n":1}.
    let payload = br#"{"n":1}"#;
    let mask = [1u8, 2, 3, 4];
    let mut f = vec![0x81, 0x80 | payload.len() as u8];
    f.extend_from_slice(&mask);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    s.write_all(&f).await.unwrap();
    let _ = tokio::time::timeout(BOUND, s.read(&mut buf)).await;
    // Reset (SO_LINGER 0) without a close frame: the server's next read fails with an
    // I/O error, which the stream must report once and then end.
    #[allow(deprecated)]
    s.set_linger(Some(Duration::ZERO)).unwrap();
    drop(s);
    eventually("handler ended", || calls.ended.load(Ordering::SeqCst) == 1).await;
    let errors = calls.errors.load(Ordering::SeqCst);
    assert!(errors <= 1, "terminal error reported {errors} times");
    // One message, at most one error, then `None`: three calls at most.
    assert!(
        calls.calls.load(Ordering::SeqCst) <= 3,
        "recv called {} times",
        calls.calls.load(Ordering::SeqCst)
    );
    let stats = server.ws_stats();
    assert!(stats.abnormal_disconnects <= 1, "{stats:?}");
    server.shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------------------
// timely metrics, queue pressure and close reasons

async fn echo_server() -> poring::Server {
    Poring::new()
        .ws("/echo", |ws: WebSocketUpgrade| async move {
            ws.managed()
                .on_upgrade(|mut sock: ManagedSocket| async move {
                    while let Some(m) = sock.recv().await {
                        if sock.send(m).await.is_err() {
                            break;
                        }
                    }
                })
        })
        .ws("/burst", |ws: WebSocketUpgrade| async move {
            ws.managed()
                .queue_messages(1)
                .max_queued_bytes(64 * 1024)
                .on_upgrade(|mut sock: ManagedSocket| async move {
                    for _ in 0..64 {
                        if sock
                            .send(Message::binary(vec![7u8; 60 * 1024]))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    let _ = sock.recv().await;
                })
        })
        .ws("/goodbye", |ws: WebSocketUpgrade| async move {
            ws.managed().on_upgrade(|sock: ManagedSocket| async move {
                sock.close(None).await;
            })
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap()
}

#[tokio::test]
async fn message_counts_are_published_while_the_session_runs() {
    let server = echo_server().await;
    let mut ws = client(server.local_addr(), "/echo").await;
    for i in 0..70 {
        ws.send(Message::text(format!("m{i}"))).await.unwrap();
        ws.next().await.unwrap().unwrap();
    }
    // The session is still open: at least one batch (64 messages) has been published.
    eventually("batch published", || {
        let s = server.ws_stats();
        s.active_sessions == 1 && s.messages_received >= 32 && s.messages_sent >= 32
    })
    .await;
    // After a quiet second, the next message publishes the rest promptly.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    ws.send(Message::text("late")).await.unwrap();
    ws.next().await.unwrap().unwrap();
    // The late inbound message was published with everything before it. Its echo is
    // published at the next batch, interval or session end.
    eventually("late message published", || {
        let s = server.ws_stats();
        s.messages_received == 71 && s.messages_sent >= 70
    })
    .await;
    assert_eq!(server.ws_stats().active_sessions, 1);
    ws.close(None).await.unwrap();
    eventually("peer close counted", || server.ws_stats().peer_closes == 1).await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn outbound_pressure_and_server_closes_are_counted() {
    let server = echo_server().await;
    let addr = server.local_addr();
    let mut ws = client(addr, "/burst").await;
    let mut got = 0;
    while got < 64 {
        match tokio::time::timeout(BOUND, ws.next()).await.unwrap() {
            Some(Ok(Message::Binary(b))) => {
                assert_eq!(b.len(), 60 * 1024);
                got += 1;
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
    assert!(
        server.ws_stats().outbound_backpressure >= 1,
        "{:?}",
        server.ws_stats()
    );
    ws.close(None).await.unwrap();

    let mut bye = client(addr, "/goodbye").await;
    assert_eq!(close_code(&mut bye).await, Some(CloseCode::Normal));
    eventually("server close counted", || {
        server.ws_stats().server_closes >= 1
    })
    .await;
    server.shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------------------
// quiet sessions publish their counts on a timer, not only on activity

/// Typed and managed (`no_ping`) handlers that receive messages and then wait: the counts
/// must reach `ws_stats()` while the session is still open and silent, within about a
/// second, without any further traffic.
#[tokio::test]
async fn quiet_typed_and_managed_sessions_publish_counts_on_a_timer() {
    let server = Poring::new()
        .ws("/typed", |ws: WebSocketUpgrade| async move {
            ws.typed::<Ping, Ping>()
                .on_upgrade(|mut sock: TypedSocket<Ping, Ping>| async move {
                    while let Some(Ok(_)) = sock.recv().await {}
                })
        })
        .ws("/managed", |ws: WebSocketUpgrade| async move {
            ws.managed()
                .no_ping()
                .on_upgrade(|mut sock: ManagedSocket| async move {
                    while sock.recv().await.is_some() {}
                })
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    let mut typed = client(addr, "/typed").await;
    let mut managed = client(addr, "/managed").await;
    for n in 0..3 {
        typed
            .send(Message::text(format!(r#"{{"n":{n}}}"#)))
            .await
            .unwrap();
        managed.send(Message::text("x")).await.unwrap();
    }
    // Far fewer than a batch: only the timer can publish these while both stay silent.
    let sent_at = Instant::now();
    eventually("quiet sessions published", || {
        let s = server.ws_stats();
        s.messages_received == 6 && s.bytes_received == 3 * 7 + 3
    })
    .await;
    let lag = sent_at.elapsed();
    assert!(lag < Duration::from_millis(2500), "published after {lag:?}");
    let s = server.ws_stats();
    assert_eq!(s.active_sessions, 2, "{s:?}");
    assert_eq!(s.sessions_ended, 0, "{s:?}");
    typed.close(None).await.unwrap();
    managed.close(None).await.unwrap();
    eventually("sessions ended", || server.ws_stats().active_sessions == 0).await;
    server.shutdown().await.unwrap();
}

// ---------------------------------------------------------------------------------------
// endpoint-level production profile and configuration checks

/// `production()` presets apply bounded settings that are enforced end to end, and the
/// warning checks flag every unbounded setting of the defaults.
#[tokio::test]
async fn production_presets_are_enforced_and_defaults_are_flagged() {
    let warnings = Arc::new(std::sync::Mutex::new(Vec::<(String, Vec<String>)>::new()));
    let (w1, w2) = (warnings.clone(), warnings.clone());
    let server = Poring::new()
        .limits(poring::Limits::production())
        .ws("/prod", move |ws: WebSocketUpgrade| {
            let w = w1.clone();
            async move {
                let up = ws.production().managed().production();
                w.lock()
                    .unwrap()
                    .push(("prod".into(), up.production_warnings()));
                up.on_upgrade(|mut sock: ManagedSocket| async move {
                    while let Some(m) = sock.recv().await {
                        if sock.send(m).await.is_err() {
                            break;
                        }
                    }
                })
            }
        })
        .ws("/default", move |ws: WebSocketUpgrade| {
            let w = w2.clone();
            async move {
                let up = ws.managed().no_ping().no_idle_timeout().no_stall_timeout();
                w.lock()
                    .unwrap()
                    .push(("default".into(), up.production_warnings()));
                up.on_upgrade(|_sock: ManagedSocket| async move {})
            }
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    // 64 KiB inbound cap: a 70 KiB message fails the session with 1009 (Message Too Big).
    let mut ws = client(addr, "/prod").await;
    ws.send(Message::text("ok")).await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap(), Message::text("ok"));
    ws.send(Message::binary(vec![0u8; 70 * 1024]))
        .await
        .unwrap();
    assert_eq!(close_code(&mut ws).await, Some(CloseCode::Size));
    // 50 msg/s per session: a burst of 200 is closed with 1008 (Policy).
    let mut ws = client(addr, "/prod").await;
    for _ in 0..200 {
        if ws.send(Message::text("x")).await.is_err() {
            break;
        }
    }
    assert_eq!(close_code(&mut ws).await, Some(CloseCode::Policy));
    eventually("rate limit counted", || server.ws_stats().rate_limited >= 1).await;
    let mut d = client(addr, "/default").await;
    let _ = close_code(&mut d).await;
    let got = warnings.lock().unwrap().clone();
    let prod: Vec<_> = got.iter().filter(|(k, _)| k == "prod").collect();
    let default: Vec<_> = got.iter().filter(|(k, _)| k == "default").collect();
    assert!(prod.iter().all(|(_, w)| w.is_empty()), "{prod:?}");
    let dw = &default[0].1;
    for needle in [
        "message_rate",
        "max_lifetime",
        "dead peers",
        "stall_timeout",
        "max_queued_bytes",
        "max_outbound_message",
    ] {
        assert!(
            dw.iter().any(|w| w.contains(needle)),
            "missing {needle}: {dw:?}"
        );
    }
    assert!(
        poring::Limits::production()
            .production_warnings()
            .is_empty()
    );
    assert_eq!(poring::Limits::default().production_warnings().len(), 2);
    server.shutdown().await.unwrap();
}
