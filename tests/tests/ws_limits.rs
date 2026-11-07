//! WebSocket message limits over real TCP (P5.2): per-session message rates, shared per-IP
//! and per-principal quotas, per-client session caps, frame vs message size limits and
//! control frames interleaved with fragments.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use poring::prelude::*;
use poring::ws::{ManagedSocket, WebSocketUpgrade, WsError, WsMessageQuota};
use poring_tests::secure::TableAuth;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

type Client = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

async fn connect(addr: SocketAddr, path: &str, token: Option<&str>) -> Result<Client, u16> {
    let mut req = format!("ws://{addr}{path}").into_client_request().unwrap();
    if let Some(t) = token {
        req.headers_mut()
            .insert("authorization", format!("Bearer {t}").parse().unwrap());
    }
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    match tokio_tungstenite::client_async(req, tcp).await {
        Ok((ws, _)) => Ok(ws),
        Err(tokio_tungstenite::tungstenite::Error::Http(r)) => Err(r.status().as_u16()),
        Err(e) => panic!("{e}"),
    }
}

/// Reads until a data message (returned) or a close frame (its code as `Err`).
async fn next(ws: &mut Client) -> Result<Message, Option<CloseCode>> {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
            Ok(Some(Ok(Message::Close(f)))) => return Err(f.map(|f| f.code)),
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
            Ok(Some(Ok(m))) => return Ok(m),
            Ok(Some(Err(_)) | None) => return Err(None),
            Err(_) => panic!("timed out"),
        }
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize, PoringSchema)]
struct Chat {
    text: String,
}

fn managed_echo(
    rate: Option<(u32, Duration)>,
    quota: Option<WsMessageQuota>,
) -> impl Fn(WebSocketUpgrade) -> std::future::Ready<Response> + Clone + Send + Sync + 'static {
    move |ws: WebSocketUpgrade| {
        let mut ws = ws;
        if let Some((n, per)) = rate {
            ws = ws.message_rate(n, per);
        }
        if let Some(q) = &quota {
            ws = ws.message_quota(q);
        }
        std::future::ready(
            ws.managed()
                .on_upgrade(|mut sock: ManagedSocket| async move {
                    while let Some(m) = sock.recv().await {
                        if sock.send(m).await.is_err() {
                            break;
                        }
                    }
                }),
        )
    }
}

async fn bind(app: poring::app::App<impl poring::app::AppSpec>) -> poring::Server {
    app.bind("127.0.0.1:0").await.unwrap()
}

#[tokio::test]
async fn per_session_message_rate_closes_managed_sessions_with_1008() {
    let server = bind(
        Poring::new()
            .get("/m", managed_echo(Some((5, Duration::from_secs(10))), None))
            .build()
            .unwrap(),
    )
    .await;
    let addr = server.local_addr();
    let mut ws = connect(addr, "/m", None).await.unwrap();
    for i in 0..5 {
        ws.send(Message::text(format!("{i}"))).await.unwrap();
        assert_eq!(next(&mut ws).await, Ok(Message::text(format!("{i}"))));
    }
    // Pings are not metered.
    ws.send(Message::Ping(Default::default())).await.unwrap();
    ws.send(Message::text("over")).await.unwrap();
    assert_eq!(next(&mut ws).await, Err(Some(CloseCode::Policy)));
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn message_rate_refills_over_time() {
    let server = bind(
        Poring::new()
            .get(
                "/m",
                managed_echo(Some((2, Duration::from_millis(200))), None),
            )
            .build()
            .unwrap(),
    )
    .await;
    let addr = server.local_addr();
    let mut ws = connect(addr, "/m", None).await.unwrap();
    for round in 0..3 {
        for i in 0..2 {
            let t = format!("{round}.{i}");
            ws.send(Message::text(t.clone())).await.unwrap();
            assert_eq!(next(&mut ws).await, Ok(Message::text(t)));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    drop(ws);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn typed_sessions_report_rate_limiting_once_and_close_with_1008() {
    let seen = Arc::new(AtomicUsize::new(0));
    let s = seen.clone();
    let server = bind(
        Poring::new()
            .get("/t", move |ws: WebSocketUpgrade| {
                let seen = s.clone();
                async move {
                    ws.message_rate(3, Duration::from_secs(10))
                        .typed::<Chat, Chat>()
                        .on_upgrade(move |mut sock| async move {
                            while let Some(r) = sock.recv().await {
                                match r {
                                    Ok(m) => {
                                        let _ = sock.send(&m).await;
                                    }
                                    Err(WsError::RateLimited) => {
                                        seen.fetch_add(1, Ordering::SeqCst);
                                    }
                                    Err(_) => {}
                                }
                            }
                        })
                }
            })
            .build()
            .unwrap(),
    )
    .await;
    let addr = server.local_addr();
    let mut ws = connect(addr, "/t", None).await.unwrap();
    for _ in 0..3 {
        ws.send(Message::text(r#"{"text":"hi"}"#)).await.unwrap();
        assert!(next(&mut ws).await.is_ok());
    }
    ws.send(Message::text(r#"{"text":"over"}"#)).await.unwrap();
    assert_eq!(next(&mut ws).await, Err(Some(CloseCode::Policy)));
    drop(ws);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        seen.load(Ordering::SeqCst),
        1,
        "RateLimited must be reported exactly once"
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn shared_per_ip_quota_spans_sessions() {
    let quota = WsMessageQuota::per_ip(4, Duration::from_secs(10));
    let server = bind(
        Poring::new()
            .get("/m", managed_echo(None, Some(quota)))
            .build()
            .unwrap(),
    )
    .await;
    let addr = server.local_addr();
    let mut a = connect(addr, "/m", None).await.unwrap();
    let mut b = connect(addr, "/m", None).await.unwrap();
    for i in 0..3 {
        a.send(Message::text(format!("a{i}"))).await.unwrap();
        assert!(next(&mut a).await.is_ok());
    }
    b.send(Message::text("b0")).await.unwrap();
    assert!(next(&mut b).await.is_ok());
    // The fifth message from this IP, on either session, is over the shared quota.
    b.send(Message::text("b1")).await.unwrap();
    assert_eq!(next(&mut b).await, Err(Some(CloseCode::Policy)));
    drop((a, b));
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn per_principal_quota_keeps_principals_apart() {
    let quota = WsMessageQuota::per_principal(2, Duration::from_secs(10));
    let server = bind(
        Poring::new()
            .authenticator(TableAuth::fixture())
            .route_with(
                RouteMethod::Get,
                "/m",
                Policy::new().authenticated(),
                managed_echo(None, Some(quota)),
            )
            .build()
            .unwrap(),
    )
    .await;
    let addr = server.local_addr();
    let mut alice = connect(addr, "/m", Some("reader-token")).await.unwrap();
    let mut bob = connect(addr, "/m", Some("writer-token")).await.unwrap();
    for i in 0..2 {
        alice.send(Message::text(format!("{i}"))).await.unwrap();
        assert!(next(&mut alice).await.is_ok());
        bob.send(Message::text(format!("{i}"))).await.unwrap();
        assert!(next(&mut bob).await.is_ok());
    }
    alice.send(Message::text("over")).await.unwrap();
    assert_eq!(next(&mut alice).await, Err(Some(CloseCode::Policy)));
    drop((alice, bob));
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn per_ip_and_per_principal_session_caps_return_429() {
    let server = bind(
        Poring::new()
            .limits(poring::Limits {
                max_ws_sessions_per_ip: 3,
                max_ws_sessions_per_principal: 1,
                ..Default::default()
            })
            .authenticator(TableAuth::fixture())
            .route_with(
                RouteMethod::Get,
                "/m",
                Policy::new().public(),
                managed_echo(None, None),
            )
            .route_with(
                RouteMethod::Get,
                "/auth",
                Policy::new().authenticated(),
                managed_echo(None, None),
            )
            .build()
            .unwrap(),
    )
    .await;
    let addr = server.local_addr();
    // Per principal: alice may hold one session; bob is independent.
    let alice = connect(addr, "/auth", Some("reader-token")).await.unwrap();
    assert_eq!(
        connect(addr, "/auth", Some("reader-token")).await.err(),
        Some(429)
    );
    let bob = connect(addr, "/auth", Some("writer-token")).await.unwrap();
    // Per IP: alice + bob + one anonymous = 3 sessions from 127.0.0.1; the fourth is refused.
    let mut anon = connect(addr, "/m", None).await.unwrap();
    assert_eq!(connect(addr, "/m", None).await.err(), Some(429));
    // Releasing a session frees its slot.
    anon.close(None).await.unwrap();
    while anon.next().await.is_some() {}
    let mut admitted = None;
    for _ in 0..50 {
        if let Ok(ws) = connect(addr, "/m", None).await {
            admitted = Some(ws);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(admitted.is_some(), "slot was not released");
    drop((alice, bob, admitted));
    server.shutdown().await.unwrap();
}

// ---- raw-frame tests -----------------------------------------------------------------

async fn raw(addr: SocketAddr, path: &str) -> tokio::net::TcpStream {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    );
    tcp.write_all(req.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(tcp.read_u8().await.unwrap());
    }
    assert!(head.starts_with(b"HTTP/1.1 101"));
    tcp
}

async fn frame(tcp: &mut tokio::net::TcpStream, first: u8, payload: &[u8]) {
    let mut f = vec![first];
    match payload.len() {
        n if n < 126 => f.push(0x80 | n as u8),
        n => {
            f.push(0x80 | 126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
    }
    f.extend_from_slice(&[0, 0, 0, 0]); // zero mask key: payload unchanged
    f.extend_from_slice(payload);
    tcp.write_all(&f).await.unwrap();
}

/// Reads server frames: (opcode, payload) until close (included) or EOF.
async fn frames(tcp: &mut tokio::net::TcpStream, until_data: usize) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let read = async {
        while let Ok(b0) = tcp.read_u8().await {
            let b1 = tcp.read_u8().await.unwrap();
            let len = match b1 & 0x7f {
                126 => tcp.read_u16().await.unwrap() as usize,
                127 => tcp.read_u64().await.unwrap() as usize,
                n => n as usize,
            };
            let mut p = vec![0; len];
            tcp.read_exact(&mut p).await.unwrap();
            let op = b0 & 0x0f;
            out.push((op, p));
            if op == 0x8 || out.iter().filter(|(o, _)| *o == 1 || *o == 2).count() >= until_data {
                break;
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(5), read).await;
    out
}

#[tokio::test]
async fn frame_and_message_limits_are_separate_and_pings_interleave_with_fragments() {
    let server = bind(
        Poring::new()
            .get("/m", |ws: WebSocketUpgrade| async move {
                ws.max_message_size(4096)
                    .max_frame_size(1024)
                    .managed()
                    .on_upgrade(|mut sock: ManagedSocket| async move {
                        while let Some(m) = sock.recv().await {
                            if sock.send(m).await.is_err() {
                                break;
                            }
                        }
                    })
            })
            .build()
            .unwrap(),
    )
    .await;
    let addr = server.local_addr();
    // 3 x 900-byte fragments (each under the frame limit, 2700 under the message limit)
    // with a ping between fragments: the pong comes back and the message is reassembled.
    let mut tcp = raw(addr, "/m").await;
    frame(&mut tcp, 0x02, &[1u8; 900]).await;
    frame(&mut tcp, 0x89, b"mid").await;
    frame(&mut tcp, 0x00, &[2u8; 900]).await;
    frame(&mut tcp, 0x80, &[3u8; 900]).await;
    let got = frames(&mut tcp, 1).await;
    assert!(got.contains(&(0xA, b"mid".to_vec())), "no pong: {got:?}");
    let data: Vec<_> = got.iter().filter(|(o, _)| *o == 2).collect();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0].1.len(), 2700);
    assert!(data[0].1[..900].iter().all(|&b| b == 1) && data[0].1[1800..].iter().all(|&b| b == 3));
    drop(tcp);
    // A single 2000-byte frame exceeds the frame limit although it fits the message limit.
    let mut tcp = raw(addr, "/m").await;
    frame(&mut tcp, 0x82, &[0u8; 2000]).await;
    let got = frames(&mut tcp, 1).await;
    let close = got.iter().find(|(o, _)| *o == 8).expect("no close frame");
    assert_eq!(u16::from_be_bytes([close.1[0], close.1[1]]), 1009);
    drop(tcp);
    server.shutdown().await.unwrap();
}
