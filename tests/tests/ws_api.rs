//! WebSocket developer API and observability over real TCP (P5.3, P5.4): fluent `ws()`
//! registration, handshake metadata, typed managed sockets, `ManagedSocket::split`, and
//! `WsStats` counters.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use poring::prelude::*;
use poring::ws::{ManagedSocket, ManagedTypedSocket, WebSocketUpgrade, WsError, WsStats};
use poring_tests::secure::TableAuth;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

type Client = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

async fn connect(
    addr: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<(Client, http::HeaderMap), u16> {
    let mut req = format!("ws://{addr}{path}").into_client_request().unwrap();
    for (k, v) in headers {
        req.headers_mut().insert(
            http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            v.parse().unwrap(),
        );
    }
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    match tokio_tungstenite::client_async(req, tcp).await {
        Ok((ws, resp)) => Ok((ws, resp.headers().clone())),
        Err(tokio_tungstenite::tungstenite::Error::Http(r)) => Err(r.status().as_u16()),
        Err(e) => panic!("{e}"),
    }
}

async fn next_data(ws: &mut Client) -> Option<Message> {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => return None,
            Ok(Some(Ok(m))) => return Some(m),
            Err(_) => panic!("timed out"),
        }
    }
}

async fn finish(mut ws: Client) {
    let _ = ws.close(None).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(Ok(_)) = ws.next().await {}
    })
    .await;
}

async fn wait_stats(server: &poring::Server, f: impl Fn(&WsStats) -> bool) -> WsStats {
    for _ in 0..300 {
        let s = server.ws_stats();
        if f(&s) {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    server.ws_stats()
}

#[derive(Debug, serde::Deserialize, serde::Serialize, PoringSchema)]
struct Chat {
    #[poring(min_length = 1)]
    text: String,
}

#[tokio::test]
async fn fluent_ws_routes_work_and_expose_handshake_metadata() {
    #[derive(Debug, Default, Clone)]
    struct Seen {
        subject: Option<String>,
        request_id: String,
        route_id: String,
        peer: bool,
        client_ip: Option<std::net::IpAddr>,
        http2: bool,
    }
    let seen = Arc::new(Mutex::new(Seen::default()));
    let s = seen.clone();
    let server = Poring::new()
        .authenticator(TableAuth::fixture())
        .ws("/meta", move |ws: WebSocketUpgrade| {
            let seen = s.clone();
            async move {
                *seen.lock().unwrap() = Seen {
                    subject: ws.identity().map(|i| i.subject.clone()),
                    request_id: ws.request_id().to_string(),
                    route_id: ws.route_id().to_owned(),
                    peer: ws.peer().is_some(),
                    client_ip: ws.client_ip(),
                    http2: ws.is_http2(),
                };
                ws.on_upgrade(|mut sock| async move {
                    while let Some(Ok(m)) = sock.next().await {
                        if m.is_close() || sock.send(m).await.is_err() {
                            break;
                        }
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
    let (mut ws, headers) = connect(addr, "/meta", &[("authorization", "Bearer reader-token")])
        .await
        .unwrap();
    ws.send(Message::text("hi")).await.unwrap();
    assert_eq!(next_data(&mut ws).await, Some(Message::text("hi")));
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.subject.as_deref(), Some("alice"));
    assert_eq!(
        Some(seen.request_id.as_str()),
        headers.get("x-request-id").and_then(|v| v.to_str().ok()),
        "request id must match the handshake response header"
    );
    assert!(!seen.route_id.is_empty());
    assert!(seen.peer);
    assert_eq!(seen.client_ip, Some("127.0.0.1".parse().unwrap()));
    assert!(!seen.http2);
    finish(ws).await;
    server.shutdown().await.unwrap();
}

#[test]
#[should_panic(expected = "must take a `WebSocketUpgrade` extractor")]
fn fluent_ws_rejects_handlers_without_an_upgrade_extractor() {
    let _ = Poring::new().ws("/nope", || async { "not a websocket" });
}

#[tokio::test]
async fn managed_typed_sockets_decode_validate_and_keep_going() {
    let server = Poring::new()
        .ws("/t", |ws: WebSocketUpgrade| async move {
            ws.managed().typed::<Chat, Chat>().on_upgrade(
                |mut sock: ManagedTypedSocket<Chat, Chat>| async move {
                    while let Some(r) = sock.recv().await {
                        let reply = match r {
                            Ok(m) => m,
                            Err(WsError::Invalid(_)) => Chat {
                                text: "invalid".into(),
                            },
                            Err(WsError::Decode(_)) => Chat {
                                text: "malformed".into(),
                            },
                            Err(_) => break,
                        };
                        if sock.send(&reply).await.is_err() {
                            break;
                        }
                    }
                },
            )
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    let (mut ws, _) = connect(addr, "/t", &[]).await.unwrap();
    for (input, want) in [
        (r#"{"text":"hello"}"#, r#"{"text":"hello"}"#),
        (r#"{"text":""}"#, r#"{"text":"invalid"}"#),
        ("not json", r#"{"text":"malformed"}"#),
        (r#"{"text":"still alive"}"#, r#"{"text":"still alive"}"#),
    ] {
        ws.send(Message::text(input)).await.unwrap();
        assert_eq!(
            next_data(&mut ws).await,
            Some(Message::text(want)),
            "{input}"
        );
    }
    finish(ws).await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn split_managed_sockets_allow_concurrent_senders() {
    let server = Poring::new()
        .ws("/s", |ws: WebSocketUpgrade| async move {
            ws.managed().on_upgrade(|sock: ManagedSocket| async move {
                let (mut rx, tx) = sock.split();
                // Two writer tasks run concurrently with the reader (inside the session
                // future; nothing is detached).
                let writer = |name: &'static str, tx: poring::ws::ManagedSender| async move {
                    for i in 0..20 {
                        if tx.send(Message::text(format!("{name}{i}"))).await.is_err() {
                            return;
                        }
                    }
                };
                let echo = async {
                    while let Some(m) = rx.recv().await {
                        if tx.send(m).await.is_err() {
                            break;
                        }
                    }
                };
                tokio::join!(writer("a", tx.clone()), writer("b", tx.clone()), echo);
            })
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    let (mut ws, _) = connect(addr, "/s", &[]).await.unwrap();
    ws.send(Message::text("ping-through")).await.unwrap();
    let mut got = Vec::new();
    while got.len() < 41 {
        match next_data(&mut ws).await {
            Some(Message::Text(t)) => got.push(t.to_string()),
            other => panic!("{other:?} after {} messages", got.len()),
        }
    }
    for name in ["a", "b"] {
        let mine: Vec<_> = got
            .iter()
            .filter(|m| m.starts_with(name))
            .cloned()
            .collect();
        let want: Vec<_> = (0..20).map(|i| format!("{name}{i}")).collect();
        assert_eq!(mine, want, "per-sender order must be preserved");
    }
    assert!(got.contains(&"ping-through".to_string()));
    finish(ws).await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn ws_stats_count_handshakes_sessions_messages_and_failures() {
    let server = Poring::new()
        .limits(poring::Limits {
            max_ws_sessions: 2,
            ..Default::default()
        })
        .authenticator(TableAuth::fixture())
        .cors(Cors::new().origins(["https://app.example"]))
        .route_with(
            RouteMethod::Get,
            "/echo",
            Policy::new().public(),
            |ws: WebSocketUpgrade| async move {
                ws.message_rate(3, Duration::from_secs(60))
                    .managed()
                    .on_upgrade(|mut sock: ManagedSocket| async move {
                        while let Some(m) = sock.recv().await {
                            if sock.send(m).await.is_err() {
                                break;
                            }
                        }
                    })
            },
        )
        .route_with(
            RouteMethod::Get,
            "/private",
            Policy::new().authenticated(),
            |ws: WebSocketUpgrade| async move { ws.on_upgrade(|_sock| async {}) },
        )
        .route_with(
            RouteMethod::Get,
            "/panic",
            Policy::new().public(),
            |ws: WebSocketUpgrade| async move {
                ws.on_upgrade(|_sock| async { panic!("handler panic (expected by test)") })
            },
        )
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    assert_eq!(server.ws_stats(), WsStats::default());

    // Two sessions exchange 2 messages each ("hello" = 5 bytes).
    let (mut a, _) = connect(addr, "/echo", &[]).await.unwrap();
    let (mut b, _) = connect(addr, "/echo", &[]).await.unwrap();
    for ws in [&mut a, &mut b] {
        for _ in 0..2 {
            ws.send(Message::text("hello")).await.unwrap();
            assert!(next_data(ws).await.is_some());
        }
    }
    let s = wait_stats(&server, |s| s.active_sessions == 2).await;
    assert_eq!(s.handshakes_accepted, 2);
    // Session limit (2) reached.
    assert_eq!(connect(addr, "/echo", &[]).await.err(), Some(503));
    // Origin and auth denials.
    assert_eq!(
        connect(addr, "/echo", &[("origin", "https://evil.example")])
            .await
            .err(),
        Some(403)
    );
    assert_eq!(connect(addr, "/private", &[]).await.err(), Some(401));
    // `a` exceeds its message rate (3): 1008.
    a.send(Message::text("hello")).await.unwrap();
    assert!(next_data(&mut a).await.is_some());
    a.send(Message::text("hello")).await.unwrap();
    assert_eq!(next_data(&mut a).await, None);
    // `b` sends invalid UTF-8: 1007.
    finish(a).await;
    drop(b);
    let s = wait_stats(&server, |s| s.active_sessions == 0).await;
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.write_all(
        format!(
            "GET /echo HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    tcp.write_all(&[0x81, 0x82, 0, 0, 0, 0, 0xc3, 0x28])
        .await
        .unwrap();
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut sink)).await;
    assert!(s.sessions_ended >= 2);
    // A panicking handler is counted once the supervisor reaps it (on a later spawn).
    let _ = connect(addr, "/panic", &[]).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (c, _) = connect(addr, "/echo", &[]).await.unwrap();
    finish(c).await;

    let s = wait_stats(&server, |s| {
        s.active_sessions == 0 && s.protocol_failures == 1
    })
    .await;
    eprintln!("{s:#?}");
    assert_eq!(s.handshakes_accepted, 5, "a, b, utf-8 session, panic, c");
    assert_eq!(s.rejected_session_limit, 1);
    assert_eq!(s.origin_denied, 1);
    assert_eq!(s.auth_denied, 1);
    assert_eq!(s.rate_limited, 1);
    assert_eq!(s.protocol_failures, 1);
    assert_eq!(
        s.abnormal_disconnects, 1,
        "`b` was dropped without a close frame"
    );
    assert_eq!(s.sessions_panicked, 1);
    assert_eq!(s.active_sessions, 0);
    assert_eq!(s.sessions_ended, 5);
    // a: 3 admitted + 1 refused received; b: 2. Sent: a 3, b 2. Plus the 2-byte invalid
    // frame (counted as received bytes? no: it fails decoding before delivery).
    assert_eq!(s.messages_received, 6);
    assert_eq!(s.messages_sent, 5);
    assert_eq!(s.bytes_received, 30);
    assert_eq!(s.bytes_sent, 25);
    let _ = CloseCode::Normal;
    server.shutdown().await.unwrap();
}
