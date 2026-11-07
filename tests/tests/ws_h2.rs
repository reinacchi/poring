//! RFC 8441 WebSockets over HTTP/2 (Phase 4).
//!
//! The client is hyper's HTTP/2 client over cleartext TCP (h2c with prior knowledge): it
//! sends a real Extended CONNECT request (`:method CONNECT`, `:protocol websocket`,
//! `:scheme`, `:authority`, `:path`) on an HTTP/2 stream, and WebSocket frames then flow on
//! that stream (tokio-tungstenite in client role over hyper's upgraded stream). No HTTP/1.1
//! `Upgrade` and no `Sec-WebSocket-Key` are involved.
//!
//! Run with `cargo test -p poring-tests --no-default-features --features websocket,http2 --test ws_h2`.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use poring::prelude::*;
use poring::ws::{ManagedSocket, WebSocketUpgrade};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::Role;

async fn server() -> poring::Server {
    Poring::new()
        .get("/echo", |ws: WebSocketUpgrade| async move {
            ws.managed()
                .on_upgrade(|mut sock: ManagedSocket| async move {
                    while let Some(m) = sock.recv().await {
                        if sock.send(m).await.is_err() {
                            break;
                        }
                    }
                })
        })
        .get("/plain", || async { "plain" })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap()
}

/// Opens an HTTP/2 connection (prior knowledge) and returns its request handle.
async fn h2(addr: SocketAddr) -> SendRequest<Empty<Bytes>> {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (send, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
            .await
            .unwrap();
    // Ends when the connection closes; owned by the test runtime.
    tokio::spawn(async move {
        let _ = conn.await;
    });
    send
}

/// A plain GET on the connection; also guarantees the server's SETTINGS were processed.
async fn get(send: &mut SendRequest<Empty<Bytes>>, addr: SocketAddr, path: &str) -> (u16, String) {
    send.ready().await.unwrap();
    let req = http::Request::get(format!("http://{addr}{path}"))
        .body(Empty::new())
        .unwrap();
    let res = send.send_request(req).await.unwrap();
    let status = res.status().as_u16();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn extended_connect(addr: SocketAddr, path: &str) -> http::Request<Empty<Bytes>> {
    let mut req = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!("http://{addr}{path}"))
        .header("sec-websocket-version", "13")
        .body(Empty::new())
        .unwrap();
    req.extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));
    req
}

#[tokio::test]
async fn server_advertises_extended_connect_on_http2() {
    let server = server().await;
    let addr = server.local_addr();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut send, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
            .await
            .unwrap();
    let mut conn = std::pin::pin!(conn);
    // Drive the connection inline until a request completes (so the server's SETTINGS have
    // been processed), then ask the connection what the server advertised.
    let res = tokio::select! {
        r = conn.as_mut() => panic!("connection ended early: {r:?}"),
        res = get(&mut send, addr, "/plain") => res,
    };
    assert_eq!(res, (200, "plain".into()));
    assert!(
        conn.is_extended_connect_protocol_enabled(),
        "server did not send SETTINGS_ENABLE_CONNECT_PROTOCOL = 1"
    );
    drop(send);
    let _ = tokio::time::timeout(Duration::from_secs(2), conn).await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn websocket_over_an_http2_stream_echoes_and_closes() {
    let server = server().await;
    let addr = server.local_addr();
    let mut send = h2(addr).await;
    assert_eq!(get(&mut send, addr, "/plain").await.0, 200);
    send.ready().await.unwrap();
    let mut res = tokio::time::timeout(
        Duration::from_secs(5),
        send.send_request(extended_connect(addr, "/echo")),
    )
    .await
    .expect("no response")
    .expect("Extended CONNECT request failed");
    assert_eq!(res.status(), 200, "{res:?}");
    for h in ["sec-websocket-accept", "upgrade", "connection"] {
        assert!(
            res.headers().get(h).is_none(),
            "HTTP/1.1-only header {h} on HTTP/2"
        );
    }
    let upgraded = hyper::upgrade::on(&mut res).await.unwrap();
    let mut ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Client, None).await;
    ws.send(Message::text("over h2")).await.unwrap();
    match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => assert_eq!(t.as_str(), "over h2"),
        other => panic!("{other:?}"),
    }
    ws.close(None).await.unwrap();
    match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) => {}
        other => panic!("{other:?}"),
    }
    // The connection still serves ordinary requests afterwards.
    assert_eq!(get(&mut send, addr, "/plain").await.0, 200);
    server.shutdown().await.unwrap();
}

/// Sends `req` and returns the status, failing the test if the stream was upgraded.
async fn status_without_tunnel(
    send: &mut SendRequest<Empty<Bytes>>,
    req: http::Request<Empty<Bytes>>,
) -> Result<u16, hyper::Error> {
    send.ready().await.unwrap();
    let res = tokio::time::timeout(Duration::from_secs(5), send.send_request(req))
        .await
        .expect("no response")?;
    assert!(
        !res.status().is_success(),
        "a non-WebSocket CONNECT got {}: that would open a tunnel",
        res.status()
    );
    Ok(res.status().as_u16())
}

#[tokio::test]
async fn non_websocket_connect_is_never_tunnelled() {
    let server = server().await;
    let addr = server.local_addr();
    let mut send = h2(addr).await;
    assert_eq!(get(&mut send, addr, "/plain").await.0, 200);
    // Classic CONNECT (no :protocol, authority-form target), as a tunnelling proxy would get.
    let classic = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(addr.to_string())
        .body(Empty::new())
        .unwrap();
    let status = status_without_tunnel(&mut send, classic).await.unwrap();
    assert_eq!(status, 404, "classic CONNECT");
    // Extended CONNECT with a protocol other than websocket, on a WebSocket and a plain route.
    for path in ["/echo", "/plain"] {
        let mut req = extended_connect(addr, path);
        req.extensions_mut()
            .insert(hyper::ext::Protocol::from_static("not-websocket"));
        let status = status_without_tunnel(&mut send, req).await.unwrap();
        assert_eq!(status, 405, "{path}: :protocol not-websocket");
    }
    // The connection is still usable.
    assert_eq!(get(&mut send, addr, "/plain").await.0, 200);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn http1_websockets_still_work_on_an_http2_enabled_server() {
    let server = server().await;
    let addr = server.local_addr();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut ws, resp) = tokio_tungstenite::client_async(format!("ws://{addr}/echo"), tcp)
        .await
        .unwrap();
    assert_eq!(resp.status(), 101);
    ws.send(Message::text("over h1")).await.unwrap();
    match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => assert_eq!(t.as_str(), "over h1"),
        other => panic!("{other:?}"),
    }
    ws.close(None).await.unwrap();
    server.shutdown().await.unwrap();
}

// ---- P4.3: routing and shared security policy over HTTP/2 ----------------------------

use poring::policy::WsOrigins;
use poring_tests::secure::TableAuth;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Server with an authenticated WS route, a public WS route, a plain GET route, CORS for
/// `https://app.example` and a WS-only allowance for `https://partner.example`. `started`
/// counts sessions that reached the handler.
async fn secure_server(started: Arc<AtomicUsize>, max_ws_sessions: usize) -> poring::Server {
    let handler = move |ws: WebSocketUpgrade| {
        let started = started.clone();
        async move {
            let ws = ws.protocols(["chat"]);
            ws.on_upgrade(move |mut sock| async move {
                started.fetch_add(1, Ordering::SeqCst);
                while let Some(Ok(m)) = sock.next().await {
                    if m.is_close() || sock.send(m).await.is_err() {
                        break;
                    }
                }
            })
        }
    };
    Poring::new()
        .limits(poring::Limits {
            max_ws_sessions,
            ..Default::default()
        })
        .authenticator(TableAuth::fixture())
        .cors(Cors::new().origins(["https://app.example"]))
        .ws_origins(WsOrigins::new().allow(["https://partner.example"]))
        .route_with(
            RouteMethod::Get,
            "/ws",
            Policy::new().authenticated(),
            handler.clone(),
        )
        .route_with(RouteMethod::Get, "/open", Policy::new().public(), handler)
        .route_with(
            RouteMethod::Get,
            "/data",
            Policy::new().public(),
            || async { "data" },
        )
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap()
}

/// An Extended CONNECT for `path` with exactly the given extra headers (no defaults).
fn connect_with(
    addr: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
) -> http::Request<Empty<Bytes>> {
    let mut b = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!("http://{addr}{path}"));
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let mut req = b.body(Empty::new()).unwrap();
    req.extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));
    req
}

async fn respond(
    send: &mut SendRequest<Empty<Bytes>>,
    req: http::Request<Empty<Bytes>>,
) -> http::Response<hyper::body::Incoming> {
    send.ready().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), send.send_request(req))
        .await
        .expect("no response")
        .expect("request failed")
}

const V13: (&str, &str) = ("sec-websocket-version", "13");

#[tokio::test]
async fn h2_handshakes_get_the_same_origin_check_as_http1() {
    let started = Arc::new(AtomicUsize::new(0));
    let server = secure_server(started.clone(), 100).await;
    let addr = server.local_addr();
    let mut send = h2(addr).await;
    let same = format!("http://{addr}");
    for (origin, want) in [
        (Some("https://evil.example"), 403),
        (Some("null"), 403),
        (Some("https://app.example"), 200),
        // Allowed for WebSockets only (not a CORS origin): the CORS unsafe-method check
        // must treat the HTTP/2 handshake like the HTTP/1.1 GET.
        (Some("https://partner.example"), 200),
        (Some(same.as_str()), 200),
        (None, 200),
    ] {
        let mut h = vec![V13];
        if let Some(o) = origin {
            h.push(("origin", o));
        }
        let res = respond(&mut send, connect_with(addr, "/open", &h)).await;
        assert_eq!(res.status(), want, "origin {origin:?}");
    }
    // Denied handshakes never reached the handler: 4 accepted sessions at most.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(started.load(Ordering::SeqCst) <= 4);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn h2_handshakes_are_authenticated_before_any_session_starts() {
    let started = Arc::new(AtomicUsize::new(0));
    let server = secure_server(started.clone(), 100).await;
    let addr = server.local_addr();
    let mut send = h2(addr).await;
    let res = respond(&mut send, connect_with(addr, "/ws", &[V13])).await;
    assert_eq!(res.status(), 401);
    let res = respond(
        &mut send,
        connect_with(addr, "/ws", &[V13, ("authorization", "Bearer nope")]),
    )
    .await;
    assert_eq!(res.status(), 401);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        started.load(Ordering::SeqCst),
        0,
        "a session started without auth"
    );
    // With a valid token the stream becomes a working WebSocket.
    let mut res = respond(
        &mut send,
        connect_with(
            addr,
            "/ws",
            &[V13, ("authorization", "Bearer reader-token")],
        ),
    )
    .await;
    assert_eq!(res.status(), 200);
    let upgraded = hyper::upgrade::on(&mut res).await.unwrap();
    let mut ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Client, None).await;
    ws.send(Message::text("authed")).await.unwrap();
    match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => assert_eq!(t.as_str(), "authed"),
        other => panic!("{other:?}"),
    }
    assert_eq!(started.load(Ordering::SeqCst), 1);
    ws.close(None).await.unwrap();
    while ws.next().await.is_some() {}
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn h2_handshake_headers_are_validated() {
    let server = secure_server(Arc::new(AtomicUsize::new(0)), 100).await;
    let addr = server.local_addr();
    let mut send = h2(addr).await;
    // Missing version: 400 with the supported version.
    let res = respond(&mut send, connect_with(addr, "/open", &[])).await;
    assert_eq!(res.status(), 400);
    assert_eq!(res.headers()["sec-websocket-version"], "13");
    // Unsupported version: 426.
    let res = respond(
        &mut send,
        connect_with(addr, "/open", &[("sec-websocket-version", "8")]),
    )
    .await;
    assert_eq!(res.status(), 426);
    assert_eq!(res.headers()["sec-websocket-version"], "13");
    // Subprotocol negotiation works as on HTTP/1.1.
    let res = respond(
        &mut send,
        connect_with(
            addr,
            "/open",
            &[V13, ("sec-websocket-protocol", "other, chat")],
        ),
    )
    .await;
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["sec-websocket-protocol"], "chat");
    for h in [
        "sec-websocket-accept",
        "upgrade",
        "connection",
        "content-length",
    ] {
        assert!(
            res.headers().get(h).is_none(),
            "{h} on an HTTP/2 WebSocket response"
        );
    }
    drop(res);
    // A key is not part of RFC 8441 and is ignored if sent.
    let res = respond(
        &mut send,
        connect_with(addr, "/open", &[V13, ("sec-websocket-key", "not-base64")]),
    )
    .await;
    assert_eq!(res.status(), 200);
    drop(res);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn h2_websocket_connect_only_reaches_websocket_routes() {
    let server = secure_server(Arc::new(AtomicUsize::new(0)), 100).await;
    let addr = server.local_addr();
    let mut send = h2(addr).await;
    // A plain GET route is not a WebSocket endpoint.
    let res = respond(&mut send, connect_with(addr, "/data", &[V13])).await;
    assert_eq!(res.status(), 405);
    let allow = res.headers()["allow"].to_str().unwrap().to_owned();
    assert!(
        allow.contains("GET") && !allow.contains("CONNECT"),
        "{allow}"
    );
    // Unknown path.
    let res = respond(&mut send, connect_with(addr, "/nope", &[V13])).await;
    assert_eq!(res.status(), 404);
    // Plain GETs to the WebSocket route are rejected by the extractor, not upgraded.
    assert_eq!(get(&mut send, addr, "/open").await.0, 400);
    assert_eq!(get(&mut send, addr, "/data").await, (200, "data".into()));
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn h2_websocket_sessions_count_against_the_session_limit() {
    let server = secure_server(Arc::new(AtomicUsize::new(0)), 1).await;
    let addr = server.local_addr();
    let mut send = h2(addr).await;
    let mut first = respond(&mut send, connect_with(addr, "/open", &[V13])).await;
    assert_eq!(first.status(), 200);
    let upgraded = hyper::upgrade::on(&mut first).await.unwrap();
    let ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Client, None).await;
    // Second stream on the same connection: over the limit.
    let second = respond(&mut send, connect_with(addr, "/open", &[V13])).await;
    assert_eq!(second.status(), 503);
    // Ordinary requests on the connection are not affected.
    assert_eq!(get(&mut send, addr, "/data").await.0, 200);
    drop(ws);
    server.shutdown().await.unwrap();
}

// ---- P4.4: stream I/O, multiplexing, cancellation, flow control, shutdown ---------------

use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

type H2Ws = WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>;

/// Live-session counter that also counts finished sessions.
#[derive(Clone, Default)]
struct Live {
    live: Arc<AtomicUsize>,
    ended: Arc<AtomicUsize>,
}
struct LiveGuard(Live);
impl Drop for LiveGuard {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
        self.0.ended.fetch_add(1, Ordering::SeqCst);
    }
}
impl Live {
    fn enter(&self) -> LiveGuard {
        self.live.fetch_add(1, Ordering::SeqCst);
        LiveGuard(self.clone())
    }
    fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }
}

async fn wait_for(mut f: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    f()
}

/// `/echo` managed echo (4 MiB messages), `/flood` managed sender that never stops,
/// `/plain` GET. Session limit `limit`, shutdown grace 2 s.
async fn lifecycle_server(live: Live, sent: Arc<AtomicUsize>, limit: usize) -> poring::Server {
    let l1 = live.clone();
    let l2 = live;
    Poring::new()
        .limits(poring::Limits {
            max_ws_sessions: limit,
            shutdown_grace: Duration::from_secs(2),
            ..Default::default()
        })
        .get("/echo", move |ws: WebSocketUpgrade| {
            let live = l1.clone();
            async move {
                ws.max_message_size(4 << 20).managed().on_upgrade(
                    move |mut sock: ManagedSocket| async move {
                        let _g = live.enter();
                        while let Some(m) = sock.recv().await {
                            if sock.send(m).await.is_err() {
                                break;
                            }
                        }
                    },
                )
            }
        })
        .get("/flood", move |ws: WebSocketUpgrade| {
            let (live, sent) = (l2.clone(), sent.clone());
            async move {
                ws.managed()
                    .no_ping()
                    .idle_timeout(Duration::from_millis(1_500))
                    .on_upgrade(move |mut sock: ManagedSocket| async move {
                        let _g = live.enter();
                        let chunk = vec![1u8; 16 * 1024];
                        while sock.send(Message::binary(chunk.clone())).await.is_ok() {
                            sent.fetch_add(1, Ordering::SeqCst);
                        }
                    })
            }
        })
        .get("/plain", || async { "plain" })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap()
}

async fn open_ws(send: &mut SendRequest<Empty<Bytes>>, addr: SocketAddr, path: &str) -> H2Ws {
    let mut res = respond(send, connect_with(addr, path, &[V13])).await;
    assert_eq!(res.status(), 200, "{path}");
    let upgraded = hyper::upgrade::on(&mut res).await.unwrap();
    WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Client, None).await
}

async fn next_data(ws: &mut H2Ws) -> Message {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
            Ok(Some(Ok(m))) => return m,
            other => panic!("{other:?}"),
        }
    }
}

#[tokio::test]
async fn several_websockets_and_requests_share_one_http2_connection() {
    let live = Live::default();
    let server = lifecycle_server(live.clone(), Arc::default(), 100).await;
    let addr = server.local_addr();
    let mut send = h2(addr).await;
    let mut streams = Vec::new();
    for _ in 0..4 {
        streams.push(open_ws(&mut send, addr, "/echo").await);
    }
    assert!(wait_for(|| live.live() == 4).await);
    // Interleave traffic on every stream with ordinary requests on the same connection.
    for round in 0..5 {
        for (i, ws) in streams.iter_mut().enumerate() {
            ws.send(Message::text(format!("s{i} r{round}")))
                .await
                .unwrap();
        }
        assert_eq!(get(&mut send, addr, "/plain").await, (200, "plain".into()));
        for (i, ws) in streams.iter_mut().enumerate() {
            match next_data(ws).await {
                Message::Text(t) => assert_eq!(t.as_str(), format!("s{i} r{round}")),
                other => panic!("{other:?}"),
            }
        }
    }
    for mut ws in streams {
        ws.close(None).await.unwrap();
        while let Some(Ok(_)) = ws.next().await {}
    }
    assert!(wait_for(|| live.live() == 0).await);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn binary_ping_and_close_codes_work_over_http2() {
    let live = Live::default();
    let server = lifecycle_server(live.clone(), Arc::default(), 100).await;
    let addr = server.local_addr();
    let mut send = h2(addr).await;
    let mut ws = open_ws(&mut send, addr, "/echo").await;
    ws.send(Message::binary(vec![0u8, 1, 2, 255]))
        .await
        .unwrap();
    assert_eq!(
        next_data(&mut ws).await,
        Message::binary(vec![0u8, 1, 2, 255])
    );
    ws.send(Message::text("")).await.unwrap();
    assert_eq!(next_data(&mut ws).await, Message::text(""));
    // A ping from the client is answered with a pong carrying the same payload.
    ws.send(Message::Ping(Bytes::from_static(b"hb")))
        .await
        .unwrap();
    let pong = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Pong(p))) => return p,
                Some(Ok(_)) => continue,
                other => panic!("{other:?}"),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(&pong[..], b"hb");
    // The peer's close code is echoed and the session ends.
    ws.close(Some(CloseFrame {
        code: CloseCode::from(4002),
        reason: "bye".into(),
    }))
    .await
    .unwrap();
    match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
        Ok(Some(Ok(Message::Close(Some(f))))) => assert_eq!(u16::from(f.code), 4002),
        other => panic!("{other:?}"),
    }
    assert!(wait_for(|| live.live() == 0).await);
    // The connection is still healthy.
    assert_eq!(get(&mut send, addr, "/plain").await.0, 200);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn cancelling_one_http2_stream_ends_only_its_session_and_frees_its_permit() {
    let live = Live::default();
    let server = lifecycle_server(live.clone(), Arc::default(), 2).await;
    let addr = server.local_addr();
    let mut send = h2(addr).await;
    let a = open_ws(&mut send, addr, "/echo").await;
    let mut b = open_ws(&mut send, addr, "/echo").await;
    assert!(wait_for(|| live.live() == 2).await);
    // At the limit: a third stream is refused.
    let res = respond(&mut send, connect_with(addr, "/echo", &[V13])).await;
    assert_eq!(res.status(), 503);
    drop(res);
    // Dropping `a` resets its stream (no close frame): only that session ends.
    drop(a);
    assert!(
        wait_for(|| live.live() == 1).await,
        "cancelled stream's session did not end"
    );
    b.send(Message::text("still here")).await.unwrap();
    assert_eq!(next_data(&mut b).await, Message::text("still here"));
    // Its permit is back: a new stream is admitted.
    let mut c = open_ws(&mut send, addr, "/echo").await;
    c.send(Message::text("c")).await.unwrap();
    assert_eq!(next_data(&mut c).await, Message::text("c"));
    drop((b, c));
    assert!(wait_for(|| live.live() == 0).await);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn large_messages_and_stalled_streams_respect_http2_flow_control() {
    let live = Live::default();
    let sent = Arc::new(AtomicUsize::new(0));
    let server = lifecycle_server(live.clone(), sent.clone(), 100).await;
    let addr = server.local_addr();
    let mut send = h2(addr).await;
    // 1 MiB each way: far larger than the 65 535-byte initial HTTP/2 window.
    let mut ws = open_ws(&mut send, addr, "/echo").await;
    let big: Vec<u8> = (0..(1usize << 20)).map(|i| (i % 251) as u8).collect();
    ws.send(Message::binary(big.clone())).await.unwrap();
    match next_data(&mut ws).await {
        Message::Binary(b) => assert!(b[..] == big[..], "payload corrupted"),
        other => panic!("{other:?}"),
    }
    // A stream whose client never reads: the server sender stalls ...
    let flood = open_ws(&mut send, addr, "/flood").await;
    assert!(wait_for(|| sent.load(Ordering::SeqCst) > 0).await);
    tokio::time::sleep(Duration::from_millis(600)).await;
    let a = sent.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let b = sent.load(Ordering::SeqCst);
    assert_eq!(a, b, "sender did not stall on a non-reading HTTP/2 stream");
    eprintln!("h2 flood stalled after {b} x 16 KiB");
    // ... while other streams and requests on the same connection keep working.
    ws.send(Message::text("independent")).await.unwrap();
    assert_eq!(next_data(&mut ws).await, Message::text("independent"));
    assert_eq!(get(&mut send, addr, "/plain").await.0, 200);
    // The stalled session is ended by its idle bound.
    assert!(
        wait_for(|| live.live() == 1).await,
        "stalled session never ended"
    );
    drop((flood, ws));
    assert!(wait_for(|| live.live() == 0).await);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_closes_open_http2_websockets_with_going_away() {
    let live = Live::default();
    let server = lifecycle_server(live.clone(), Arc::default(), 100).await;
    let addr = server.local_addr();
    let mut send = h2(addr).await;
    let mut streams = Vec::new();
    for _ in 0..3 {
        streams.push(open_ws(&mut send, addr, "/echo").await);
    }
    assert!(wait_for(|| live.live() == 3).await);
    let started = std::time::Instant::now();
    let shutdown = tokio::spawn(server.shutdown());
    for ws in streams.iter_mut() {
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
            Ok(Some(Ok(Message::Close(Some(f))))) => assert_eq!(f.code, CloseCode::Away),
            other => panic!("{other:?}"),
        }
    }
    drop(streams);
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
    assert_eq!(live.live(), 0);
}

/// `/stall-hb`: heartbeat only; `/stall`: no timers at all. Both flood a client that never
/// reads, so the server's writes block on HTTP/2 stream flow control.
async fn stall_server(live: Live) -> poring::Server {
    let (l1, l2, l3) = (live.clone(), live.clone(), live);
    let flood = |live: Live| {
        move |mut sock: ManagedSocket| async move {
            let _g = live.enter();
            let chunk = vec![1u8; 16 * 1024];
            while sock.send(Message::binary(chunk.clone())).await.is_ok() {}
        }
    };
    Poring::new()
        .limits(poring::Limits {
            shutdown_grace: Duration::from_secs(1),
            ..Default::default()
        })
        .get("/stall-hb", move |ws: WebSocketUpgrade| {
            let live = l1.clone();
            async move {
                ws.managed()
                    .no_idle_timeout()
                    .ping_interval(Duration::from_millis(100))
                    .pong_timeout(Duration::from_millis(300))
                    .close_timeout(Duration::from_millis(200))
                    .on_upgrade(flood(live))
            }
        })
        .get("/stall", move |ws: WebSocketUpgrade| {
            let live = l2.clone();
            async move {
                ws.managed()
                    .no_idle_timeout()
                    .no_ping()
                    .no_write_timeout()
                    .close_timeout(Duration::from_millis(200))
                    .on_upgrade(flood(live))
            }
        })
        .get("/echo", move |ws: WebSocketUpgrade| {
            let live = l3.clone();
            async move {
                ws.managed()
                    .on_upgrade(move |mut sock: ManagedSocket| async move {
                        let _g = live.enter();
                        while let Some(m) = sock.recv().await {
                            if sock.send(m).await.is_err() {
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
        .unwrap()
}

#[tokio::test]
async fn heartbeat_ends_a_stalled_http2_websocket_and_spares_its_neighbours() {
    let live = Live::default();
    let server = stall_server(live.clone()).await;
    let addr = server.local_addr();
    let mut send = h2(addr).await;
    let mut echo = open_ws(&mut send, addr, "/echo").await;
    let _stalled = open_ws(&mut send, addr, "/stall-hb").await;
    assert!(wait_for(|| live.live() == 2).await);
    // The stalled stream never reads (nor answers pings): its heartbeat ends it ...
    assert!(
        wait_for(|| server.ws_stats().heartbeat_timeouts == 1).await,
        "heartbeat not enforced on a blocked HTTP/2 stream"
    );
    assert!(wait_for(|| live.live() == 1).await);
    // ... while the other stream on the same connection is unaffected.
    echo.send(Message::text("alive")).await.unwrap();
    assert_eq!(next_data(&mut echo).await, Message::text("alive"));
    drop(echo);
    assert!(wait_for(|| live.live() == 0).await);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_blocked_http2_websocket_write_ends_its_session_promptly_at_shutdown() {
    let live = Live::default();
    let server = stall_server(live.clone()).await;
    let addr = server.local_addr();
    let mut send = h2(addr).await;
    let _stalled = open_ws(&mut send, addr, "/stall").await;
    assert!(wait_for(|| live.live() == 1).await);
    // Let the writes block on flow control.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let started = std::time::Instant::now();
    let shutdown = tokio::spawn(server.shutdown());
    // The session (handler, permits, queues) ends at once, blocked write or not.
    assert!(wait_for(|| live.live() == 0).await);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    // hyper keeps the HTTP/2 stream's internal send task waiting for the window this
    // client never grants, so the connection itself only closes when the grace period
    // (1 s here) ends and it is cancelled: bounded, never indefinite.
    tokio::time::timeout(Duration::from_secs(5), shutdown)
        .await
        .expect("shutdown is bounded by the grace period")
        .unwrap()
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
}

// ---- P4.5: independent client interoperability (Node.js http2 / nghttp2) -------------

/// Runs `tests/interop/h2_ws_client.mjs` against a Poring server. Requires Node.js >= 18
/// on `PATH`; ignored by default so a missing Node never turns into a silent pass. Run with
/// `cargo test -p poring-tests --no-default-features --features websocket,http2 --test ws_h2 -- --ignored`.
#[tokio::test]
#[ignore = "requires Node.js on PATH; run with --ignored"]
async fn independent_nodejs_http2_client_interoperates() {
    let server = server().await;
    let addr = server.local_addr();
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("interop/h2_ws_client.mjs");
    let out = tokio::time::timeout(
        Duration::from_secs(20),
        tokio::process::Command::new("node")
            .arg(&script)
            .arg(addr.to_string())
            .arg("/echo")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("node client hung")
    .expect("failed to run `node` (is Node.js installed?)");
    let stdout = String::from_utf8_lossy(&out.stdout);
    eprintln!("node: {stdout}{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "node client failed: {stdout}");
    assert!(stdout.contains("\"ok\":true"), "{stdout}");
    server.shutdown().await.unwrap();
}
