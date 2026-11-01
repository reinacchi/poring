//! Typed WebSocket (echo, validation, close, backpressure) and multipart limits.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use poring::extract::multipart::Multipart;
use poring::prelude::*;
use poring::ws::{WebSocketUpgrade, WsError};
use poring_tests::status_of;
use serde::{Deserialize, Serialize};
use tokio_tungstenite::tungstenite::Message;

#[derive(Debug, Deserialize, Serialize, PoringSchema)]
struct ChatIn {
    #[poring(min_length = 1, max_length = 100)]
    text: String,
}

#[derive(Clone, Default)]
struct Progress(Arc<AtomicUsize>);

#[derive(Clone, Default, PoringState)]
struct WsState {
    progress: Progress,
}

#[poring::ws("/ws/echo")]
async fn echo(ws: WebSocketUpgrade) -> Response {
    ws.typed::<ChatIn, serde_json::Value>().on_upgrade(|mut sock| async move {
        while let Some(msg) = sock.recv().await {
            let out = match msg {
                Ok(m) => serde_json::json!({"kind": "Echo", "text": m.text}),
                Err(WsError::Invalid(issues)) => serde_json::json!({"kind": "Invalid", "issues": issues.len()}),
                Err(_) => break,
            };
            if sock.send(&out).await.is_err() {
                break;
            }
        }
    })
}

#[poring::ws("/ws/flood")]
async fn flood(State(p): State<Progress>, ws: WebSocketUpgrade) -> Response {
    ws.max_write_buffer(64 * 1024).typed::<ChatIn, String>().on_upgrade(move |mut sock| async move {
        let chunk = "x".repeat(32 * 1024);
        for _ in 0..512 {
            if sock.send(&chunk).await.is_err() {
                return;
            }
            p.0.fetch_add(1, Ordering::SeqCst);
        }
    })
}

#[poring::post("/upload", policy(body_limit = "4KiB"))]
async fn upload(mut mp: Multipart) -> Result<String, ApiError> {
    let mut out = Vec::new();
    while let Some(f) = mp.next_field().await? {
        let name = f.name().unwrap_or("?").to_owned();
        let len = f.bytes().await?.len();
        out.push(format!("{name}={len}"));
    }
    Ok(out.join(","))
}

poring_app! {
    WsApp {
        state: WsState,
        routes: [echo, flood, upload],
    }
}

async fn connect(addr: std::net::SocketAddr, path: &str) -> tokio_tungstenite::WebSocketStream<tokio::net::TcpStream> {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (ws, resp) = tokio_tungstenite::client_async(format!("ws://{addr}{path}"), tcp).await.unwrap();
    assert_eq!(resp.status(), 101);
    ws
}

#[tokio::test]
async fn typed_echo_validation_and_close() {
    let server = WsApp::builder().state(WsState::default()).build().unwrap().bind("127.0.0.1:0").await.unwrap();
    let mut ws = connect(server.local_addr(), "/ws/echo").await;
    ws.send(Message::text(r#"{"text":"hello"}"#)).await.unwrap();
    let m = ws.next().await.unwrap().unwrap();
    assert_eq!(serde_json::from_str::<serde_json::Value>(m.to_text().unwrap()).unwrap()["text"], "hello");
    ws.send(Message::text(r#"{"text":""}"#)).await.unwrap();
    let m = ws.next().await.unwrap().unwrap();
    assert_eq!(serde_json::from_str::<serde_json::Value>(m.to_text().unwrap()).unwrap()["kind"], "Invalid");
    // Oversized message (> 64 KiB default) terminates the connection instead of being buffered.
    let _ = ws.send(Message::text(format!("{{\"text\":\"{}\"}}", "y".repeat(70 * 1024)))).await;
    let next = tokio::time::timeout(Duration::from_secs(3), ws.next()).await.unwrap();
    assert!(matches!(next, None | Some(Err(_)) | Some(Ok(Message::Close(_)))), "{next:?}");
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn slow_reader_applies_backpressure() {
    let state = WsState::default();
    let progress = state.progress.clone();
    let server = WsApp::builder().state(state).build().unwrap().bind("127.0.0.1:0").await.unwrap();
    let mut ws = connect(server.local_addr(), "/ws/flood").await;
    // Don't read for a while: the producer must stall well before sending all 512 x 32 KiB (16 MiB).
    tokio::time::sleep(Duration::from_millis(500)).await;
    let stalled_at = progress.0.load(Ordering::SeqCst);
    assert!(stalled_at < 512, "producer was not throttled (sent {stalled_at}/512)");
    // Now drain: every message eventually arrives.
    let mut got = 0;
    while got < 512 {
        match tokio::time::timeout(Duration::from_secs(10), ws.next()).await.unwrap() {
            Some(Ok(Message::Text(_))) => got += 1,
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(progress.0.load(Ordering::SeqCst), 512);
    eprintln!("producer stalled at {stalled_at}/512 messages while the reader was paused");
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn non_upgrade_request_is_rejected() {
    let app = WsApp::builder().state(WsState::default()).build().unwrap();
    let r = app.client().get("/ws/echo").send().await;
    assert_eq!(r.status, 400);
    let m = WsApp::manifest().unwrap();
    assert!(m.find("GET /ws/echo").unwrap().websocket);
}

fn multipart_body(parts: &[(&str, usize)]) -> String {
    let mut s = String::new();
    for (name, len) in parts {
        s.push_str(&format!("--XB\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{}\r\n", "a".repeat(*len)));
    }
    s.push_str("--XB--\r\n");
    s
}

#[tokio::test]
async fn multipart_ceilings() {
    let app = WsApp::builder().state(WsState::default()).build().unwrap();
    let c = app.client();
    let ok = c
        .post("/upload")
        .header("content-type", "multipart/form-data; boundary=XB")
        .body(multipart_body(&[("a", 10), ("b", 20)]))
        .send()
        .await;
    assert_eq!(ok.text(), "a=10,b=20");
    let big = c
        .post("/upload")
        .header("content-type", "multipart/form-data; boundary=XB")
        .body(multipart_body(&[("a", 5000)]))
        .send()
        .await;
    assert_eq!(big.status, 413);
    let many: Vec<(&str, usize)> = (0..70).map(|_| ("f", 1)).collect();
    let r = c
        .post("/upload")
        .header("content-type", "multipart/form-data; boundary=XB")
        .body(multipart_body(&many))
        .send()
        .await;
    assert_eq!(r.status, 400, "{}", r.text());
    let r = c.post("/upload").header("content-type", "text/plain").body("x").send().await;
    assert_eq!(r.status, 415);
    let _ = status_of("");
}
