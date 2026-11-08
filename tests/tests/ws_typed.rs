//! Typed WebSocket echo, validation, close and backpressure (`#[poring::ws]` routes).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use poring::prelude::*;
use poring::ws::{WebSocketUpgrade, WsError};
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
    ws.typed::<ChatIn, serde_json::Value>()
        .on_upgrade(|mut sock| async move {
            while let Some(msg) = sock.recv().await {
                let out = match msg {
                    Ok(m) => serde_json::json!({"kind": "Echo", "text": m.text}),
                    Err(WsError::Invalid(issues)) => {
                        serde_json::json!({"kind": "Invalid", "issues": issues.len()})
                    }
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
    ws.max_write_buffer(64 * 1024)
        .typed::<ChatIn, String>()
        .on_upgrade(move |mut sock| async move {
            let chunk = "x".repeat(32 * 1024);
            for _ in 0..512 {
                if sock.send(&chunk).await.is_err() {
                    return;
                }
                p.0.fetch_add(1, Ordering::SeqCst);
            }
        })
}

poring_app! {
    WsApp {
        state: WsState,
        routes: [echo, flood],
    }
}

async fn connect(
    addr: std::net::SocketAddr,
    path: &str,
) -> tokio_tungstenite::WebSocketStream<tokio::net::TcpStream> {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (ws, resp) = tokio_tungstenite::client_async(format!("ws://{addr}{path}"), tcp)
        .await
        .unwrap();
    assert_eq!(resp.status(), 101);
    ws
}

#[tokio::test]
async fn typed_echo_validation_and_close() {
    let server = WsApp::builder()
        .state(WsState::default())
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let mut ws = connect(server.local_addr(), "/ws/echo").await;
    ws.send(Message::text(r#"{"text":"hello"}"#)).await.unwrap();
    let m = ws.next().await.unwrap().unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(m.to_text().unwrap()).unwrap()["text"],
        "hello"
    );
    ws.send(Message::text(r#"{"text":""}"#)).await.unwrap();
    let m = ws.next().await.unwrap().unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(m.to_text().unwrap()).unwrap()["kind"],
        "Invalid"
    );
    // Oversized message (> 64 KiB default) terminates the connection instead of being buffered.
    let _ = ws
        .send(Message::text(format!(
            "{{\"text\":\"{}\"}}",
            "y".repeat(70 * 1024)
        )))
        .await;
    let next = tokio::time::timeout(Duration::from_secs(3), ws.next())
        .await
        .unwrap();
    assert!(
        matches!(next, None | Some(Err(_)) | Some(Ok(Message::Close(_)))),
        "{next:?}"
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn slow_reader_applies_backpressure() {
    let state = WsState::default();
    let progress = state.progress.clone();
    let server = WsApp::builder()
        .state(state)
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let mut ws = connect(server.local_addr(), "/ws/flood").await;
    // Don't read for a while: the producer must stall well before sending all 512 x 32 KiB (16 MiB).
    tokio::time::sleep(Duration::from_millis(500)).await;
    let stalled_at = progress.0.load(Ordering::SeqCst);
    assert!(
        stalled_at < 512,
        "producer was not throttled (sent {stalled_at}/512)"
    );
    // Now drain: every message eventually arrives.
    let mut got = 0;
    while got < 512 {
        match tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .unwrap()
        {
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
