//! Downstream smoke test: attribute macros, fluent routes, JSON, a per-route WebSocket
//! origin policy (the macro feature added after poring-macros 0.1.1), managed and typed
//! WebSockets, served over a real socket and exercised with a real client.
use futures_util::{SinkExt, StreamExt};
use poring::prelude::*;
use poring::ws::WebSocketUpgrade;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;

#[derive(Serialize)]
struct Health {
    ok: bool,
}

#[poring::get("/health")]
async fn health() -> Json<Health> {
    Json(Health { ok: true })
}

#[derive(Deserialize, PoringSchema)]
struct In {
    #[poring(min_length = 1)]
    text: String,
}

#[derive(Serialize)]
struct Out {
    echo: String,
}

#[poring::ws("/typed", policy(ws_origins = ["https://app.example"]))]
async fn typed(ws: WebSocketUpgrade) -> Response {
    ws.managed()
        .typed::<In, Out>()
        .on_upgrade(|mut sock| async move {
            while let Some(Ok(m)) = sock.recv().await {
                if sock.send(&Out { echo: m.text }).await.is_err() {
                    break;
                }
            }
        })
}

poring_app! {
    pub Consumer {
        routes: [health, typed],
    }
}

#[tokio::main]
async fn main() {
    let server = Consumer::builder()
        .build()
        .expect("app builds")
        .bind("127.0.0.1:0")
        .await
        .expect("binds");
    let addr = server.local_addr();

    // HTTP/1.1 JSON route.
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("GET /health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = String::new();
    s.read_to_string(&mut buf).await.unwrap();
    assert!(buf.starts_with("HTTP/1.1 200"), "{buf}");
    assert!(buf.ends_with("{\"ok\":true}"), "{buf}");

    // Typed managed WebSocket, allowed origin.
    let mut req = tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
        format!("ws://{addr}/typed"),
    )
    .unwrap();
    req.headers_mut()
        .insert("origin", "https://app.example".parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    ws.send(Message::text(r#"{"text":"hi"}"#)).await.unwrap();
    let reply = loop {
        match ws.next().await.unwrap().unwrap() {
            Message::Text(t) => break t.to_string(),
            _ => continue,
        }
    };
    assert_eq!(reply, r#"{"echo":"hi"}"#);
    ws.close(None).await.unwrap();

    // Disallowed origin: rejected before the upgrade.
    let mut req = tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
        format!("ws://{addr}/typed"),
    )
    .unwrap();
    req.headers_mut()
        .insert("origin", "https://evil.example".parse().unwrap());
    match tokio_tungstenite::connect_async(req).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(r)) => assert_eq!(r.status(), 403),
        other => panic!("expected 403, got {other:?}"),
    }

    server.shutdown().await.unwrap();
    println!("consumer smoke test: OK");
}
