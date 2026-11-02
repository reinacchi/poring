//! Typed WebSocket echo.
//!
//! ```text
//! cargo run -p poring-examples --example websocket_echo
//! # then, with any WebSocket client:  websocat ws://127.0.0.1:3000/echo
//! #   {"text":"hi"}  ->  {"echo":"hi","n":1}
//! #   {"text":""}    ->  {"error":"invalid","issues":[...]}
//! ```
use poring::prelude::*;
use poring::ws::{WebSocketUpgrade, WsError};
use serde::{Deserialize, Serialize};

/// Inbound message: validated before the handler sees it.
#[derive(Deserialize, PoringSchema)]
struct In {
    #[poring(min_length = 1, max_length = 500)]
    text: String,
}

/// Outbound message.
#[derive(Serialize)]
#[serde(untagged)]
enum Out {
    Echo {
        echo: String,
        n: u64,
    },
    Error {
        error: &'static str,
        issues: Vec<poring::ValidationIssue>,
    },
}

#[poring::ws("/echo")]
async fn echo(ws: WebSocketUpgrade) -> Response {
    ws.max_message_size(16 * 1024)
        .typed::<In, Out>()
        .on_upgrade(|mut sock| async move {
            let mut n = 0;
            while let Some(msg) = sock.recv().await {
                let reply = match msg {
                    Ok(m) => {
                        n += 1;
                        Out::Echo { echo: m.text, n }
                    }
                    Err(WsError::Invalid(issues)) => Out::Error {
                        error: "invalid",
                        issues,
                    },
                    Err(WsError::Decode(_)) => Out::Error {
                        error: "malformed json",
                        issues: vec![],
                    },
                    Err(WsError::Socket(_)) => break,
                };
                // `send` waits when the client reads slowly (bounded write buffer).
                if sock.send(&reply).await.is_err() {
                    break;
                }
            }
        })
}

poring_app! {
    pub Echo {
        routes: [echo],
    }
}

#[tokio::main]
async fn main() -> Result<(), poring::StartupError> {
    let addr = std::env::var("PORING_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());
    Echo::builder().listen(addr).await
}
