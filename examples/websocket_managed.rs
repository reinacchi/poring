//! Managed WebSocket echo: Poring drives the socket (pings, idle detection, close codes).
//!
//! ```text
//! cargo run -p poring-examples --example websocket_managed
//! # then: websocat ws://127.0.0.1:3000/echo
//! ```
use poring::prelude::*;
use poring::ws::{ManagedSocket, WebSocketUpgrade};

fn main() -> Result<(), poring::StartupError> {
    Poring::new()
        .ws("/echo", |ws: WebSocketUpgrade| async move {
            // Managed sessions keep pinging, detect dead peers and close cleanly.
            ws.max_message_size(64 * 1024).managed().on_upgrade(
                |mut sock: ManagedSocket| async move {
                    while let Some(msg) = sock.recv().await {
                        if sock.send(msg).await.is_err() {
                            break;
                        }
                    }
                },
            )
        })
        .run("127.0.0.1:3000")?;

    Ok(())
}
