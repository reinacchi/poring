//! Async fluent app with a typed JSON route (kept identical to the README by
//! `tests/tests/readme.rs`).
use poring::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, PoringSchema)]
struct Message {
    text: String,
}

#[tokio::main]
async fn main() -> Result<(), poring::StartupError> {
    Poring::new()
        .get("/ping", || async { "pong" })
        .post("/echo", |Json(message): Json<Message>| async move {
            Json(message)
        })
        .listen("127.0.0.1:3000")
        .await
}
