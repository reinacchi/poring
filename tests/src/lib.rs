//! Shared helpers for Poring's integration tests.
#![forbid(unsafe_code)]

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Sends raw bytes over TCP and returns the raw response (until close or timeout).
pub async fn raw_http(addr: std::net::SocketAddr, request: &[u8]) -> String {
    let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
    s.write_all(request).await.expect("write");
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).into_owned()
}

/// Status code of a raw HTTP/1.1 response.
pub fn status_of(raw: &str) -> u16 {
    raw.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
}

pub mod secure;
pub mod shop;
