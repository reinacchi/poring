//! Server shutdown supervision: once `shutdown()` (or `serve`) returns, no connection task,
//! HTTP/2 stream task or WebSocket session may still be running — whatever outlived the
//! grace period has been cancelled. Covers HTTP/1.1, slow request bodies, HTTP/2, TLS and
//! upgraded WebSocket sessions.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use poring::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BOUND: Duration = Duration::from_secs(5);
const GRACE: Duration = Duration::from_millis(300);

#[derive(Clone, Default)]
struct Probe {
    started: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
}

struct DropGuard(Arc<AtomicUsize>);
impl Drop for DropGuard {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn get(c: &AtomicUsize) -> usize {
    c.load(Ordering::SeqCst)
}

async fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
    let start = Instant::now();
    while !cond() {
        assert!(start.elapsed() < BOUND, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// `/hang` never completes; `/slow` reads a request body.
fn app(probe: Probe) -> poring::Poring {
    Poring::new()
        .limits(poring::Limits {
            shutdown_grace: GRACE,
            ..Default::default()
        })
        .get("/hang", move || {
            let p = probe.clone();
            async move {
                p.started.fetch_add(1, Ordering::SeqCst);
                let _guard = DropGuard(p.dropped.clone());
                std::future::pending::<&'static str>().await
            }
        })
        .post("/slow", |body: String| async move { body })
}

/// Shuts `server` down (bounded) and returns how long it took.
async fn shut(server: poring::Server) -> Duration {
    let start = Instant::now();
    tokio::time::timeout(BOUND, server.shutdown())
        .await
        .expect("shutdown is bounded")
        .unwrap();
    start.elapsed()
}

#[tokio::test]
async fn http1_handler_outliving_the_grace_period_is_cancelled() {
    let probe = Probe::default();
    let server = app(probe.clone())
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("GET /hang HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    eventually("handler started", || get(&probe.started) == 1).await;
    let took = shut(server).await;
    assert!(took >= GRACE, "the grace period is honoured ({took:?})");
    assert_eq!(get(&probe.dropped), 1, "nothing outlives shutdown()");
    // The connection is closed.
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(BOUND, s.read(&mut buf))
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(n, 0);
}

#[tokio::test]
async fn slow_request_body_does_not_keep_the_connection_alive() {
    let server = app(Probe::default())
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    // 10 of the announced 1000 bytes, then nothing.
    s.write_all(
        format!(
            "POST /slow HTTP/1.1\r\nHost: {addr}\r\nContent-Type: text/plain\r\n\
             Content-Length: 1000\r\n\r\n0123456789"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    shut(server).await;
    let mut buf = Vec::new();
    let r = tokio::time::timeout(Duration::from_secs(1), s.read_to_end(&mut buf)).await;
    assert!(
        r.is_ok(),
        "the connection must be closed once shutdown() returned"
    );
}

#[tokio::test]
async fn idle_and_finished_connections_shut_down_promptly() {
    let server = app(Probe::default())
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(
        format!(
            "POST /slow HTTP/1.1\r\nHost: {addr}\r\nContent-Type: text/plain\r\n\
             Content-Length: 2\r\n\r\nok"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(BOUND, s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
    // A keep-alive connection with no request in flight closes at once.
    let took = shut(server).await;
    assert!(
        took < GRACE,
        "no request in flight: no need to wait ({took:?})"
    );
}

#[cfg(feature = "http2")]
#[tokio::test]
async fn http2_stream_tasks_are_cancelled_at_shutdown() {
    use bytes::Bytes;
    use http_body_util::Empty;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let probe = Probe::default();
    let server = app(probe.clone())
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut send, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
            .await
            .unwrap();
    let conn = tokio::spawn(async move {
        let _ = conn.await;
    });
    // Two multiplexed requests on one connection, both hanging.
    let mut requests = Vec::new();
    for _ in 0..2 {
        send.ready().await.unwrap();
        let req = http::Request::get(format!("http://{addr}/hang"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        requests.push(tokio::spawn(send.send_request(req)));
    }
    eventually("both handlers started", || get(&probe.started) == 2).await;
    shut(server).await;
    assert_eq!(
        get(&probe.dropped),
        2,
        "HTTP/2 stream tasks do not outlive shutdown()"
    );
    for r in requests {
        let r = tokio::time::timeout(BOUND, r).await.unwrap().unwrap();
        assert!(r.is_err(), "the hanging requests were reset");
    }
    tokio::time::timeout(BOUND, conn).await.unwrap().unwrap();
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn tls_connections_are_supervised_like_plain_ones() {
    use tokio_rustls::rustls;
    use tokio_rustls::rustls::pki_types::ServerName;

    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let tls = poring::tls::TlsConfig::from_pem(
        ck.cert.pem().as_bytes(),
        ck.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let probe = Probe::default();
    let server = app(probe.clone())
        .build()
        .unwrap()
        .bind_tls("127.0.0.1:0", tls)
        .await
        .unwrap();
    let addr: std::net::SocketAddr = server.local_addr();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ck.cert.der().clone()).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut s = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    s.write_all(b"GET /hang HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    eventually("handler started", || get(&probe.started) == 1).await;

    // A second client stalls in the TLS handshake (sends nothing at all).
    let _stalled = tokio::net::TcpStream::connect(addr).await.unwrap();

    shut(server).await;
    assert_eq!(get(&probe.dropped), 1);
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn websocket_session_ignoring_shutdown_is_cancelled() {
    use poring::ws::WebSocketUpgrade;

    let probe = Probe::default();
    let p = probe.clone();
    let server = app(Probe::default())
        .ws("/ws", move |ws: WebSocketUpgrade| {
            let p = p.clone();
            async move {
                // A raw session that ignores the shutdown signal entirely.
                ws.on_upgrade(move |_sock| async move {
                    p.started.fetch_add(1, Ordering::SeqCst);
                    let _guard = DropGuard(p.dropped.clone());
                    std::future::pending::<()>().await;
                })
            }
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (_ws, _) = tokio_tungstenite::client_async(format!("ws://{addr}/ws"), tcp)
        .await
        .unwrap();
    eventually("session started", || get(&probe.started) == 1).await;
    shut(server).await;
    assert_eq!(get(&probe.dropped), 1);
}
