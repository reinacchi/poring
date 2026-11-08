//! Native TLS (HTTPS / WSS) with `poring/tls-rustls`. Certificates are generated at
//! test time with rcgen. The client is tokio-rustls trusting only that certificate.
//!
//! Run with `cargo test -p poring-tests --no-default-features --features tls --test tls`
//! (add `,http2` to also test ALPN `h2` and RFC 8441 over TLS).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use poring::prelude::*;
use poring::tls::{TlsConfig, TlsError};
use poring::ws::{ManagedSocket, WebSocketUpgrade};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_tungstenite::tungstenite::Message;

struct Pki {
    cert_pem: String,
    key_pem: String,
    cert_der: CertificateDer<'static>,
}

fn pki() -> Pki {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    Pki {
        cert_pem: ck.cert.pem(),
        key_pem: ck.signing_key.serialize_pem(),
        cert_der: ck.cert.der().clone(),
    }
}

async fn server(pki: &Pki, header_timeout: Duration) -> poring::Server {
    let tls = TlsConfig::from_pem(pki.cert_pem.as_bytes(), pki.key_pem.as_bytes()).unwrap();
    Poring::new()
        .limits(poring::Limits {
            header_read_timeout: header_timeout,
            ..Default::default()
        })
        .get("/plain", || async { "plain over tls" })
        .ws("/echo", |ws: WebSocketUpgrade| async move {
            ws.managed()
                .on_upgrade(|mut sock: ManagedSocket| async move {
                    while let Some(m) = sock.recv().await {
                        if sock.send(m).await.is_err() {
                            break;
                        }
                    }
                })
        })
        .build()
        .unwrap()
        .bind_tls("127.0.0.1:0", tls)
        .await
        .unwrap()
}

async fn tls_connect(
    pki: &Pki,
    addr: SocketAddr,
    alpn: &[&[u8]],
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pki.cert_der.clone()).unwrap();
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap()
}

#[tokio::test]
async fn https_requests_work_over_tls() {
    let pki = pki();
    let server = server(&pki, Duration::from_secs(5)).await;
    let tls = tls_connect(&pki, server.local_addr(), &[b"http/1.1"]).await;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);
    let res = send
        .send_request(
            http::Request::get("/plain")
                .header("host", "localhost")
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"plain over tls");
    drop(send);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn wss_echo_works_over_tls() {
    let pki = pki();
    let server = server(&pki, Duration::from_secs(5)).await;
    let addr = server.local_addr();
    let tls = tls_connect(&pki, addr, &[b"http/1.1"]).await;
    let (mut ws, resp) =
        tokio_tungstenite::client_async(format!("wss://localhost:{}/echo", addr.port()), tls)
            .await
            .unwrap();
    assert_eq!(resp.status(), 101);
    ws.send(Message::text("secure hello")).await.unwrap();
    match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => assert_eq!(t.as_str(), "secure hello"),
        other => panic!("{other:?}"),
    }
    ws.close(None).await.unwrap();
    while let Some(Ok(_)) = ws.next().await {}
    server.shutdown().await.unwrap();
}

#[cfg(feature = "http2")]
#[tokio::test]
async fn alpn_h2_and_rfc8441_websockets_work_over_tls() {
    let pki = pki();
    let server = server(&pki, Duration::from_secs(5)).await;
    let addr = server.local_addr();
    let tls = tls_connect(&pki, addr, &[b"h2", b"http/1.1"]).await;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (mut send, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        TokioIo::new(tls),
    )
    .await
    .unwrap();
    tokio::spawn(conn);
    send.ready().await.unwrap();
    let mut req = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!("https://localhost:{}/echo", addr.port()))
        .header("sec-websocket-version", "13")
        .body(Empty::<Bytes>::new())
        .unwrap();
    req.extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));
    let mut res = send.send_request(req).await.unwrap();
    assert_eq!(res.status(), 200);
    let upgraded = hyper::upgrade::on(&mut res).await.unwrap();
    let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        TokioIo::new(upgraded),
        tokio_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await;
    ws.send(Message::text("h2 over tls")).await.unwrap();
    match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => assert_eq!(t.as_str(), "h2 over tls"),
        other => panic!("{other:?}"),
    }
    drop(ws);
    server.shutdown().await.unwrap();
}

#[test]
fn invalid_tls_configuration_is_reported_without_key_material() {
    let pki = pki();
    match TlsConfig::from_pem(b"not pem", pki.key_pem.as_bytes()) {
        Err(TlsError::Certificate(_)) => {}
        other => panic!("{other:?}"),
    }
    match TlsConfig::from_pem(pki.cert_pem.as_bytes(), b"-----BEGIN NOTHING-----") {
        Err(e @ TlsError::PrivateKey) => {
            assert!(!e.to_string().contains("BEGIN"), "{e}");
        }
        other => panic!("{other:?}"),
    }
    // A key that does not belong to the certificate.
    let other = rcgen::KeyPair::generate().unwrap().serialize_pem();
    match TlsConfig::from_pem(pki.cert_pem.as_bytes(), other.as_bytes()) {
        Err(TlsError::Rustls(_)) => {}
        other => panic!("mismatched key accepted: {other:?}"),
    }
    match TlsConfig::from_pem_files("/definitely/missing/cert.pem", "/missing/key.pem") {
        Err(e @ TlsError::Io { .. }) => assert!(e.to_string().contains("cert.pem"), "{e}"),
        other => panic!("{other:?}"),
    }
    let ok = TlsConfig::from_pem(pki.cert_pem.as_bytes(), pki.key_pem.as_bytes()).unwrap();
    let dbg = format!("{ok:?}");
    assert!(
        !dbg.contains("PRIVATE") && dbg.contains("http/1.1"),
        "{dbg}"
    );
}

#[tokio::test]
async fn plaintext_and_stalled_clients_do_not_block_tls_service() {
    let pki = pki();
    let server = server(&pki, Duration::from_millis(300)).await;
    let addr = server.local_addr();
    // A client that never starts the TLS handshake is dropped after the header timeout.
    let mut stalled = tokio::net::TcpStream::connect(addr).await.unwrap();
    // Plain HTTP on the TLS port: the handshake fails and the connection is closed.
    let mut plain = tokio::net::TcpStream::connect(addr).await.unwrap();
    plain
        .write_all(b"GET /plain HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), plain.read_to_end(&mut buf)).await;
    assert!(!String::from_utf8_lossy(&buf).contains("plain over tls"));
    // Meanwhile TLS clients are served.
    let tls = tls_connect(&pki, addr, &[b"http/1.1"]).await;
    let (mut ws, _) =
        tokio_tungstenite::client_async(format!("wss://localhost:{}/echo", addr.port()), tls)
            .await
            .unwrap();
    ws.send(Message::text("still served")).await.unwrap();
    assert!(matches!(ws.next().await, Some(Ok(Message::Text(_)))));
    drop(ws);
    let mut one = [0u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(3), stalled.read(&mut one)).await;
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
        "stalled TLS client was not closed: {closed:?}"
    );
    server.shutdown().await.unwrap();
}

/// Raw HTTP/1.1 WebSocket handshake over TLS. Returns the response head.
async fn tls_handshake_head(pki: &Pki, addr: SocketAddr, origin: Option<&str>) -> String {
    let mut tls = tls_connect(pki, addr, &[b"http/1.1"]).await;
    let origin = origin
        .map(|o| format!("Origin: {o}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "GET /echo HTTP/1.1\r\nHost: localhost:{}\r\nConnection: Upgrade\r\n\
         Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n{origin}\r\n",
        addr.port()
    );
    tls.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let n = tls.read(&mut chunk).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
    })
    .await;
    String::from_utf8_lossy(&buf).into_owned()
}

/// On a native TLS (wss://) endpoint, a same-host `http://` origin is cross-origin and must
/// be refused, while the `https://` origin upgrades.
#[tokio::test]
async fn wss_endpoints_refuse_plain_http_origins() {
    let pki = pki();
    let server = server(&pki, Duration::from_secs(5)).await;
    let addr = server.local_addr();
    let port = addr.port();
    let cases = [
        (Some(format!("https://localhost:{port}")), "101"),
        (Some(format!("http://localhost:{port}")), "403"),
        (Some("http://localhost".to_owned()), "403"),
        (None, "101"),
    ];
    for (origin, want) in cases {
        let head = tls_handshake_head(&pki, addr, origin.as_deref()).await;
        assert!(
            head.starts_with(&format!("HTTP/1.1 {want}")),
            "origin {origin:?}: {head}"
        );
    }
    assert_eq!(server.ws_stats().origin_denied, 2);
    server.shutdown().await.unwrap();
}
