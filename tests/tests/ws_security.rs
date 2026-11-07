//! WebSocket handshake security over real TCP (Phase 2, P2.1 Origin enforcement).
//!
//! Raw HTTP/1.1 requests are used so that malformed and adversarial handshakes can be
//! expressed exactly. Every denial must happen before `101 Switching Protocols`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use poring::prelude::*;
use poring::ws::WebSocketUpgrade;
use poring_tests::secure::TableAuth;
use poring_tests::status_of;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

/// Counts sessions that actually started (the upgrade completed and the handler ran).
#[derive(Clone, Default)]
struct Started(Arc<AtomicUsize>);

fn ws_handler(
    started: Started,
) -> impl Fn(WebSocketUpgrade) -> std::future::Ready<Response> + Clone + Send + Sync + 'static {
    move |ws: WebSocketUpgrade| {
        let started = started.clone();
        std::future::ready(ws.on_upgrade(move |_sock| async move {
            started.0.fetch_add(1, Ordering::SeqCst);
        }))
    }
}

/// Sends a raw request and returns the response head (up to the blank line).
async fn handshake(addr: SocketAddr, request: String) -> String {
    let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
    s.write_all(request.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let read = async {
        loop {
            let n = s.read(&mut chunk).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(3), read).await;
    String::from_utf8_lossy(&buf).into_owned()
}

/// A handshake request for `path` with `extra` header lines (each ending in `\r\n`).
fn ws_request(addr: SocketAddr, path: &str, extra: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {KEY}\r\n{extra}\r\n"
    )
}

fn has_header(head: &str, name: &str) -> bool {
    head.lines().any(|l| {
        l.split_once(':')
            .is_some_and(|(n, _)| n.trim().eq_ignore_ascii_case(name))
    })
}

/// An app without CORS: the WebSocket default is same-origin.
async fn plain_app(started: Started) -> poring::Server {
    Poring::new()
        .get("/ws", ws_handler(started))
        .get("/data", || async { "data" })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap()
}

/// An app with explicit CORS origins and a cookie-capable authenticator; `/ws` requires
/// authentication.
async fn cookie_app(started: Started) -> poring::Server {
    Poring::new()
        .authenticator(TableAuth::fixture())
        .cors(
            Cors::new()
                .origins(["https://app.example"])
                .credentials(true),
        )
        .route_with(
            RouteMethod::Get,
            "/ws",
            Policy::new().authenticated(),
            ws_handler(started),
        )
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

#[tokio::test]
async fn same_origin_and_originless_handshakes_upgrade() {
    let started = Started::default();
    let server = plain_app(started.clone()).await;
    let addr = server.local_addr();

    let head = handshake(addr, ws_request(addr, "/ws", "")).await;
    assert_eq!(
        status_of(&head),
        101,
        "no Origin (non-browser client): {head}"
    );

    let head = handshake(
        addr,
        ws_request(addr, "/ws", &format!("Origin: http://{addr}\r\n")),
    )
    .await;
    assert_eq!(status_of(&head), 101, "same origin: {head}");

    // Scheme/host comparison is ASCII case-insensitive.
    let head = handshake(
        addr,
        ws_request(addr, "/ws", &format!("Origin: HTTP://{addr}\r\n")),
    )
    .await;
    assert_eq!(
        status_of(&head),
        101,
        "same origin, upper-case scheme: {head}"
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(started.0.load(Ordering::SeqCst), 3);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn cross_origin_handshake_is_rejected_without_cors() {
    let started = Started::default();
    let server = plain_app(started.clone()).await;
    let addr = server.local_addr();

    let port = addr.port();
    let hostile = [
        "Origin: https://evil.example\r\n".to_owned(),
        // Same host, different port.
        format!("Origin: http://127.0.0.1:{}\r\n", port.wrapping_add(1)),
        // Opaque origin (sandboxed iframe, file://).
        "Origin: null\r\n".to_owned(),
        // Malformed values.
        "Origin: not a url\r\n".to_owned(),
        format!("Origin: http://{addr}/path\r\n"),
        format!("Origin: ftp://{addr}\r\n"),
        "Origin: \r\n".to_owned(),
        // Duplicate Origin headers, even if one matches.
        format!("Origin: http://{addr}\r\nOrigin: https://evil.example\r\n"),
        format!("Origin: http://{addr}\r\nOrigin: http://{addr}\r\n"),
    ];
    for origin in &hostile {
        let head = handshake(addr, ws_request(addr, "/ws", origin)).await;
        assert_eq!(status_of(&head), 403, "{origin:?} => {head}");
        assert!(
            head.contains("ws_origin_denied") || !head.contains("101"),
            "{head}"
        );
        assert!(
            !has_header(&head, "sec-websocket-accept"),
            "{origin:?} => {head}"
        );
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(started.0.load(Ordering::SeqCst), 0, "no session may start");
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn cookie_authenticated_cross_site_handshake_is_rejected() {
    let started = Started::default();
    let server = cookie_app(started.clone()).await;
    let addr = server.local_addr();
    let cookie = "Cookie: sid=session-bob\r\n";

    // H1 reproduction: a hostile page carrying the victim's session cookie.
    let head = handshake(
        addr,
        ws_request(
            addr,
            "/ws",
            &format!("Origin: https://evil.example\r\n{cookie}"),
        ),
    )
    .await;
    assert_eq!(status_of(&head), 403, "CSWSH must be denied: {head}");

    // Allowed origin, valid session: upgrades.
    let head = handshake(
        addr,
        ws_request(
            addr,
            "/ws",
            &format!("Origin: https://app.example\r\n{cookie}"),
        ),
    )
    .await;
    assert_eq!(status_of(&head), 101, "{head}");

    // Allowed origin without credentials: authentication still runs.
    let head = handshake(
        addr,
        ws_request(addr, "/ws", "Origin: https://app.example\r\n"),
    )
    .await;
    assert_eq!(status_of(&head), 401, "{head}");

    // Same origin is also accepted when CORS is configured.
    let head = handshake(
        addr,
        ws_request(addr, "/ws", &format!("Origin: http://{addr}\r\n{cookie}")),
    )
    .await;
    assert_eq!(status_of(&head), 101, "{head}");

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(started.0.load(Ordering::SeqCst), 2);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn wildcard_cors_does_not_open_websockets_to_every_origin() {
    let started = Started::default();
    let server = Poring::new()
        .cors(Cors::new().origins(["*"]))
        .get("/ws", ws_handler(started.clone()))
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    let head = handshake(
        addr,
        ws_request(addr, "/ws", "Origin: https://evil.example\r\n"),
    )
    .await;
    assert_eq!(status_of(&head), 403, "{head}");
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn http_cors_semantics_for_plain_get_are_unchanged() {
    let started = Started::default();
    let server = cookie_app(started).await;
    let addr = server.local_addr();
    // A non-upgrade GET from a disallowed origin is still served (CORS only withholds the
    // Access-Control headers); only unsafe methods are rejected.
    let req = format!(
        "GET /data HTTP/1.1\r\nHost: {addr}\r\nOrigin: https://evil.example\r\nConnection: close\r\n\r\n"
    );
    let head = handshake(addr, req).await;
    assert_eq!(status_of(&head), 200, "{head}");
    assert!(!has_header(&head, "access-control-allow-origin"), "{head}");

    let server2 = plain_app(Started::default()).await;
    let addr2 = server2.local_addr();
    let req = format!(
        "GET /data HTTP/1.1\r\nHost: {addr2}\r\nOrigin: https://evil.example\r\nConnection: close\r\n\r\n"
    );
    assert_eq!(status_of(&handshake(addr2, req).await), 200);
    server.shutdown().await.unwrap();
    server2.shutdown().await.unwrap();
}

// ---- P2.2: RFC 6455 §4.2.1 handshake strictness -------------------------------------

/// A handshake with explicit header lines (no defaults besides Host/Connection/Upgrade).
fn raw_ws(addr: SocketAddr, version: &str, headers: &str) -> String {
    format!(
        "GET /ws {version}\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n{headers}\r\n"
    )
}

fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| {
        l.split_once(':')
            .filter(|(n, _)| n.trim().eq_ignore_ascii_case(name))
            .map(|(_, v)| v.trim())
    })
}

#[tokio::test]
async fn valid_handshake_returns_rfc_accept_key() {
    let started = Started::default();
    let server = plain_app(started.clone()).await;
    let addr = server.local_addr();
    let head = handshake(addr, ws_request(addr, "/ws", "")).await;
    assert_eq!(status_of(&head), 101, "{head}");
    // RFC 6455 §1.3 sample nonce/accept pair.
    assert_eq!(
        header_value(&head, "sec-websocket-accept"),
        Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn malformed_keys_are_rejected_before_upgrade() {
    let started = Started::default();
    let server = plain_app(started.clone()).await;
    let addr = server.local_addr();
    let v13 = "Sec-WebSocket-Version: 13\r\n";
    let bad = [
        // Missing key.
        String::new(),
        "Sec-WebSocket-Key: \r\n".to_owned(),
        "Sec-WebSocket-Key: abc\r\n".to_owned(),
        // Valid base64 of 15 and 17 bytes.
        "Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAA\r\n".to_owned(),
        "Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAAA=\r\n".to_owned(),
        // Not base64.
        "Sec-WebSocket-Key: !!!!!!!!!!!!!!!!!!!!!!==\r\n".to_owned(),
        // URL-safe alphabet is not the base64 alphabet RFC 6455 uses.
        "Sec-WebSocket-Key: ________________-_____==\r\n".to_owned(),
        // Non-canonical trailing bits (decodes to 16 bytes only if ignored).
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZR==\r\n".to_owned(),
        // Missing padding.
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ\r\n".to_owned(),
        // Two keys, both individually valid.
        format!("Sec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n"),
        // Two keys folded into one comma list.
        format!("Sec-WebSocket-Key: {KEY}, {KEY}\r\n"),
    ];
    for key in &bad {
        let head = handshake(addr, raw_ws(addr, "HTTP/1.1", &format!("{v13}{key}"))).await;
        assert_eq!(status_of(&head), 400, "{key:?} => {head}");
        assert!(
            !has_header(&head, "sec-websocket-accept"),
            "{key:?} => {head}"
        );
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(started.0.load(Ordering::SeqCst), 0);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn version_negotiation_follows_rfc6455() {
    let started = Started::default();
    let server = plain_app(started.clone()).await;
    let addr = server.local_addr();
    let key = format!("Sec-WebSocket-Key: {KEY}\r\n");

    // Unsupported version: 426 advertising the supported version (RFC 6455 §4.4).
    for v in ["8", "14", "13, 8", "abc"] {
        let head = handshake(
            addr,
            raw_ws(
                addr,
                "HTTP/1.1",
                &format!("Sec-WebSocket-Version: {v}\r\n{key}"),
            ),
        )
        .await;
        assert_eq!(status_of(&head), 426, "{v} => {head}");
        assert_eq!(
            header_value(&head, "sec-websocket-version"),
            Some("13"),
            "{head}"
        );
        assert!(!has_header(&head, "sec-websocket-accept"), "{head}");
    }
    // Missing or duplicated version: malformed request.
    for v in [
        String::new(),
        "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Version: 13\r\n".to_owned(),
    ] {
        let head = handshake(addr, raw_ws(addr, "HTTP/1.1", &format!("{v}{key}"))).await;
        assert_eq!(status_of(&head), 400, "{v:?} => {head}");
        assert_eq!(
            header_value(&head, "sec-websocket-version"),
            Some("13"),
            "{head}"
        );
    }
    // Whitespace around the value is not significant.
    let head = handshake(
        addr,
        raw_ws(
            addr,
            "HTTP/1.1",
            &format!("Sec-WebSocket-Version:  13 \r\n{key}"),
        ),
    )
    .await;
    assert_eq!(status_of(&head), 101, "{head}");
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn non_http11_and_non_get_handshakes_are_rejected() {
    let started = Started::default();
    let server = plain_app(started.clone()).await;
    let addr = server.local_addr();
    let hdrs = format!("Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {KEY}\r\n");

    let head = handshake(addr, raw_ws(addr, "HTTP/1.0", &hdrs)).await;
    assert_ne!(status_of(&head), 101, "HTTP/1.0: {head}");
    assert!(!has_header(&head, "sec-websocket-accept"), "{head}");

    let post = format!(
        "POST /ws HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n{hdrs}Content-Length: 0\r\n\r\n"
    );
    let head = handshake(addr, post).await;
    assert_ne!(status_of(&head), 101, "POST: {head}");

    // Missing Upgrade / Connection tokens.
    let no_upgrade =
        format!("GET /ws HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\n{hdrs}\r\n");
    assert_eq!(status_of(&handshake(addr, no_upgrade).await), 400);
    let no_conn = format!("GET /ws HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\n{hdrs}\r\n");
    assert_eq!(status_of(&handshake(addr, no_conn).await), 400);
    // Token lists are parsed, not compared whole.
    let listed = format!(
        "GET /ws HTTP/1.1\r\nHost: {addr}\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n{hdrs}\r\n"
    );
    assert_eq!(status_of(&handshake(addr, listed).await), 101);

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(started.0.load(Ordering::SeqCst), 1);
    server.shutdown().await.unwrap();
}

// ---- P2.3: subprotocol negotiation (RFC 6455 §4.2.2 item 5.4, §11.3.4) ----------------

use std::sync::Mutex;

#[derive(Debug, serde::Deserialize, serde::Serialize, PoringSchema)]
struct TypedMsg {
    text: String,
}

/// Records the protocol each handler saw (`None` = no protocol selected).
#[derive(Clone, Default)]
struct Seen(Arc<Mutex<Vec<Option<String>>>>);

async fn proto_app(seen: Seen) -> poring::Server {
    let optional = seen.clone();
    let required = seen.clone();
    let typed = seen.clone();
    Poring::new()
        .get("/ws", ws_handler(Started::default()))
        .get("/proto", move |ws: WebSocketUpgrade| {
            let seen = optional.clone();
            async move {
                let ws = ws.protocols(["chat.v2", "chat.v1"]);
                seen.0
                    .lock()
                    .unwrap()
                    .push(ws.protocol().map(str::to_owned));
                ws.on_upgrade(|_sock| async {})
            }
        })
        .get("/proto-required", move |ws: WebSocketUpgrade| {
            let seen = required.clone();
            async move {
                let ws = ws.protocols(["chat.v1"]).require_protocol();
                seen.0
                    .lock()
                    .unwrap()
                    .push(ws.protocol().map(str::to_owned));
                ws.on_upgrade(|_sock| async {})
            }
        })
        .get("/proto-typed", move |ws: WebSocketUpgrade| {
            let seen = typed.clone();
            async move {
                let ws = ws.protocols(["json.v1"]).typed::<TypedMsg, TypedMsg>();
                seen.0
                    .lock()
                    .unwrap()
                    .push(ws.protocol().map(str::to_owned));
                ws.on_upgrade(|_sock| async {})
            }
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap()
}

fn proto_request(addr: SocketAddr, path: &str, protocols: &str) -> String {
    ws_request(addr, path, protocols)
}

#[tokio::test]
async fn subprotocol_is_selected_by_server_preference_from_offered_list() {
    let seen = Seen::default();
    let server = proto_app(seen.clone()).await;
    let addr = server.local_addr();

    let head = handshake(
        addr,
        proto_request(
            addr,
            "/proto",
            "Sec-WebSocket-Protocol: chat.v1, chat.v2\r\n",
        ),
    )
    .await;
    assert_eq!(status_of(&head), 101, "{head}");
    assert_eq!(
        header_value(&head, "sec-websocket-protocol"),
        Some("chat.v2")
    );

    // Several header lines form one list.
    let head = handshake(
        addr,
        proto_request(
            addr,
            "/proto",
            "Sec-WebSocket-Protocol: other\r\nSec-WebSocket-Protocol: chat.v1\r\n",
        ),
    )
    .await;
    assert_eq!(status_of(&head), 101, "{head}");
    assert_eq!(
        header_value(&head, "sec-websocket-protocol"),
        Some("chat.v1")
    );

    // Matching is exact (case-sensitive).
    let head = handshake(
        addr,
        proto_request(addr, "/proto", "Sec-WebSocket-Protocol: CHAT.V1\r\n"),
    )
    .await;
    assert_eq!(status_of(&head), 101, "{head}");
    assert!(!has_header(&head, "sec-websocket-protocol"), "{head}");

    // Nothing in common: optional negotiation proceeds without a protocol.
    let head = handshake(
        addr,
        proto_request(addr, "/proto", "Sec-WebSocket-Protocol: other\r\n"),
    )
    .await;
    assert_eq!(status_of(&head), 101, "{head}");
    assert!(!has_header(&head, "sec-websocket-protocol"), "{head}");

    // No offer at all.
    let head = handshake(addr, proto_request(addr, "/proto", "")).await;
    assert_eq!(status_of(&head), 101, "{head}");
    assert!(!has_header(&head, "sec-websocket-protocol"), "{head}");

    assert_eq!(
        *seen.0.lock().unwrap(),
        vec![
            Some("chat.v2".to_owned()),
            Some("chat.v1".to_owned()),
            None,
            None,
            None
        ]
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn unconfigured_routes_never_echo_an_offered_protocol() {
    let server = proto_app(Seen::default()).await;
    let addr = server.local_addr();
    let head = handshake(
        addr,
        proto_request(addr, "/ws", "Sec-WebSocket-Protocol: chat.v1\r\n"),
    )
    .await;
    assert_eq!(status_of(&head), 101, "{head}");
    assert!(!has_header(&head, "sec-websocket-protocol"), "{head}");
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn required_subprotocol_rejects_before_upgrade() {
    let server = proto_app(Seen::default()).await;
    let addr = server.local_addr();
    for offer in ["", "Sec-WebSocket-Protocol: other\r\n"] {
        let head = handshake(addr, proto_request(addr, "/proto-required", offer)).await;
        assert_eq!(status_of(&head), 400, "{offer:?} => {head}");
        assert!(!has_header(&head, "sec-websocket-accept"), "{head}");
    }
    let head = handshake(
        addr,
        proto_request(
            addr,
            "/proto-required",
            "Sec-WebSocket-Protocol: chat.v1\r\n",
        ),
    )
    .await;
    assert_eq!(status_of(&head), 101, "{head}");
    assert_eq!(
        header_value(&head, "sec-websocket-protocol"),
        Some("chat.v1")
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn malformed_protocol_offers_are_rejected() {
    let server = proto_app(Seen::default()).await;
    let addr = server.local_addr();
    let bad = [
        "Sec-WebSocket-Protocol: \r\n",
        "Sec-WebSocket-Protocol: chat.v1,,chat.v2\r\n",
        "Sec-WebSocket-Protocol: chat.v1,\r\n",
        "Sec-WebSocket-Protocol: chat v1\r\n",
        "Sec-WebSocket-Protocol: chat@v1\r\n",
        "Sec-WebSocket-Protocol: \"chat.v1\"\r\n",
        "Sec-WebSocket-Protocol: chat.v1, chat.v1\r\n",
        "Sec-WebSocket-Protocol: chat.v1\r\nSec-WebSocket-Protocol: chat.v1\r\n",
    ];
    // Rejected even on routes that do not negotiate protocols.
    for path in ["/proto", "/ws"] {
        for offer in bad {
            let head = handshake(addr, proto_request(addr, path, offer)).await;
            assert_eq!(status_of(&head), 400, "{path} {offer:?} => {head}");
            assert!(!has_header(&head, "sec-websocket-accept"), "{head}");
        }
    }
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn typed_upgrade_negotiates_like_raw() {
    let seen = Seen::default();
    let server = proto_app(seen.clone()).await;
    let addr = server.local_addr();
    let head = handshake(
        addr,
        proto_request(addr, "/proto-typed", "Sec-WebSocket-Protocol: json.v1\r\n"),
    )
    .await;
    assert_eq!(status_of(&head), 101, "{head}");
    assert_eq!(
        header_value(&head, "sec-websocket-protocol"),
        Some("json.v1")
    );
    assert_eq!(*seen.0.lock().unwrap(), vec![Some("json.v1".to_owned())]);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn tungstenite_client_accepts_negotiated_protocol() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let server = proto_app(Seen::default()).await;
    let addr = server.local_addr();
    let mut req = format!("ws://{addr}/proto").into_client_request().unwrap();
    req.headers_mut()
        .insert("sec-websocket-protocol", "chat.v1".parse().unwrap());
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (_ws, resp) = tokio_tungstenite::client_async(req, tcp).await.unwrap();
    assert_eq!(resp.status(), 101);
    assert_eq!(
        resp.headers().get("sec-websocket-protocol").unwrap(),
        "chat.v1"
    );
    server.shutdown().await.unwrap();
}

// ---- P2.4: property tests over real TCP -----------------------------------------------
//
// Each property compares the server's status with an independent oracle written from the
// RFC text (not by calling Poring's helpers), and checks that no input yields 5xx or a
// dead server.

mod props {
    use super::*;
    use proptest::prelude::*;
    use std::sync::OnceLock;

    /// One shared server per test binary (the runtime outlives every proptest case).
    fn server() -> &'static (tokio::runtime::Runtime, SocketAddr) {
        static S: OnceLock<(tokio::runtime::Runtime, SocketAddr)> = OnceLock::new();
        S.get_or_init(|| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            let addr = rt.block_on(async {
                let server = plain_app(Started::default()).await;
                let addr = server.local_addr();
                // Keep serving for the life of the process.
                std::mem::forget(server);
                addr
            });
            (rt, addr)
        })
    }

    fn status(request: String) -> u16 {
        let (rt, addr) = server();
        let head = rt.block_on(handshake(*addr, request));
        let s = status_of(&head);
        assert!(s != 0 && s < 500, "server failed: {head:?}");
        s
    }

    fn request(addr: SocketAddr, version: &str, key: &str, extra: &str) -> String {
        format!(
            "GET /ws HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
             Sec-WebSocket-Version: {version}\r\nSec-WebSocket-Key: {key}\r\n{extra}\r\n"
        )
    }

    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// RFC 6455 §4.2.1 item 5 / RFC 4648 §4: 16 bytes => 22 symbols + "==", and the last
    /// symbol's low 4 bits must be zero (canonical encoding).
    fn key_oracle(k: &str) -> bool {
        let b = k.as_bytes();
        b.len() == 24
            && b[22..] == *b"=="
            && b[..22].iter().all(|c| B64.contains(c))
            && B64.iter().position(|c| *c == b[21]).unwrap() % 16 == 0
    }

    /// RFC 7230 token list, unique elements, optional whitespace around elements.
    fn protocols_oracle(v: &str) -> bool {
        let tchar = |c: u8| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c);
        let mut seen = Vec::new();
        for item in v.split(',') {
            let item = item.trim_matches([' ', '\t']);
            if item.is_empty() || !item.bytes().all(tchar) || seen.contains(&item) {
                return false;
            }
            seen.push(item);
        }
        true
    }

    /// Header-safe printable ASCII (hyper trims surrounding whitespace itself).
    fn header_text() -> impl Strategy<Value = String> {
        "[!-~]([ -~]{0,30}[!-~])?"
    }

    fn base64ish() -> impl Strategy<Value = String> {
        prop_oneof![
            "[A-Za-z0-9+/]{21}[AQgw]==",
            "[A-Za-z0-9+/=_-]{20,28}",
            header_text(),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        #[test]
        fn key_accepted_iff_canonical_16_byte_base64(key in base64ish()) {
            let addr = server().1;
            let s = status(request(addr, "13", &key, ""));
            prop_assert_eq!(s == 101, key_oracle(&key), "key {:?} => {}", key, s);
            prop_assert!(s == 101 || s == 400, "key {:?} => {}", key, s);
        }

        #[test]
        fn version_accepted_iff_13(v in prop_oneof![Just("13".to_owned()), "1[0-9]", header_text()]) {
            let addr = server().1;
            let s = status(request(addr, &v, KEY, ""));
            let expected = if v.trim() == "13" { 101 } else { 426 };
            prop_assert_eq!(s, expected, "version {:?}", v);
        }

        #[test]
        fn protocol_offer_accepted_iff_valid_token_list(
            v in prop_oneof!["[a-z.]{1,6}(, ?[a-z.]{1,6}){0,3}", "[ -~]{1,24}"]
        ) {
            // Leading/trailing whitespace is stripped by hyper before Poring sees it.
            let v = v.trim().to_owned();
            prop_assume!(!v.is_empty());
            let addr = server().1;
            let s = status(request(addr, "13", KEY, &format!("Sec-WebSocket-Protocol: {v}\r\n")));
            prop_assert_eq!(s == 101, protocols_oracle(&v), "offer {:?} => {}", v, s);
            prop_assert!(s == 101 || s == 400, "offer {:?} => {}", v, s);
        }

        #[test]
        fn foreign_origins_never_upgrade(origin in prop_oneof![
            "https?://[a-z0-9.-]{1,20}(:[0-9]{1,5})?",
            header_text(),
        ]) {
            let addr = server().1;
            let s = status(request(addr, "13", KEY, &format!("Origin: {origin}\r\n")));
            let same = origin.eq_ignore_ascii_case(&format!("http://{addr}"));
            prop_assert_eq!(s == 101, same, "origin {:?} => {}", origin, s);
            prop_assert!(s == 101 || s == 403, "origin {:?} => {}", origin, s);
        }
    }

    #[test]
    fn oracles_agree_with_known_vectors() {
        assert!(key_oracle(KEY));
        assert!(!key_oracle("dGhlIHNhbXBsZSBub25jZR=="));
        assert!(protocols_oracle("a, b.c"));
        assert!(!protocols_oracle("a,,b"));
        assert!(!protocols_oracle("a, a"));
    }
}

// ---- P2.1 follow-up 1 (ADR-011): dedicated WebSocket origin configuration --------------

use poring::policy::WsOrigins;

#[tokio::test]
async fn ws_origins_allowlist_extends_same_origin() {
    let started = Started::default();
    let server = Poring::new()
        .ws_origins(WsOrigins::new().allow(["https://partner.example", "http://LOCALHOST:8080"]))
        .get("/ws", ws_handler(started.clone()))
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    for (origin, expected) in [
        ("https://partner.example".to_owned(), 101),
        // Normalised: scheme/host case and the scheme's default port.
        ("HTTPS://Partner.Example:443".to_owned(), 101),
        ("http://localhost:8080".to_owned(), 101),
        (format!("http://{addr}"), 101),
        ("http://partner.example".to_owned(), 403),
        ("https://partner.example:8443".to_owned(), 403),
        ("https://evil.example".to_owned(), 403),
        ("null".to_owned(), 403),
    ] {
        let head = handshake(
            addr,
            ws_request(addr, "/ws", &format!("Origin: {origin}\r\n")),
        )
        .await;
        assert_eq!(status_of(&head), expected, "{origin} => {head}");
    }
    // Plain GET CORS is not affected by WS origins.
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn ws_origins_any_disables_the_check_without_cookie_auth() {
    let server = Poring::new()
        .ws_origins(WsOrigins::any())
        .get("/ws", ws_handler(Started::default()))
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    for origin in ["https://evil.example", "null"] {
        let head = handshake(
            addr,
            ws_request(addr, "/ws", &format!("Origin: {origin}\r\n")),
        )
        .await;
        assert_eq!(status_of(&head), 101, "{origin} => {head}");
    }
    server.shutdown().await.unwrap();
}

#[test]
fn ws_origins_any_is_refused_with_cookie_authentication() {
    let err = Poring::new()
        .authenticator(TableAuth::fixture())
        .ws_origins(WsOrigins::any())
        .get("/ws", ws_handler(Started::default()))
        .build()
        .unwrap_err()
        .to_string();
    assert!(err.contains("ws_origins"), "{err}");
}

#[test]
fn invalid_ws_origins_are_reported_by_build() {
    for bad in [
        "*",
        "https://a.example/path",
        "ftp://a.example",
        "a.example",
        "https://",
        "null",
    ] {
        let r = Poring::new()
            .ws_origins(WsOrigins::new().allow([bad]))
            .get("/ws", ws_handler(Started::default()))
            .build();
        let err = r.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(err.contains("ws_origins"), "{bad:?} accepted: {err}");
    }
}

#[poring::ws("/macro-ws")]
async fn macro_ws(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(|_sock| async {})
}

poring_app! {
    MacroWsApp {
        routes: [macro_ws],
    }
}

#[tokio::test]
async fn macro_builder_accepts_ws_origins() {
    let server = MacroWsApp::builder()
        .ws_origins(WsOrigins::new().allow(["https://partner.example"]))
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    let ok = handshake(
        addr,
        ws_request(addr, "/macro-ws", "Origin: https://partner.example\r\n"),
    )
    .await;
    assert_eq!(status_of(&ok), 101, "{ok}");
    let bad = handshake(
        addr,
        ws_request(addr, "/macro-ws", "Origin: https://evil.example\r\n"),
    )
    .await;
    assert_eq!(status_of(&bad), 403, "{bad}");
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn ws_origins_survive_later_state_and_authenticator_calls() {
    let server = Poring::new()
        .ws_origins(WsOrigins::new().allow(["https://partner.example"]))
        .state(Started::default())
        .authenticator(TableAuth::fixture())
        .route_with(
            RouteMethod::Get,
            "/ws",
            Policy::new().public(),
            |ws: WebSocketUpgrade| async move { ws.on_upgrade(|_sock| async {}) },
        )
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    let head = handshake(
        addr,
        ws_request(addr, "/ws", "Origin: https://partner.example\r\n"),
    )
    .await;
    assert_eq!(status_of(&head), 101, "{head}");
    server.shutdown().await.unwrap();
}

// ---- P2.1a (per-route): `Policy::ws_origins` and `policy(ws_origins = ..)` -------------

async fn origin_status(addr: SocketAddr, path: &str, origin: &str) -> u16 {
    status_of(
        &handshake(
            addr,
            ws_request(addr, path, &format!("Origin: {origin}\r\n")),
        )
        .await,
    )
}

#[tokio::test]
async fn route_and_group_ws_origins_override_the_app_default() {
    let partner = || WsOrigins::new().allow(["https://partner.example"]);
    let server = Poring::new()
        .ws_origins(WsOrigins::new().allow(["https://app-wide.example"]))
        .get("/ws", ws_handler(Started::default()))
        .route_with(
            RouteMethod::Get,
            "/partner",
            Policy::new().ws_origins(partner()),
            ws_handler(Started::default()),
        )
        .route_with(
            RouteMethod::Get,
            "/open",
            Policy::new().ws_origins(WsOrigins::any()),
            ws_handler(Started::default()),
        )
        .group("/g", |g| {
            g.policy(Policy::new().ws_origins(partner()))
                .get("/inherits", ws_handler(Started::default()))
                .route_with(
                    RouteMethod::Get,
                    "/overrides",
                    Policy::new().ws_origins(WsOrigins::new()),
                    ws_handler(Started::default()),
                )
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    let same = format!("http://{addr}");
    let cases = [
        // App default list.
        ("/ws", "https://app-wide.example", 101),
        ("/ws", "https://partner.example", 403),
        // Route list replaces the app list; same-origin is always allowed.
        ("/partner", "https://partner.example", 101),
        ("/partner", "https://app-wide.example", 403),
        ("/partner", same.as_str(), 101),
        // Route opt-out.
        ("/open", "https://evil.example", 101),
        // Group level is inherited, and a route can override it.
        ("/g/inherits", "https://partner.example", 101),
        ("/g/inherits", "https://evil.example", 403),
        ("/g/overrides", "https://partner.example", 403),
        ("/g/overrides", same.as_str(), 101),
        // Unknown paths are not affected by any route's opt-out (routing runs first: 404).
        ("/nope", "https://evil.example", 404),
    ];
    for (path, origin, expected) in cases {
        assert_eq!(
            origin_status(addr, path, origin).await,
            expected,
            "{path} {origin}"
        );
    }
    server.shutdown().await.unwrap();
}

#[test]
fn route_ws_origins_are_validated_by_build() {
    let any_with_cookies = Poring::new()
        .authenticator(TableAuth::fixture())
        .route_with(
            RouteMethod::Get,
            "/ws",
            Policy::new().public().ws_origins(WsOrigins::any()),
            ws_handler(Started::default()),
        )
        .build()
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(
        any_with_cookies.contains("ws_origins"),
        "{any_with_cookies}"
    );

    let bad_entry = Poring::new()
        .group("/g", |g| {
            g.policy(Policy::new().ws_origins(WsOrigins::new().allow(["*"])))
                .get("/ws", ws_handler(Started::default()))
        })
        .build()
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(bad_entry.contains("ws_origins"), "{bad_entry}");
}

#[poring::ws("/m/partner", policy(ws_origins = ["https://partner.example"]))]
async fn macro_partner(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(|_sock| async {})
}

#[poring::ws("/m/open", policy(ws_origins = any))]
async fn macro_open(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(|_sock| async {})
}

#[poring::ws("/m/default")]
async fn macro_default(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(|_sock| async {})
}

poring_app! {
    MacroRouteOrigins {
        routes: [macro_partner, macro_open, macro_default],
    }
}

#[tokio::test]
async fn macro_routes_declare_ws_origins_in_policy() {
    let server = MacroRouteOrigins::builder()
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    assert_eq!(
        origin_status(addr, "/m/partner", "https://partner.example").await,
        101
    );
    assert_eq!(
        origin_status(addr, "/m/partner", "https://evil.example").await,
        403
    );
    assert_eq!(
        origin_status(addr, "/m/open", "https://evil.example").await,
        101
    );
    assert_eq!(
        origin_status(addr, "/m/default", "https://partner.example").await,
        403
    );
    // The resolved policy is visible to tooling.
    let m = MacroRouteOrigins::builder().build().unwrap().manifest();
    let json = serde_json::to_string(&m).unwrap();
    assert!(json.contains("https://partner.example"), "{json}");
    server.shutdown().await.unwrap();
}

#[poring::ws("/m/open-cookie", policy(public, ws_origins = any))]
async fn macro_open_cookie(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(|_sock| async {})
}

poring_app! {
    MacroCookieAny {
        auth: TableAuth,
        routes: [macro_open_cookie],
    }
}

#[test]
fn macro_ws_origins_any_is_refused_with_cookie_authentication() {
    let err = MacroCookieAny::builder()
        .authenticator(TableAuth::fixture())
        .build()
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(err.contains("ws_origins"), "{err}");
}

// ---- P2.1b: public host from trusted reverse proxies -----------------------------------

/// A handshake with an explicit `Host` and extra header lines.
fn proxied(host: &str, extra: &str) -> String {
    format!(
        "GET /ws HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {KEY}\r\n{extra}\r\n"
    )
}

async fn proxy_app(trusted: &[&str]) -> poring::Server {
    Poring::new()
        .trusted_proxies(trusted.iter().copied())
        .get("/ws", ws_handler(Started::default()))
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap()
}

#[tokio::test]
async fn trusted_proxy_forwarded_host_counts_as_same_origin() {
    // The test client connects from 127.0.0.1, which is trusted here.
    let server = proxy_app(&["127.0.0.1"]).await;
    let addr = server.local_addr();
    let cases = [
        // X-Forwarded-Host / -Proto.
        (
            "X-Forwarded-Host: public.example\r\nX-Forwarded-Proto: https\r\nOrigin: https://public.example\r\n",
            101,
        ),
        (
            "X-Forwarded-Host: public.example\r\nOrigin: https://public.example\r\n",
            101,
        ),
        (
            "X-Forwarded-Host: PUBLIC.example\r\nX-Forwarded-Proto: HTTPS\r\nOrigin: https://public.example\r\n",
            101,
        ),
        (
            "X-Forwarded-Host: public.example:8443\r\nOrigin: https://public.example:8443\r\n",
            101,
        ),
        // The forwarded scheme must match the origin's scheme.
        (
            "X-Forwarded-Host: public.example\r\nX-Forwarded-Proto: http\r\nOrigin: https://public.example\r\n",
            403,
        ),
        (
            "X-Forwarded-Host: public.example:8443\r\nOrigin: https://public.example\r\n",
            403,
        ),
        // Ambiguous or malformed forwarded hosts are ignored (fall back to Host).
        (
            "X-Forwarded-Host: evil.example, public.example\r\nOrigin: https://public.example\r\n",
            403,
        ),
        (
            "X-Forwarded-Host: public.example\r\nX-Forwarded-Host: public.example\r\nOrigin: https://public.example\r\n",
            403,
        ),
        (
            "X-Forwarded-Host: public.example/x\r\nOrigin: https://public.example\r\n",
            403,
        ),
        (
            "X-Forwarded-Host: public.example\r\nX-Forwarded-Proto: ftp\r\nOrigin: https://public.example\r\n",
            403,
        ),
        // RFC 7239 Forwarded (single element; quoted values allowed).
        (
            "Forwarded: for=192.0.2.1;host=public.example;proto=https\r\nOrigin: https://public.example\r\n",
            101,
        ),
        (
            "Forwarded: host=\"public.example:8443\"\r\nOrigin: https://public.example:8443\r\n",
            101,
        ),
        (
            "Forwarded: host=public.example;proto=http\r\nOrigin: https://public.example\r\n",
            403,
        ),
        (
            "Forwarded: host=evil.example, host=public.example\r\nOrigin: https://public.example\r\n",
            403,
        ),
        // `Forwarded` takes precedence over X-Forwarded-* when both are present.
        (
            "Forwarded: host=public.example\r\nX-Forwarded-Host: other.example\r\nOrigin: https://other.example\r\n",
            403,
        ),
        // The proxy's own Host stays a valid same-origin target.
        (
            "X-Forwarded-Host: public.example\r\nOrigin: http://internal:8080\r\n",
            101,
        ),
        // A foreign origin is still foreign.
        (
            "X-Forwarded-Host: public.example\r\nOrigin: https://evil.example\r\n",
            403,
        ),
    ];
    for (extra, expected) in cases {
        let head = handshake(addr, proxied("internal:8080", extra)).await;
        assert_eq!(status_of(&head), expected, "{extra:?} => {head}");
    }
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn forwarded_host_from_untrusted_peers_is_ignored() {
    for trusted in [&[][..], &["10.0.0.0/8"][..]] {
        let server = proxy_app(trusted).await;
        let addr = server.local_addr();
        for extra in [
            "X-Forwarded-Host: evil.example\r\nOrigin: https://evil.example\r\n",
            "Forwarded: host=evil.example\r\nOrigin: https://evil.example\r\n",
        ] {
            let head = handshake(addr, proxied("internal:8080", extra)).await;
            assert_eq!(status_of(&head), 403, "{trusted:?} {extra:?} => {head}");
        }
        server.shutdown().await.unwrap();
    }
}

// ---- P2.1c: the WebSocket origin check in static contracts and runtime traces ---------

mod contract {
    use super::*;
    #[cfg(feature = "trace-flow")]
    use poring::contract::RuntimeTrace;
    use poring::contract::build_graph;
    use poring::flow::FlowConfig;
    use std::collections::BTreeSet;

    fn app() -> poring::FluentApp<Started> {
        Poring::with_state(Started::default())
            .flow_recording(FlowConfig {
                sample_every: 1,
                capacity: 64,
            })
            .get("/ws", ws_handler(Started::default()))
            .get("/data", || async { "data" })
            .build()
            .unwrap()
    }

    #[cfg(feature = "trace-flow")]
    fn assert_trace_follows_graph(app: &poring::FluentApp<Started>, t: &RuntimeTrace) {
        let g = build_graph(&app.manifest(), None).unwrap();
        let nodes: BTreeSet<&str> = g.nodes.iter().map(|n| n.id.as_str()).collect();
        let edges: BTreeSet<(String, String)> = g
            .edges
            .iter()
            .map(|e| (e.from.clone(), e.to.clone()))
            .collect();
        for s in &t.steps {
            assert!(
                nodes.contains(s.node.as_str()),
                "runtime node {} not in graph",
                s.node
            );
        }
        for w in t.path().windows(2) {
            assert!(
                edges.contains(&(w[0].to_owned(), w[1].to_owned())),
                "runtime transition {} -> {} not in graph",
                w[0],
                w[1]
            );
        }
    }

    #[test]
    fn websocket_routes_list_the_origin_check_first() {
        let m = app().manifest();
        let ws = m.routes.iter().find(|r| r.path == "/ws").unwrap();
        let data = m.routes.iter().find(|r| r.path == "/data").unwrap();
        assert!(ws.websocket);
        assert_eq!(
            ws.policy.checks.first().map(String::as_str),
            Some("ws_origin")
        );
        assert!(!data.policy.checks.iter().any(|c| c == "ws_origin"));

        let g = build_graph(&m, None).unwrap();
        let ids: BTreeSet<&str> = g.nodes.iter().map(|n| n.id.as_str()).collect();
        assert!(
            ids.contains(format!("{}.ws_origin", ws.id).as_str()),
            "{ids:?}"
        );
        assert!(!ids.contains(format!("{}.ws_origin", data.id).as_str()));
        let explain = poring::contract::explain(&m, &ws.id).unwrap();
        assert!(explain.contains("ws_origin"), "{explain}");
    }

    // Runtime traces need the `trace-flow` feature (static contracts above do not).
    #[cfg(feature = "trace-flow")]
    #[tokio::test]
    async fn runtime_traces_record_the_origin_check_on_the_static_path() {
        let app = app();
        let server = app.clone().bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr();
        let denied = handshake(
            addr,
            ws_request(addr, "/ws", "Origin: https://evil.example\r\n"),
        )
        .await;
        assert_eq!(status_of(&denied), 403);
        let allowed = handshake(addr, ws_request(addr, "/ws", "")).await;
        assert_eq!(status_of(&allowed), 101);
        server.shutdown().await.unwrap();

        let traces = app.flow().recent();
        let ws_id = app
            .manifest()
            .routes
            .iter()
            .find(|r| r.path == "/ws")
            .unwrap()
            .id
            .clone();
        let origin_node = format!("{ws_id}.ws_origin");
        assert_eq!(traces.len(), 2, "{traces:?}");
        for t in &traces {
            assert!(t.path().contains(&origin_node.as_str()), "{:?}", t.path());
            assert_trace_follows_graph(&app, t);
        }
        assert!(
            traces[0]
                .path()
                .contains(&format!("{ws_id}.deny.403").as_str())
        );
    }
}

/// Opaque origins: a sandboxed iframe or `data:` page sends `Origin: null` with the user's
/// cookies. Listing `"null"` in the *HTTP* CORS configuration must not admit a WebSocket
/// handshake (the Origin is validated before any allowlist), while ordinary HTTP CORS for
/// that origin keeps working as configured.
#[tokio::test]
async fn cors_listing_null_does_not_admit_opaque_websocket_origins() {
    let started = Started::default();
    let server = Poring::new()
        .authenticator(TableAuth::fixture())
        .cors(
            Cors::new()
                .origins(["null", "https://app.example"])
                .credentials(true),
        )
        .route_with(
            RouteMethod::Get,
            "/ws",
            Policy::new().authenticated(),
            ws_handler(started.clone()),
        )
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
        .unwrap();
    let addr = server.local_addr();
    let cookie = "Cookie: sid=session-bob\r\n";

    for origin in [
        "null",
        "NULL",
        "https://app.example.",
        "https://app_example",
        "https://%61pp.example",
        "https://app..example",
        "https://[not-v6]",
    ] {
        let head = handshake(
            addr,
            ws_request(addr, "/ws", &format!("Origin: {origin}\r\n{cookie}")),
        )
        .await;
        assert_eq!(status_of(&head), 403, "{origin:?} must be denied: {head}");
    }
    // Non-ASCII (an unencoded IDN) is not a serialised origin.
    let mut req = ws_request(addr, "/ws", cookie).into_bytes();
    let at = req.len() - 2;
    req.splice(at..at, "Origin: https://äpp.example\r\n".bytes());
    let head = handshake(addr, String::from_utf8(req).unwrap()).await;
    assert_eq!(status_of(&head), 403, "non-ASCII origin: {head}");

    // The explicitly listed tuple origin still upgrades with credentials.
    let head = handshake(
        addr,
        ws_request(
            addr,
            "/ws",
            &format!("Origin: https://app.example\r\n{cookie}"),
        ),
    )
    .await;
    assert_eq!(status_of(&head), 101, "{head}");

    // Ordinary HTTP CORS is unchanged: the configured `null` entry is honoured there.
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(
        format!("GET /data HTTP/1.1\r\nHost: {addr}\r\nOrigin: null\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut body = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), s.read_to_string(&mut body)).await;
    assert_eq!(status_of(&body), 200, "{body}");
    assert!(
        body.to_ascii_lowercase()
            .contains("access-control-allow-origin: null"),
        "HTTP CORS must keep its configured behaviour: {body}"
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        started.0.load(Ordering::SeqCst),
        1,
        "only the valid origin starts"
    );
    server.shutdown().await.unwrap();
}
