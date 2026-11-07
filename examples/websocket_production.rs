//! A production-shaped WebSocket service: every limit Poring offers, set explicitly.
//!
//! ```text
//! PUBLIC_ORIGIN=https://chat.example.com TRUSTED_PROXY=10.0.0.10 \
//!     cargo run -p poring-examples --example websocket_production
//! # then (no Origin header, so the origin policy does not apply to this client):
//! # websocat -H 'Authorization: Bearer alice-token' ws://127.0.0.1:3000/chat
//! ```
//!
//! What it configures, and why (see `docs/guide.md`, "WebSockets in production"):
//!
//! * **Session caps:** `Limits::production()` caps sessions per listener, per client IP and
//!   per principal, so one client cannot take every slot.
//! * **Trusted proxies:** the TLS-terminating proxy is trusted, so client IPs (per-IP caps,
//!   quotas) and the public scheme (origin checks) come from its headers, and from no one
//!   else's.
//! * **Origin enforcement:** browsers may only connect from the public origin, and never
//!   from a plain-`http://` page (`https_only`).
//! * **Message quotas:** a per-session rate plus a per-principal quota shared by all of a
//!   user's sessions; exceeding either closes the session with `1008`.
//! * **Memory budget:** inbound messages are capped at 16 KiB, outbound queues at 16
//!   messages / 256 KiB per session, so the worst case per session is bounded and known.
//! * **Timeouts:** heartbeat, idle, write, inbound-stall and lifetime deadlines, so dead,
//!   slow or stuck peers and stuck handlers always release their slots.
//! * **Metrics:** `ws_stats()` is logged every minute.
use std::time::Duration;

use poring::policy::WsOrigins;
use poring::prelude::*;
use poring::ws::{ManagedTypedSocket, WebSocketUpgrade, WsMessageQuota};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, PoringSchema)]
struct ClientMsg {
    #[poring(min_length = 1, max_length = 2000)]
    text: String,
}

#[derive(Debug, Serialize)]
struct ServerMsg {
    from: String,
    text: String,
}

/// Bearer tokens only: no cookies, so cross-site WebSocket hijacking cannot ride a
/// browser session (the origin policy is defence in depth).
#[derive(Clone)]
pub struct Tokens;

impl Authenticator for Tokens {
    async fn authenticate(&self, req: &AuthRequest<'_>) -> Result<Option<Identity>, AuthError> {
        match req.bearer_token() {
            Some("alice-token") => Ok(Some(Identity::new("alice", Credential::Bearer))),
            Some("bob-token") => Ok(Some(Identity::new("bob", Credential::Bearer))),
            Some(_) => Err(AuthError::Invalid),
            None => Ok(None),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let public_origin =
        std::env::var("PUBLIC_ORIGIN").unwrap_or_else(|_| "https://chat.example.com".into());
    let proxy = std::env::var("TRUSTED_PROXY").unwrap_or_else(|_| "10.0.0.10".into());
    let addr = std::env::var("PORING_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());

    // Shared by every session: 600 messages per minute per user, across all their tabs.
    let quota = WsMessageQuota::per_principal(600, Duration::from_secs(60)).max_keys(100_000);

    let app = Poring::new()
        .limits(poring::Limits::production())
        .trusted_proxies([proxy.as_str()])
        .ws_origins(WsOrigins::new().allow([public_origin]).https_only())
        .authenticator(Tokens)
        .policy(Policy::new().deny_anonymous())
        .route_with(
            RouteMethod::Get,
            "/health",
            Policy::new().public_with_reason("load balancer probe"),
            || async { "ok" },
        )
        .ws("/chat", move |ws: WebSocketUpgrade| {
            let quota = quota.clone();
            async move {
                let user = ws.identity().map(|i| i.subject.clone()).unwrap_or_default();
                ws.max_message_size(16 * 1024)
                    .max_frame_size(16 * 1024)
                    .message_rate(20, Duration::from_secs(1))
                    .message_quota(&quota)
                    .max_lifetime(Duration::from_secs(4 * 60 * 60))
                    .managed()
                    .ping_interval(Duration::from_secs(25))
                    .pong_timeout(Duration::from_secs(10))
                    .idle_timeout(Duration::from_secs(90))
                    .write_timeout(Duration::from_secs(15))
                    .stall_timeout(Duration::from_secs(15))
                    .queue_messages(16)
                    .max_queued_bytes(256 * 1024)
                    .max_outbound_message(64 * 1024)
                    .typed::<ClientMsg, ServerMsg>()
                    .on_upgrade(
                        move |mut sock: ManagedTypedSocket<ClientMsg, ServerMsg>| async move {
                            while let Some(msg) = sock.recv().await {
                                let Ok(msg) = msg else {
                                    // Invalid JSON or validation failure: skip it; transport
                                    // problems end the stream on their own.
                                    continue;
                                };
                                let reply = ServerMsg {
                                    from: user.clone(),
                                    text: msg.text,
                                };
                                if sock.send(&reply).await.is_err() {
                                    break;
                                }
                            }
                        },
                    )
            }
        })
        .build()?;

    let server = app.bind(&addr).await?;
    println!("listening on {}", server.local_addr());
    let mut every_minute = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = every_minute.tick() => {
                let s = server.ws_stats();
                println!(
                    "ws: active={} accepted={} origin_denied={} rate_limited={} stalls={} \
                     write_timeouts={} heartbeat_timeouts={} in={}msg/{}B out={}msg/{}B",
                    s.active_sessions, s.handshakes_accepted, s.origin_denied, s.rate_limited,
                    s.inbound_stalls, s.write_timeouts, s.heartbeat_timeouts,
                    s.messages_received, s.bytes_received, s.messages_sent, s.bytes_sent,
                );
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    server.shutdown().await?;
    Ok(())
}
