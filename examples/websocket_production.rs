//! A production-shaped WebSocket service: every limit Poring offers, set explicitly, with
//! authentication for both non-browser and browser clients and no built-in credentials.
//!
//! ```text
//! # Service tokens come from the environment (or your secret store), never from code.
//! # Generate real ones, e.g.: openssl rand -hex 32
//! export CHAT_API_TOKENS="alice=$(openssl rand -hex 32),bob=$(openssl rand -hex 32)"
//! PUBLIC_ORIGIN=https://chat.example.com TRUSTED_PROXY=10.0.0.10 \
//!     cargo run -p poring-examples --example websocket_production
//!
//! # Non-browser client: bearer token on the handshake.
//! websocat -H "Authorization: Bearer <alice's token>" ws://127.0.0.1:3000/chat
//!
//! # Browser client (cannot set headers on `new WebSocket`): fetch a one-time ticket over
//! # an authenticated HTTPS request, then connect within 30 s with it in the query.
//! curl -X POST -H "Authorization: Bearer <alice's token>" http://127.0.0.1:3000/ws-ticket
//! ```
//!
//! **This is a template, not a deployable service.** The token store is a stand-in for
//! your identity provider: in production, verify OIDC/JWT access tokens (signature,
//! issuer, audience, expiry) or look tokens up in a secret store, and issue tickets to
//! users authenticated by your normal web session.
//!
//! What it configures, and why:
//!
//! * **Authentication:** bearer tokens (non-browser) or single-use, 30-second tickets
//!   (browser). No ambient cookies authenticate the WebSocket, so cross-site WebSocket
//!   hijacking cannot ride a browser session. The origin policy is defence in depth.
//! * **Session caps:** `Limits::production()` caps sessions per listener, per client IP and
//!   per principal, so one client cannot take every slot.
//! * **Trusted proxies:** only the TLS-terminating proxy's forwarding headers are believed,
//!   so client IPs (per-IP caps, quotas) and the public scheme (origin checks) are right.
//! * **Origin enforcement:** browsers may only connect from the public origin, and never
//!   from a plain-`http://` page (`https_only`).
//! * **Endpoint limits:** `WebSocketUpgrade::production()` / `ManagedUpgrade::production()`
//!   as a baseline (message size, rate, lifetime, heartbeats, deadlines, memory budget),
//!   then tightened for this endpoint, plus a per-principal quota shared by all of a
//!   user's sessions. Startup fails if any setting is flagged by `production_warnings()`.
//! * **Metrics:** `ws_stats()` is logged every minute.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

#[derive(Serialize)]
struct Ticket {
    ticket: String,
    expires_in_secs: u64,
}

/// Single-use WebSocket tickets: `ticket -> (subject, expiry)`, bounded.
#[derive(Clone, Default)]
struct Tickets(Arc<Mutex<HashMap<String, (String, Instant)>>>);

const TICKET_TTL: Duration = Duration::from_secs(30);
const MAX_TICKETS: usize = 100_000;

impl Tickets {
    fn issue(&self, subject: &str) -> Option<String> {
        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw).ok()?;
        let ticket: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let mut map = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        map.retain(|_, (_, exp)| *exp > now);
        if map.len() >= MAX_TICKETS {
            return None;
        }
        map.insert(ticket.clone(), (subject.to_owned(), now + TICKET_TTL));
        Some(ticket)
    }

    /// Consumes the ticket: valid once, until it expires.
    fn redeem(&self, ticket: &str) -> Option<String> {
        let mut map = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let (subject, exp) = map.remove(ticket)?;
        (exp > Instant::now()).then_some(subject)
    }
}

/// Constant-time byte comparison (no early exit on the first differing byte).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Stand-in for an identity provider: service tokens loaded from `CHAT_API_TOKENS`
/// (`subject=token,...`), plus redemption of browser tickets on the `/chat` handshake.
#[derive(Clone)]
pub struct Auth {
    tokens: Arc<Vec<(String, String)>>,
    tickets: Tickets,
}

impl Auth {
    fn from_env(tickets: Tickets) -> Result<Self, String> {
        let raw = std::env::var("CHAT_API_TOKENS").map_err(|_| {
            "CHAT_API_TOKENS is not set: refusing to start without credentials \
             (format: subject=token,subject=token; tokens of at least 32 characters)"
                .to_owned()
        })?;
        let mut tokens = Vec::new();
        for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            // Never echo the entry: it may be a token.
            let (subject, token) = entry
                .split_once('=')
                .ok_or("CHAT_API_TOKENS: every entry must be subject=token")?;
            if token.len() < 32 {
                return Err(format!("token for {subject} is shorter than 32 characters"));
            }
            tokens.push((subject.to_owned(), token.to_owned()));
        }
        if tokens.is_empty() {
            return Err("CHAT_API_TOKENS holds no tokens".into());
        }
        Ok(Auth {
            tokens: Arc::new(tokens),
            tickets,
        })
    }
}

impl Authenticator for Auth {
    async fn authenticate(&self, req: &AuthRequest<'_>) -> Result<Option<Identity>, AuthError> {
        if let Some(presented) = req.bearer_token() {
            // Compare against every token so timing does not reveal which one matched.
            let mut found = None;
            for (subject, token) in self.tokens.iter() {
                if ct_eq(presented.as_bytes(), token.as_bytes()) {
                    found = Some(subject.clone());
                }
            }
            return match found {
                Some(subject) => Ok(Some(Identity::new(subject, Credential::Bearer))),
                None => Err(AuthError::Invalid),
            };
        }
        // Browser handshakes: `GET /chat?ticket=...` (single use, 30 s).
        if req.uri.path() == "/chat"
            && let Some(ticket) = req
                .uri
                .query()
                .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("ticket=")))
        {
            return match self.tickets.redeem(ticket) {
                Some(subject) => Ok(Some(Identity::new(subject, Credential::Other))),
                None => Err(AuthError::Invalid),
            };
        }
        Ok(None)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let public_origin =
        std::env::var("PUBLIC_ORIGIN").unwrap_or_else(|_| "https://chat.example.com".into());
    let proxy = std::env::var("TRUSTED_PROXY").unwrap_or_else(|_| "10.0.0.10".into());
    let addr = std::env::var("PORING_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());

    let tickets = Tickets::default();
    let auth = Auth::from_env(tickets.clone())?;
    let limits = Limits::production();
    if let Some(w) = limits.production_warnings().first() {
        return Err(format!("unsafe listener limits: {w}").into());
    }

    // Shared by every session: 600 messages per minute per user, across all their tabs.
    let quota = WsMessageQuota::per_principal(600, Duration::from_secs(60)).max_keys(100_000);

    let app = Poring::new()
        .limits(limits)
        .trusted_proxies([proxy.as_str()])
        .ws_origins(WsOrigins::new().allow([public_origin]).https_only())
        .authenticator(auth)
        .policy(Policy::new().deny_anonymous())
        .route_with(
            RouteMethod::Get,
            "/health",
            Policy::new().public_with_reason("load balancer probe"),
            || async { "ok" },
        )
        // Browser clients call this with their normal authenticated session (here: the
        // bearer token stand-in) and use the ticket for `new WebSocket(url + "?ticket=")`.
        .route_with(
            RouteMethod::Post,
            "/ws-ticket",
            Policy::new(),
            move |Principal(who): Principal<Authenticated>| {
                let tickets = tickets.clone();
                async move {
                    match tickets.issue(&who.subject) {
                        Some(ticket) => Ok(Json(Ticket {
                            ticket,
                            expires_in_secs: TICKET_TTL.as_secs(),
                        })),
                        None => Err(StatusCode::SERVICE_UNAVAILABLE),
                    }
                }
            },
        )
        .ws("/chat", move |ws: WebSocketUpgrade| {
            let quota = quota.clone();
            async move {
                let user = ws.identity().map(|i| i.subject.clone()).unwrap_or_default();
                let upgrade = ws
                    .production()
                    .max_message_size(16 * 1024)
                    .message_rate(20, Duration::from_secs(1))
                    .message_quota(&quota)
                    .max_lifetime(Duration::from_secs(4 * 60 * 60))
                    .managed()
                    .production()
                    .ping_interval(Duration::from_secs(25))
                    .pong_timeout(Duration::from_secs(10))
                    .stall_timeout(Duration::from_secs(15))
                    .queue_messages(16)
                    .max_queued_bytes(256 * 1024)
                    .max_outbound_message(64 * 1024);
                debug_assert!(upgrade.production_warnings().is_empty());
                upgrade.typed::<ClientMsg, ServerMsg>().on_upgrade(
                    move |mut sock: ManagedTypedSocket<ClientMsg, ServerMsg>| async move {
                        while let Some(msg) = sock.recv().await {
                            let Ok(msg) = msg else {
                                // Invalid JSON or validation failure: skip it. Transport
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
                // Counts only: no tokens, tickets, identities or payloads are logged.
                let s = server.ws_stats();
                println!(
                    "ws: active={} accepted={} origin_denied={} auth_denied={} rate_limited={} \
                     stalls={} write_timeouts={} heartbeat_timeouts={} in={}msg/{}B out={}msg/{}B",
                    s.active_sessions, s.handshakes_accepted, s.origin_denied, s.auth_denied,
                    s.rate_limited, s.inbound_stalls, s.write_timeouts, s.heartbeat_timeouts,
                    s.messages_received, s.bytes_received, s.messages_sent, s.bytes_sent,
                );
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    server.shutdown().await?;
    Ok(())
}
