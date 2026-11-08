//! Typed WebSocket routes (`websocket` feature).
//!
//! Compiled example: `examples/websocket_echo.rs`.
//!
//! ```text
//! #[poring::ws("/chat")]
//! async fn chat(ws: WebSocketUpgrade) -> Response {
//!     ws.typed::<ClientMsg, ServerMsg>().on_upgrade(|mut sock| async move {
//!         while let Some(Ok(msg)) = sock.recv().await {
//!             if sock.send(&ServerMsg::from(msg)).await.is_err() { break; }
//!         }
//!     })
//! }
//! ```
//!
//! * Inbound frames are size-limited (`max_message_size`, default 64 KiB), parsed as JSON
//!   and validated with the type's `PoringSchema` rules before the handler sees them.
//! * Outbound data is bounded: raw and typed sockets' `send` awaits the socket flush with a
//!   bounded write buffer, and managed sessions bound their outbound queue by messages and
//!   bytes, so a slow reader applies backpressure to the producer instead of growing memory.
//!   In managed sessions a blocked write never stalls reading, heartbeats, timeouts or
//!   shutdown (see [`ManagedUpgrade::write_timeout`]).
//! * The upgrade request itself goes through the normal policy pipeline (auth, rate
//!   limits) before `on_upgrade` runs. Handshakes carrying an `Origin` header must be
//!   same-origin or listed explicitly in the app's CORS origins or
//!   [`WsOrigins`](crate::policy::WsOrigins) (the `*` wildcard does not count). Otherwise
//!   they are rejected with 403 before any `101`. Same-origin includes the scheme whenever
//!   the endpoint's scheme is known (native TLS, HTTP/2 `:scheme`, or a trusted proxy's
//!   `Forwarded`/`X-Forwarded-Proto`): an `http://` page cannot reach a `wss://` endpoint
//!   by host match alone. `WsOrigins::https_only` refuses every non-`https` origin.
//!   Handshakes without `Origin` (non-browser clients) are allowed: Origin is not
//!   authentication.
//! * Managed sessions whose handler stops reading are closed with `1013` after
//!   [`ManagedUpgrade::stall_timeout`] (default 60 s), so a stuck handler cannot hold its
//!   session slot indefinitely.
//! * The handshake is validated before `101` (RFC 6455 §4.2.1): HTTP/1.1 `GET` with
//!   `Connection: upgrade` and `Upgrade: websocket` tokens, exactly one
//!   `Sec-WebSocket-Version: 13` (otherwise `426` advertising 13, or `400` if missing or
//!   repeated) and exactly one `Sec-WebSocket-Key` that is base64 of 16 bytes (`400`).
//! * Subprotocols are opt-in: [`WebSocketUpgrade::protocols`] selects, in server
//!   preference order, only a protocol the client offered. Malformed offers are rejected
//!   with `400`. Extensions such as `permessage-deflate` are never negotiated.

use std::future::Future;
use std::marker::PhantomData;

use futures_util::{SinkExt, StreamExt};
use http::{HeaderValue, StatusCode, header};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::{self, Message};

use crate::ctx::Ctx;
use crate::descriptor::ExtractorKind;
use crate::error::{ApiError, ValidationIssue, rejection};
use crate::extract::{ExtractorMeta, FromRequest};
use crate::response::{IntoResponse, Response};
use crate::schema::PoringSchema;

/// Server-owned supervisor of the upgraded sessions of one listener (one `serve` call).
///
/// Sessions are admitted against `Limits::max_ws_sessions` before `101`, run as tasks
/// owned here (never detached: see [`crate::app::tasks::TaskTracker`]), and hold their
/// session permit and their TCP connection permit until they end, whether normally, by
/// error, by panic or by cancellation. A finished session is removed from the set as it ends, so
/// completed tasks are never retained, even when no further handshake arrives. On shutdown
/// the supervisor stops admitting, and lingering sessions are aborted after the grace
/// period.
pub(crate) struct Supervisor {
    sessions: std::sync::Arc<tokio::sync::Semaphore>,
    tasks: crate::app::tasks::TaskTracker,
    /// Flips to `true` once shutdown begins (observed by [`WsShutdown`]).
    stop: tokio::sync::watch::Sender<bool>,
    /// Live sessions per client IP / principal, for the per-client caps. Only touched when
    /// a capped session starts or ends, never per message.
    holders: std::sync::Mutex<std::collections::HashMap<SessionKey, usize>>,
    counters: std::sync::Arc<WsCounters>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum SessionKey {
    Ip(std::net::IpAddr),
    Subject(String),
}

/// One session counted against a per-client cap. Released on drop.
struct KeyHold {
    supervisor: std::sync::Arc<Supervisor>,
    key: SessionKey,
}

impl Drop for KeyHold {
    fn drop(&mut self) {
        let mut map = self
            .supervisor
            .holders
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(n) = map.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.key);
            }
        }
    }
}

impl Supervisor {
    /// `max_sessions` is taken literally: `0` admits no session at all (every handshake is
    /// refused with `503`). Values above [`tokio::sync::Semaphore::MAX_PERMITS`] mean
    /// "unlimited" and are clamped to it.
    pub(crate) fn new(max_sessions: usize, counters: std::sync::Arc<WsCounters>) -> Self {
        let panics = counters.clone();
        Supervisor {
            sessions: std::sync::Arc::new(tokio::sync::Semaphore::new(
                max_sessions.min(tokio::sync::Semaphore::MAX_PERMITS),
            )),
            tasks: crate::app::tasks::TaskTracker::with_panic_hook(move || {
                panics.note(WsEvent::Panicked);
                tracing::warn!("websocket session panicked");
            }),
            stop: tokio::sync::watch::Sender::new(false),
            holders: std::sync::Mutex::new(std::collections::HashMap::new()),
            counters,
        }
    }

    /// Counts one more session for `key` unless it already has `max` (`0` refuses every
    /// session). `usize::MAX` means "no cap" and is not tracked at all.
    fn hold(
        self: &std::sync::Arc<Self>,
        key: SessionKey,
        max: usize,
    ) -> Result<Option<KeyHold>, ()> {
        if max == usize::MAX {
            return Ok(None);
        }
        let mut map = self.holders.lock().unwrap_or_else(|p| p.into_inner());
        let n = map.entry(key.clone()).or_insert(0);
        if *n >= max {
            if *n == 0 {
                map.remove(&key);
            }
            return Err(());
        }
        *n += 1;
        Ok(Some(KeyHold {
            supervisor: self.clone(),
            key,
        }))
    }

    /// Spawns a session unless the supervisor is closed.
    fn spawn(&self, session: impl Future<Output = ()> + Send + 'static) -> bool {
        self.tasks.spawn(session)
    }

    /// Stops admitting new sessions and tells running sessions that shutdown has begun.
    pub(crate) fn close(&self) {
        self.tasks.close();
        self.stop.send_replace(true);
    }

    /// Closes the supervisor, aborts every remaining session and waits (at most `bound`)
    /// for them to be dropped.
    pub(crate) async fn abort_all(&self, bound: std::time::Duration) {
        self.stop.send_replace(true);
        let n = self.tasks.abort_all();
        let drained = tokio::time::timeout(bound, self.tasks.wait_idle()).await;
        if n > 0 {
            tracing::debug!(sessions = n, "websocket sessions cancelled at shutdown");
        }
        if drained.is_err() {
            tracing::warn!("websocket sessions did not stop after cancellation");
        }
    }
}

/// Inserted by the server into WebSocket upgrade requests: the listener's supervisor and
/// the request's TCP connection permit.
#[derive(Clone)]
pub(crate) struct Admission {
    pub(crate) supervisor: std::sync::Arc<Supervisor>,
    pub(crate) connection: std::sync::Arc<tokio::sync::OwnedSemaphorePermit>,
    /// Client IP as the HTTP rate limiter resolves it (trusted proxies applied).
    pub(crate) client_ip: std::net::IpAddr,
}

/// A message quota shared by every WebSocket session that uses it, keyed by client IP or
/// by principal (see [`WebSocketUpgrade::message_quota`]). Create it once (for example in
/// application state) and pass it to each upgrade. Clones share the same buckets.
///
/// Buckets live in a bounded, sharded [`RateLimiter`](crate::policy::rate_limit::RateLimiter)
/// (GCRA): `messages` per `per` with a burst of `messages`. When the key store is full,
/// messages from new clients are refused (fail closed).
#[derive(Clone)]
pub struct WsMessageQuota {
    limiter: std::sync::Arc<crate::policy::rate_limit::RateLimiter>,
    rule: crate::policy::rate_limit::RateRule,
    by_principal: bool,
}

impl std::fmt::Debug for WsMessageQuota {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsMessageQuota")
            .field("rule", &self.rule)
            .field("by_principal", &self.by_principal)
            .finish_non_exhaustive()
    }
}

impl WsMessageQuota {
    fn new(messages: u32, per: std::time::Duration, by_principal: bool) -> Self {
        WsMessageQuota {
            limiter: std::sync::Arc::new(crate::policy::rate_limit::RateLimiter::new(100_000)),
            rule: crate::policy::rate_limit::RateRule {
                scope: 0,
                limit: messages.max(1),
                window_ns: u64::try_from(per.as_nanos()).unwrap_or(u64::MAX).max(1),
            },
            by_principal,
        }
    }

    /// `messages` per `per` for each client IP, across all its sessions. A `messages` of 0
    /// is treated as 1 and a zero `per` as 1 ns.
    pub fn per_ip(messages: u32, per: std::time::Duration) -> Self {
        Self::new(messages, per, false)
    }

    /// `messages` per `per` for each authenticated principal, across all its sessions.
    /// Anonymous sessions are keyed by client IP instead.
    pub fn per_principal(messages: u32, per: std::time::Duration) -> Self {
        Self::new(messages, per, true)
    }

    /// Maximum number of tracked clients (default 100 000, clamped to
    /// 1..=[`MAX_KEYS`](crate::policy::rate_limit::MAX_KEYS)).
    pub fn max_keys(mut self, n: usize) -> Self {
        self.limiter = std::sync::Arc::new(crate::policy::rate_limit::RateLimiter::new(n));
        self
    }
}

/// Local GCRA for one session's inbound message rate (no locks, no allocation).
#[derive(Clone, Copy, Debug)]
struct Gcra {
    start: std::time::Instant,
    emission_ns: u128,
    tau_ns: u128,
    tat_ns: u128,
}

impl Gcra {
    fn new(messages: u32, per: std::time::Duration) -> Self {
        let per_ns = per.as_nanos().max(1);
        let emission_ns = (per_ns / u128::from(messages.max(1))).max(1);
        Gcra {
            start: std::time::Instant::now(),
            emission_ns,
            tau_ns: per_ns.saturating_sub(emission_ns),
            tat_ns: 0,
        }
    }

    fn admit(&mut self, now: std::time::Instant) -> bool {
        let t = now.duration_since(self.start).as_nanos();
        let tat = self.tat_ns.max(t);
        if tat - t > self.tau_ns {
            return false;
        }
        self.tat_ns = tat + self.emission_ns;
        true
    }
}

/// Inbound message admission for managed and typed sessions.
#[derive(Debug, Default)]
struct MessageGate {
    local: Option<Gcra>,
    shared: Option<(WsMessageQuota, crate::policy::rate_limit::RateKeyValue)>,
}

impl MessageGate {
    /// Whether one more data message may be processed.
    fn admit(&mut self) -> bool {
        if self.local.is_none() && self.shared.is_none() {
            return true;
        }
        let now = std::time::Instant::now();
        if let Some(g) = &mut self.local
            && !g.admit(now)
        {
            return false;
        }
        match &self.shared {
            Some((q, key)) => q.limiter.check_one(q.rule, key, now).is_allowed(),
            None => true,
        }
    }
}

const RATE_EXCEEDED: &str = "message rate exceeded";

/// A point-in-time copy of an app's WebSocket counters ([`App::ws_stats`](crate::app::App::ws_stats),
/// [`Server::ws_stats`](crate::app::Server::ws_stats)). All counters are cumulative since the
/// app was built, except `active_sessions`.
///
/// Message and byte counts cover [managed](WebSocketUpgrade::managed) and
/// [typed](WebSocketUpgrade::typed) sessions only (raw sockets are not observed). Each
/// session accumulates them locally and publishes them every 64 messages, about one second
/// after an unpublished count was taken while the session waits for input (managed
/// sessions always, typed sessions while the handler is awaiting `recv`), at the next
/// `recv`/`send` otherwise, and when the session ends. Counts are therefore eventually
/// consistent: a scrape can lag a session by roughly a second, or longer only while a typed
/// handler is busy outside `recv`/`send`. Event counters (refusals, timeouts, closes) are
/// published immediately. Payloads, headers and credentials are never recorded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct WsStats {
    /// Handshakes answered with `101` (HTTP/1.1) or `200` (HTTP/2) and started.
    pub handshakes_accepted: u64,
    /// Handshakes refused because `Limits::max_ws_sessions` was reached (`503`).
    pub rejected_session_limit: u64,
    /// Handshakes refused by a per-IP or per-principal session cap (`429`).
    pub rejected_client_cap: u64,
    /// Handshakes refused because the server was shutting down (`503`).
    pub rejected_shutdown: u64,
    /// Handshakes refused by the WebSocket origin policy (`403`).
    pub origin_denied: u64,
    /// Handshakes to WebSocket routes refused by authentication (`401`).
    pub auth_denied: u64,
    /// Sessions currently running.
    pub active_sessions: u64,
    /// Sessions that have ended, however they ended.
    pub sessions_ended: u64,
    /// Sessions whose handler panicked.
    pub sessions_panicked: u64,
    /// Data messages received / sent (managed and typed sessions).
    pub messages_received: u64,
    /// See `messages_received`.
    pub messages_sent: u64,
    /// Payload bytes received / sent (managed and typed sessions).
    pub bytes_received: u64,
    /// See `bytes_received`.
    pub bytes_sent: u64,
    /// Sessions failed with `1002`, `1007` or `1009` after a protocol error.
    pub protocol_failures: u64,
    /// Sessions closed with `1008` for exceeding a message rate or quota.
    pub rate_limited: u64,
    /// Managed sessions closed after their idle timeout.
    pub idle_timeouts: u64,
    /// Sessions ended by `max_lifetime`.
    pub lifetime_expired: u64,
    /// Managed or typed sessions closed with `1001` at server shutdown.
    pub shutdown_closes: u64,
    /// Managed or typed sessions whose peer disappeared without a close handshake (TCP
    /// reset or EOF, HTTP/2 stream reset).
    pub abnormal_disconnects: u64,
    /// Managed sessions closed because a heartbeat ping was not answered with the matching
    /// pong within `pong_timeout`.
    pub heartbeat_timeouts: u64,
    /// Managed sessions ended because an outbound message could not be written within
    /// `write_timeout` (a peer that stopped reading).
    pub write_timeouts: u64,
    /// Managed sessions closed with `1013` because the handler did not take an inbound
    /// message within `stall_timeout`.
    pub inbound_stalls: u64,
    /// Inbound messages that had to wait for room in a managed handler's queue (the pump
    /// stopped reading the socket meanwhile): a measure of inbound queue pressure.
    pub inbound_backpressure: u64,
    /// Managed `send` calls that had to wait for the outbound queue or its byte budget: a
    /// measure of outbound queue pressure (slow peers).
    pub outbound_backpressure: u64,
    /// Managed or typed sessions whose peer sent a close frame.
    pub peer_closes: u64,
    /// Managed sessions closed by the application (`close`, or the handler returning), with
    /// `1000` or the application's code.
    pub server_closes: u64,
}

/// Rare session events counted directly.
#[derive(Clone, Copy, Debug)]
pub(crate) enum WsEvent {
    Accepted,
    RejectedSessionLimit,
    RejectedClientCap,
    RejectedShutdown,
    OriginDenied,
    AuthDenied,
    Panicked,
    ProtocolFailure,
    RateLimited,
    IdleTimeout,
    LifetimeExpired,
    ShutdownClose,
    AbnormalDisconnect,
    HeartbeatTimeout,
    WriteTimeout,
    InboundStall,
    InboundBackpressure,
    OutboundBackpressure,
    PeerClose,
    ServerClose,
}

/// Number of [`WsEvent`] variants.
const WS_EVENTS: usize = WsEvent::ServerClose as usize + 1;

/// App-wide WebSocket counters: relaxed atomics, touched on handshakes, session start/end
/// and rare events only (per-message counts are accumulated per session).
#[derive(Debug, Default)]
pub(crate) struct WsCounters {
    events: [std::sync::atomic::AtomicU64; WS_EVENTS],
    active: std::sync::atomic::AtomicU64,
    ended: std::sync::atomic::AtomicU64,
    messages_received: std::sync::atomic::AtomicU64,
    messages_sent: std::sync::atomic::AtomicU64,
    bytes_received: std::sync::atomic::AtomicU64,
    bytes_sent: std::sync::atomic::AtomicU64,
}

impl WsCounters {
    pub(crate) fn note(&self, e: WsEvent) {
        self.events[e as usize].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn event(&self, e: WsEvent) -> u64 {
        self.events[e as usize].load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn snapshot(&self) -> WsStats {
        use std::sync::atomic::Ordering::Relaxed;
        WsStats {
            handshakes_accepted: self.event(WsEvent::Accepted),
            rejected_session_limit: self.event(WsEvent::RejectedSessionLimit),
            rejected_client_cap: self.event(WsEvent::RejectedClientCap),
            rejected_shutdown: self.event(WsEvent::RejectedShutdown),
            origin_denied: self.event(WsEvent::OriginDenied),
            auth_denied: self.event(WsEvent::AuthDenied),
            active_sessions: self.active.load(Relaxed),
            sessions_ended: self.ended.load(Relaxed),
            sessions_panicked: self.event(WsEvent::Panicked),
            messages_received: self.messages_received.load(Relaxed),
            messages_sent: self.messages_sent.load(Relaxed),
            bytes_received: self.bytes_received.load(Relaxed),
            bytes_sent: self.bytes_sent.load(Relaxed),
            protocol_failures: self.event(WsEvent::ProtocolFailure),
            rate_limited: self.event(WsEvent::RateLimited),
            idle_timeouts: self.event(WsEvent::IdleTimeout),
            lifetime_expired: self.event(WsEvent::LifetimeExpired),
            shutdown_closes: self.event(WsEvent::ShutdownClose),
            abnormal_disconnects: self.event(WsEvent::AbnormalDisconnect),
            heartbeat_timeouts: self.event(WsEvent::HeartbeatTimeout),
            write_timeouts: self.event(WsEvent::WriteTimeout),
            inbound_stalls: self.event(WsEvent::InboundStall),
            inbound_backpressure: self.event(WsEvent::InboundBackpressure),
            outbound_backpressure: self.event(WsEvent::OutboundBackpressure),
            peer_closes: self.event(WsEvent::PeerClose),
            server_closes: self.event(WsEvent::ServerClose),
        }
    }
}

/// Marks one session active for its lifetime.
struct ActiveSession(std::sync::Arc<WsCounters>);

impl ActiveSession {
    fn start(c: std::sync::Arc<WsCounters>) -> Self {
        c.active.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        ActiveSession(c)
    }
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering::Relaxed;
        self.0.active.fetch_sub(1, Relaxed);
        self.0.ended.fetch_add(1, Relaxed);
    }
}

/// Messages a session counts locally before publishing them to the app counters.
const METER_BATCH: u64 = 64;
/// Longest time a session keeps counts unpublished while it is waiting for input (typed and
/// managed sessions arm a timer for it) or processing messages.
const METER_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Per-session message/byte counts. Accumulated locally (no shared-cache-line traffic per
/// message) and published to the app counters in batches: every [`METER_BATCH`] messages,
/// when [`METER_INTERVAL`] has passed at the next message, at
/// [`flush_deadline`](Self::flush_deadline) while the session waits for input, on
/// [`flush`](Self::flush) and when dropped.
#[derive(Debug)]
struct SessionMeter {
    counters: Option<std::sync::Arc<WsCounters>>,
    messages_received: u64,
    messages_sent: u64,
    bytes_received: u64,
    bytes_sent: u64,
    last_flush: std::time::Instant,
}

impl Default for SessionMeter {
    fn default() -> Self {
        SessionMeter::new(None)
    }
}

impl SessionMeter {
    fn new(counters: Option<std::sync::Arc<WsCounters>>) -> Self {
        SessionMeter {
            counters,
            messages_received: 0,
            messages_sent: 0,
            bytes_received: 0,
            bytes_sent: 0,
            last_flush: std::time::Instant::now(),
        }
    }

    fn received(&mut self, m: &Message) {
        self.messages_received += 1;
        self.bytes_received += m.len() as u64;
        self.maybe_flush();
    }

    fn sent(&mut self, m: &Message) {
        self.messages_sent += 1;
        self.bytes_sent += m.len() as u64;
        self.maybe_flush();
    }

    fn maybe_flush(&mut self) {
        if self.counters.is_none() {
            return;
        }
        if self.messages_received + self.messages_sent >= METER_BATCH
            || self.last_flush.elapsed() >= METER_INTERVAL
        {
            self.flush();
        }
    }

    /// When unpublished counts must be published: `None` if there is nothing to publish (or
    /// no counters), so an idle session arms no timer and costs nothing.
    fn flush_deadline(&self) -> Option<tokio::time::Instant> {
        self.counters.as_ref()?;
        if self.messages_received + self.messages_sent == 0 {
            return None;
        }
        Some(tokio::time::Instant::from_std(self.last_flush) + METER_INTERVAL)
    }

    /// Publishes the counts accumulated so far.
    fn flush(&mut self) {
        use std::sync::atomic::Ordering::Relaxed;
        self.last_flush = std::time::Instant::now();
        let Some(c) = &self.counters else { return };
        if self.messages_received + self.messages_sent == 0 {
            return;
        }
        c.messages_received
            .fetch_add(std::mem::take(&mut self.messages_received), Relaxed);
        c.messages_sent
            .fetch_add(std::mem::take(&mut self.messages_sent), Relaxed);
        c.bytes_received
            .fetch_add(std::mem::take(&mut self.bytes_received), Relaxed);
        c.bytes_sent
            .fetch_add(std::mem::take(&mut self.bytes_sent), Relaxed);
    }

    fn note(&self, e: WsEvent) {
        if let Some(c) = &self.counters {
            c.note(e);
        }
    }
}

impl Drop for SessionMeter {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Notification that the server serving a WebSocket session has begun shutting down.
///
/// Obtained with [`WebSocketUpgrade::shutdown_signal`] before `on_upgrade`, and moved into
/// the session. After it fires, sessions have until `Limits::shutdown_grace` to finish.
/// Sessions still running then are cancelled (their socket is dropped without a close
/// frame). Raw-socket handlers should send a close frame themselves, typically
/// `CloseCode::Away` (1001). [`TypedSocket::recv`] does so automatically.
///
/// ```no_run
/// # use poring::ws::WebSocketUpgrade;
/// # use poring::response::Response;
/// use futures_util::StreamExt;
/// use tokio_tungstenite::tungstenite::protocol::CloseFrame;
/// use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
///
/// async fn feed(ws: WebSocketUpgrade) -> Response {
///     let mut stop = ws.shutdown_signal();
///     ws.on_upgrade(move |mut sock| async move {
///         tokio::select! {
///             _ = async { while let Some(Ok(_msg)) = sock.next().await {} } => {}
///             _ = stop.wait() => {
///                 let frame = CloseFrame { code: CloseCode::Away, reason: "restarting".into() };
///                 let _ = sock.close(Some(frame)).await;
///             }
///         }
///     })
/// }
/// ```
#[derive(Clone, Debug)]
pub struct WsShutdown {
    rx: Option<tokio::sync::watch::Receiver<bool>>,
}

impl WsShutdown {
    /// Whether shutdown has begun.
    pub fn is_shutting_down(&self) -> bool {
        self.rx.as_ref().is_some_and(|rx| *rx.borrow())
    }

    /// Completes once shutdown has begun (immediately if it already has). Never completes
    /// for an upgrade that is not served by a Poring server (e.g. the in-process client).
    /// Cancel-safe. No periodic wake-ups.
    pub async fn wait(&mut self) {
        match &mut self.rx {
            // An error means the supervisor is gone, which only happens after shutdown.
            Some(rx) => {
                let _ = rx.wait_for(|stopping| *stopping).await;
            }
            None => std::future::pending().await,
        }
    }
}

/// The raw upgraded socket.
///
/// The handler owns the close handshake: tungstenite answers a peer's close frame on the
/// next read or write, but on a read error (invalid UTF-8, oversized message, protocol
/// violation) it sends nothing, and close codes passed to `close` are not validated. Use
/// [`WebSocketUpgrade::managed`] or [`WebSocketUpgrade::typed`] to have Poring send `1007`,
/// `1009` or `1002` and keep reserved codes off the wire.
pub type RawSocket = WebSocketStream<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>>;

/// Extractor for a WebSocket upgrade request (validates the RFC 6455 handshake headers).
pub struct WebSocketUpgrade {
    /// `Sec-WebSocket-Key` for HTTP/1.1. `None` for HTTP/2 (RFC 8441 has no key exchange).
    key: Option<HeaderValue>,
    on_upgrade: Option<hyper::upgrade::OnUpgrade>,
    admission: Option<Admission>,
    config: WebSocketConfig,
    /// Subprotocols offered by the client, in the client's order (validated, unique).
    offered: Vec<String>,
    /// Index into `offered` of the selected subprotocol.
    selected: Option<usize>,
    require_protocol: bool,
    max_lifetime: Option<std::time::Duration>,
    /// Identity subject, if the request was authenticated (per-principal caps/quotas).
    subject: Option<String>,
    identity: Option<crate::policy::Identity>,
    request_id: crate::ctx::RequestId,
    route_id: String,
    peer: Option<std::net::SocketAddr>,
    per_ip_max: usize,
    per_principal_max: usize,
    message_rate: Option<(u32, std::time::Duration)>,
    message_quota: Option<WsMessageQuota>,
}

impl std::fmt::Debug for WebSocketUpgrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSocketUpgrade").finish_non_exhaustive()
    }
}

impl ExtractorMeta for WebSocketUpgrade {
    const KIND: ExtractorKind = ExtractorKind::WebSocket;
}

fn header_has_token(h: &http::HeaderMap, name: header::HeaderName, token: &str) -> bool {
    h.get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case(token))
}

/// The only value of a header that must appear exactly once.
fn single(h: &http::HeaderMap, name: header::HeaderName) -> Option<&HeaderValue> {
    let mut all = h.get_all(name).iter();
    match (all.next(), all.next()) {
        (Some(v), None) => Some(v),
        _ => None,
    }
}

/// RFC 6455 §4.2.1 item 5: base64 (standard alphabet, padded, canonical) of 16 bytes.
fn valid_key(key: &[u8]) -> bool {
    key.len() == 24
        && data_encoding::BASE64
            .decode(key)
            .is_ok_and(|nonce| nonce.len() == 16)
}

/// RFC 6455 §4.2.1 item 6 and §4.4: exactly one `Sec-WebSocket-Version`, equal to 13.
/// Unsupported versions get `426 Upgrade Required`. Missing or repeated headers are
/// malformed (400). Both advertise `Sec-WebSocket-Version: 13`.
fn check_version(h: &http::HeaderMap) -> Result<(), ApiError> {
    let supported = || HeaderValue::from_static("13");
    let Some(v) = single(h, header::SEC_WEBSOCKET_VERSION) else {
        return Err(rejection::bad_request(
            "websocket_version",
            "exactly one Sec-WebSocket-Version header is required",
        )
        .with_header(header::SEC_WEBSOCKET_VERSION, supported()));
    };
    if v.to_str().is_ok_and(|v| v.trim() == "13") {
        return Ok(());
    }
    Err(ApiError::framework(
        StatusCode::UPGRADE_REQUIRED,
        "websocket_version",
        "unsupported WebSocket version; this server supports 13",
    )
    .with_header(header::SEC_WEBSOCKET_VERSION, supported())
    .with_header(header::UPGRADE, HeaderValue::from_static("websocket")))
}

/// RFC 6455 §4.1 item 10 / §11.3.4: `Sec-WebSocket-Protocol` is a comma-separated list
/// (possibly over several header lines) of unique, non-empty RFC 7230 tokens.
fn offered_protocols(h: &http::HeaderMap) -> Result<Vec<String>, ApiError> {
    let invalid = || {
        rejection::bad_request(
            "websocket_protocol",
            "Sec-WebSocket-Protocol must be a list of unique tokens",
        )
    };
    let mut out: Vec<String> = Vec::new();
    for value in h.get_all(header::SEC_WEBSOCKET_PROTOCOL) {
        let value = value.to_str().map_err(|_| invalid())?;
        for item in value.split(',') {
            let item = item.trim_matches([' ', '\t']);
            if !is_token(item) || out.iter().any(|o| o == item) {
                return Err(invalid());
            }
            out.push(item.to_owned());
        }
    }
    Ok(out)
}

/// RFC 7230 §3.2.6 `token`: one or more `tchar`.
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

impl<S: Sync> FromRequest<S> for WebSocketUpgrade {
    type Rejection = ApiError;

    async fn from_request(cx: &mut Ctx<'_, S>) -> Result<Self, ApiError> {
        let h = &cx.parts.headers;
        // HTTP/2 (RFC 8441 §4–5): Extended CONNECT with `:protocol = websocket`. No
        // Connection/Upgrade headers and no key exchange.
        let h2 = crate::policy::ws_origin::websocket_handshake(
            &cx.parts.method,
            cx.parts.version,
            h,
            &cx.parts.extensions,
        ) == Some(crate::policy::ws_origin::Handshake::H2);
        // HTTP/1.1 (RFC 6455 §4.2.1): a GET carrying the upgrade tokens.
        if !h2
            && (cx.parts.method != http::Method::GET
                || cx.parts.version != http::Version::HTTP_11
                || !header_has_token(h, header::CONNECTION, "upgrade")
                || !header_has_token(h, header::UPGRADE, "websocket"))
        {
            return Err(rejection::bad_request(
                "not_websocket",
                "expected a WebSocket upgrade request",
            ));
        }
        check_version(h)?;
        let key = if h2 {
            None
        } else {
            Some(
                single(h, header::SEC_WEBSOCKET_KEY)
                    .filter(|k| valid_key(k.as_bytes()))
                    .cloned()
                    .ok_or_else(|| {
                        rejection::bad_request(
                            "websocket_key",
                            "Sec-WebSocket-Key must be one base64-encoded 16-byte nonce",
                        )
                    })?,
            )
        };
        let offered = offered_protocols(h)?;
        let on_upgrade = cx.parts.extensions.remove::<hyper::upgrade::OnUpgrade>();
        let admission = cx.parts.extensions.remove::<Admission>();
        let mut config = WebSocketConfig::default();
        config.max_message_size = Some(64 * 1024);
        config.max_frame_size = Some(64 * 1024);
        config.write_buffer_size = 16 * 1024;
        config.max_write_buffer_size = DEFAULT_MAX_WRITE_BUFFER;
        Ok(WebSocketUpgrade {
            key,
            on_upgrade,
            admission,
            config,
            offered,
            selected: None,
            require_protocol: false,
            max_lifetime: None,
            subject: cx.identity.as_ref().map(|i| i.subject.clone()),
            identity: cx.identity.clone(),
            request_id: cx.request_id.clone(),
            route_id: cx.route.id.clone(),
            peer: cx.peer,
            per_ip_max: cx.limits.max_ws_sessions_per_ip,
            per_principal_max: cx.limits.max_ws_sessions_per_principal,
            message_rate: None,
            message_quota: None,
        })
    }
}

impl WebSocketUpgrade {
    /// Maximum inbound message size in bytes (default 64 KiB).
    pub fn max_message_size(mut self, n: usize) -> Self {
        self.config.max_message_size = Some(n);
        self.config.max_frame_size = Some(n);
        self
    }

    /// The authenticated principal, when the route's policy authenticated the handshake.
    pub fn identity(&self) -> Option<&crate::policy::Identity> {
        self.identity.as_ref()
    }

    /// The handshake's request ID (also in the `x-request-id` response header), for
    /// correlating session logs with the HTTP request.
    pub fn request_id(&self) -> &crate::ctx::RequestId {
        &self.request_id
    }

    /// The matched route's ID (as in contracts and flow traces).
    pub fn route_id(&self) -> &str {
        &self.route_id
    }

    /// The TCP peer address, if served by a Poring server.
    pub fn peer(&self) -> Option<std::net::SocketAddr> {
        self.peer
    }

    /// The client IP as Poring's rate limiter resolves it (the TCP peer, or the client
    /// named by trusted proxies' forwarding headers), if served by a Poring server.
    pub fn client_ip(&self) -> Option<std::net::IpAddr> {
        self.admission.as_ref().map(|a| a.client_ip)
    }

    /// Whether the handshake arrived over HTTP/2 (RFC 8441 Extended CONNECT) rather than as
    /// an HTTP/1.1 upgrade.
    pub fn is_http2(&self) -> bool {
        self.key.is_none()
    }

    /// Maximum size of a single inbound frame in bytes (default: the message limit, 64 KiB).
    /// Values above the message limit have no effect. 0 is treated as 1.
    pub fn max_frame_size(mut self, n: usize) -> Self {
        self.config.max_frame_size = Some(n.max(1));
        self
    }

    /// Limits inbound data messages to `messages` per `per` for this session (burst
    /// `messages`). Applies to [managed](Self::managed) and [typed](Self::typed) sessions.
    /// A session over the limit is closed with `1008 Policy Violation` (typed `recv`
    /// returns [`WsError::RateLimited`] once). Raw sockets are not metered. Ping/pong and
    /// close frames are not counted. A `messages` of 0 is treated as 1, a zero `per` as 1 ns.
    pub fn message_rate(mut self, messages: u32, per: std::time::Duration) -> Self {
        self.message_rate = Some((messages, per));
        self
    }

    /// Also meters inbound data messages against a quota shared across sessions (per
    /// client IP or per principal, see [`WsMessageQuota`]). Same enforcement as
    /// [`message_rate`](Self::message_rate).
    pub fn message_quota(mut self, quota: &WsMessageQuota) -> Self {
        self.message_quota = Some(quota.clone());
        self
    }

    fn message_gate(&mut self, client_ip: Option<std::net::IpAddr>) -> MessageGate {
        use crate::policy::rate_limit::RateKeyValue;
        let shared = self.message_quota.take().map(|q| {
            let key = match (&self.subject, q.by_principal, client_ip) {
                (Some(s), true, _) => RateKeyValue::Subject(s.clone()),
                (_, _, Some(ip)) => RateKeyValue::ip(ip),
                _ => RateKeyValue::Unknown,
            };
            (q, key)
        });
        MessageGate {
            local: self.message_rate.map(|(n, per)| Gcra::new(n, per)),
            shared,
        }
    }

    /// Upper bound on the transport's outbound buffer, which must hold one whole outbound
    /// message plus up to 16 KiB of coalesced earlier writes. Default 64 MiB + 16 KiB, so
    /// any message up to 64 MiB can be sent. Sending a message larger than `n - 16 KiB`
    /// fails with [`WsError::Socket`] (`WriteBufferFull`) instead of being sent.
    ///
    /// This is **not** a queue length: `send` already waits until earlier data has been
    /// written to the connection (backpressure), so at most one message is buffered by the
    /// transport at a time whatever this value is.
    pub fn max_write_buffer(mut self, n: usize) -> Self {
        self.config.max_write_buffer_size = n.max(self.config.write_buffer_size + 1);
        self
    }

    /// Subprotocols this endpoint supports, **in the server's order of preference**.
    ///
    /// The first supported protocol that the client also offered (exact, case-sensitive
    /// match) is selected and echoed in `Sec-WebSocket-Protocol`. A protocol the client did
    /// not offer is never selected. Without a match the handshake proceeds with no protocol,
    /// unless [`require_protocol`](Self::require_protocol) is set. Calling this again
    /// replaces the previous selection.
    ///
    /// ```no_run
    /// # use poring::ws::WebSocketUpgrade;
    /// # use poring::response::Response;
    /// async fn chat(ws: WebSocketUpgrade) -> Response {
    ///     let ws = ws.protocols(["chat.v2", "chat.v1"]);
    ///     let version = ws.protocol().map(str::to_owned);
    ///     ws.on_upgrade(move |_sock| async move {
    ///         let _ = version; // e.g. pick a codec
    ///     })
    /// }
    /// ```
    pub fn protocols<I, T>(mut self, supported: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        self.selected = supported
            .into_iter()
            .find_map(|p| self.offered.iter().position(|o| o == p.as_ref()));
        self
    }

    /// Rejects the handshake with `400 websocket_protocol` (before `101`) when no
    /// subprotocol was selected by [`protocols`](Self::protocols).
    pub fn require_protocol(mut self) -> Self {
        self.require_protocol = true;
        self
    }

    /// The selected subprotocol, if any.
    pub fn protocol(&self) -> Option<&str> {
        self.selected.map(|i| self.offered[i].as_str())
    }

    /// Subprotocols offered by the client, in the client's order.
    pub fn offered_protocols(&self) -> impl Iterator<Item = &str> {
        self.offered.iter().map(String::as_str)
    }

    /// A handle that fires when the server begins shutting down (see [`WsShutdown`]).
    pub fn shutdown_signal(&self) -> WsShutdown {
        WsShutdown {
            rx: self
                .admission
                .as_ref()
                .map(|a| a.supervisor.stop.subscribe()),
        }
    }

    /// Maximum duration of the session. When it elapses, a raw or typed session is
    /// cancelled (its socket is dropped without a close frame). A [managed](Self::managed)
    /// session is closed with `1001 Going Away` first.
    pub fn max_lifetime(mut self, d: std::time::Duration) -> Self {
        self.max_lifetime = Some(d);
        self
    }

    /// Production starting point for a public endpoint's inbound limits. Applies:
    ///
    /// | setting | value |
    /// |---|---|
    /// | [`max_message_size`](Self::max_message_size) / [`max_frame_size`](Self::max_frame_size) | 64 KiB |
    /// | [`message_rate`](Self::message_rate) | 50 messages per second per session |
    /// | [`max_lifetime`](Self::max_lifetime) | 24 h |
    ///
    /// Call it first and override afterwards. Settings the preset does not touch
    /// (subprotocols, [`message_quota`](Self::message_quota)) keep their values. It does not
    /// configure origins, trusted proxies, authentication or per-client session caps: those
    /// are app-level ([`WsOrigins`](crate::policy::WsOrigins),
    /// [`Limits::production`](crate::app::Limits::production)). Combine with
    /// [`ManagedUpgrade::production`] for heartbeats, deadlines and the outbound memory
    /// budget. The values are defensible defaults, not a guarantee for every workload.
    ///
    /// ```
    /// use poring::prelude::*;
    /// use poring::ws::{ManagedSocket, WebSocketUpgrade};
    ///
    /// let app = Poring::new()
    ///     .ws("/live", |ws: WebSocketUpgrade| async move {
    ///         ws.production()
    ///             .max_message_size(16 * 1024)
    ///             .managed()
    ///             .production()
    ///             .on_upgrade(|mut sock: ManagedSocket| async move {
    ///                 while let Some(m) = sock.recv().await {
    ///                     if sock.send(m).await.is_err() {
    ///                         break;
    ///                     }
    ///                 }
    ///             })
    ///     })
    ///     .build()
    ///     .unwrap();
    /// # drop(app);
    /// ```
    pub fn production(self) -> Self {
        self.max_message_size(64 * 1024)
            .message_rate(50, std::time::Duration::from_secs(1))
            .max_lifetime(std::time::Duration::from_secs(24 * 60 * 60))
    }

    /// Settings of this upgrade that are unbounded or unusually permissive for a public
    /// endpoint, as human-readable warnings (empty when none). Use it in a startup log or a
    /// test. It never changes behaviour. Raw and typed sessions additionally have no
    /// heartbeat, idle, write or stall deadlines: prefer [`managed`](Self::managed) and
    /// [`ManagedUpgrade::production_warnings`] for long-lived public sessions.
    pub fn production_warnings(&self) -> Vec<String> {
        let mut w = Vec::new();
        let msg = self.config.max_message_size.unwrap_or(usize::MAX);
        if msg > 1 << 20 {
            w.push(format!(
                "max_message_size is {msg} bytes (more than 1 MiB per message)"
            ));
        }
        if self.message_rate.is_none() && self.message_quota.is_none() {
            w.push("no message_rate or message_quota: inbound message rate is unlimited".into());
        }
        if self.max_lifetime.is_none() {
            w.push("no max_lifetime: sessions may live forever".into());
        }
        w
    }

    /// Switches to a managed session, whose socket is driven by Poring: pings, idle
    /// detection and close frames keep working while the handler is not reading. See
    /// [`ManagedSocket`].
    pub fn managed(self) -> ManagedUpgrade {
        ManagedUpgrade {
            inner: self,
            ping_interval: Some(DEFAULT_PING_INTERVAL),
            pong_timeout: Some(DEFAULT_PONG_TIMEOUT),
            idle_timeout: Some(DEFAULT_IDLE_TIMEOUT),
            write_timeout: Some(DEFAULT_WRITE_TIMEOUT),
            stall_timeout: Some(DEFAULT_STALL_TIMEOUT),
            close_timeout: DEFAULT_CLOSE_TIMEOUT,
            queue_messages: MANAGED_QUEUE,
            max_outbound_message: DEFAULT_MAX_OUTBOUND,
            max_queued_bytes: DEFAULT_MAX_OUTBOUND,
        }
    }

    /// Switches to typed JSON messages.
    pub fn typed<In, Out>(self) -> TypedUpgrade<In, Out> {
        TypedUpgrade {
            inner: self,
            _t: PhantomData,
        }
    }

    /// Completes the handshake and runs `f` with the raw socket in a session task owned by
    /// the server.
    ///
    /// The session is admitted against `Limits::max_ws_sessions` first. When the limit is
    /// reached (or the server is shutting down) the response is `503` and `f` never runs.
    /// The session keeps its TCP connection slot until `f` returns, panics or is cancelled
    /// at shutdown (after `Limits::shutdown_grace`).
    pub fn on_upgrade<F, Fut>(self, f: F) -> Response
    where
        F: FnOnce(RawSocket) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        if self.require_protocol && self.selected.is_none() {
            return rejection::bad_request(
                "websocket_protocol",
                "no supported WebSocket subprotocol was offered",
            )
            .into_response();
        }
        let protocol = self.protocol().and_then(|p| HeaderValue::from_str(p).ok());
        // In-process test client / HTTP/2 without extended CONNECT / no supervising
        // server: no upgrade possible.
        let (Some(on_upgrade), Some(admission)) = (self.on_upgrade, self.admission) else {
            return rejection::bad_request("upgrade_unavailable", "connection cannot be upgraded")
                .into_response();
        };
        let counters = admission.supervisor.counters.clone();
        let Ok(session) = admission.supervisor.sessions.clone().try_acquire_owned() else {
            counters.note(WsEvent::RejectedSessionLimit);
            tracing::debug!(route = %self.route_id, request_id = %self.request_id, "websocket handshake refused: session limit");
            return rejection::unavailable("too many WebSocket sessions").into_response();
        };
        let sup = &admission.supervisor;
        let Ok(ip_hold) = sup.hold(SessionKey::Ip(admission.client_ip), self.per_ip_max) else {
            counters.note(WsEvent::RejectedClientCap);
            return rejection::too_many_requests(std::time::Duration::from_secs(1)).into_response();
        };
        let principal_hold = match &self.subject {
            Some(s) => sup.hold(SessionKey::Subject(s.clone()), self.per_principal_max),
            None => Ok(None),
        };
        let Ok(principal_hold) = principal_hold else {
            counters.note(WsEvent::RejectedClientCap);
            return rejection::too_many_requests(std::time::Duration::from_secs(1)).into_response();
        };
        let accept = self
            .key
            .as_ref()
            .map(|k| tungstenite::handshake::derive_accept_key(k.as_bytes()));
        let config = self.config;
        let connection = admission.connection;
        let lifetime = self.max_lifetime;
        let session_counters = counters.clone();
        let h2 = self.key.is_none();
        let spawned = admission.supervisor.spawn(async move {
            // Released when the session ends, however it ends.
            let _permits = (session, connection, ip_hold, principal_hold);
            let _active = ActiveSession::start(session_counters.clone());
            match on_upgrade.await {
                Ok(upgraded) => {
                    let io = hyper_util::rt::TokioIo::new(upgraded);
                    let socket =
                        WebSocketStream::from_raw_socket(io, Role::Server, Some(config)).await;
                    let session = f(socket);
                    match lifetime {
                        Some(d) => {
                            if tokio::time::timeout(d, session).await.is_err() {
                                session_counters.note(WsEvent::LifetimeExpired);
                                tracing::debug!("websocket session reached its maximum lifetime");
                            }
                        }
                        None => session.await,
                    }
                }
                Err(e) => tracing::debug!(error = %e, "websocket upgrade failed"),
            }
        });
        if !spawned {
            counters.note(WsEvent::RejectedShutdown);
            return rejection::unavailable("server is shutting down").into_response();
        }
        counters.note(WsEvent::Accepted);
        tracing::debug!(
            route = %self.route_id,
            request_id = %self.request_id,
            transport = if h2 { "h2" } else { "http/1.1" },
            "websocket session accepted"
        );
        let mut r = match accept {
            // HTTP/1.1: 101 with the RFC 6455 accept exchange.
            Some(accept) => {
                let mut r = StatusCode::SWITCHING_PROTOCOLS.into_response();
                let h = r.headers_mut();
                h.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
                h.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
                if let Ok(v) = HeaderValue::from_str(&accept) {
                    h.insert(header::SEC_WEBSOCKET_ACCEPT, v);
                }
                r
            }
            // HTTP/2: a 2xx without a body turns the stream into the tunnel (RFC 8441 §5).
            None => StatusCode::OK.into_response(),
        };
        let h = r.headers_mut();
        if let Some(p) = protocol {
            h.insert(header::SEC_WEBSOCKET_PROTOCOL, p);
        }
        r
    }
}

/// Default outbound buffer bound: one 64 MiB message (tungstenite's default inbound limit,
/// i.e. what a default peer accepts) plus the 16 KiB write-coalescing buffer.
const DEFAULT_MAX_WRITE_BUFFER: usize = (64 << 20) + 16 * 1024;
const DEFAULT_PING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
const DEFAULT_PONG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
/// Default per-session outbound byte budget (and per-message limit): 64 MiB, matching what a
/// default peer accepts inbound.
const DEFAULT_MAX_OUTBOUND: usize = 64 << 20;
const DEFAULT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(75);
/// Default bound on writing one outbound message (from handing it to the socket until it is
/// flushed): 64 MiB still fits at about 9 Mbit/s.
const DEFAULT_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const DEFAULT_CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Default bound on how long an inbound message may wait for the handler to take it.
const DEFAULT_STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// Default capacity (in messages) of each direction's queue between the handler and the
/// I/O pump.
const MANAGED_QUEUE: usize = 16;
/// Largest byte budget a semaphore reservation can express.
const MAX_BUDGET: usize = u32::MAX as usize;

/// A managed upgrade in progress (see [`WebSocketUpgrade::managed`]).
#[derive(Debug)]
pub struct ManagedUpgrade {
    inner: WebSocketUpgrade,
    ping_interval: Option<std::time::Duration>,
    pong_timeout: Option<std::time::Duration>,
    idle_timeout: Option<std::time::Duration>,
    write_timeout: Option<std::time::Duration>,
    stall_timeout: Option<std::time::Duration>,
    close_timeout: std::time::Duration,
    queue_messages: usize,
    max_outbound_message: usize,
    max_queued_bytes: usize,
}

impl ManagedUpgrade {
    /// Interval between server pings (default 30 s). Pings are sent even while the
    /// handler is not reading.
    pub fn ping_interval(mut self, d: std::time::Duration) -> Self {
        self.ping_interval = Some(d);
        self
    }

    /// Disables server pings (and with them pong enforcement).
    pub fn no_ping(mut self) -> Self {
        self.ping_interval = None;
        self
    }

    /// How long the peer has to answer a heartbeat ping with the matching pong (default
    /// 20 s). Each ping carries a fresh 8-byte challenge. Only a pong echoing it counts:
    /// data messages, pings and unsolicited or stale pongs do not. At most one challenge is
    /// outstanding, so a tick that finds one still unanswered sends no new ping. When the
    /// deadline passes the session is closed with `1001` and counted in
    /// [`WsStats::heartbeat_timeouts`]. The close waits at most
    /// `min(pong_timeout, close_timeout)` for the unresponsive peer's reply. If an outbound
    /// write is blocked, the close frame cannot be delivered and the connection is dropped
    /// at once. While the handler is not taking inbound messages
    /// (and the pump therefore does not read the socket) the deadline is paused, so a slow
    /// handler never causes a heartbeat failure.
    pub fn pong_timeout(mut self, d: std::time::Duration) -> Self {
        self.pong_timeout = Some(d);
        self
    }

    /// Sends heartbeat pings without requiring pongs (liveness then rests on the idle
    /// timeout alone).
    pub fn no_pong_timeout(mut self) -> Self {
        self.pong_timeout = None;
        self
    }

    /// Capacity, in messages, of each direction's queue between the handler and the I/O
    /// pump (default 16). `0` is treated as `1`, since a queue must hold one message.
    pub fn queue_messages(mut self, n: usize) -> Self {
        self.queue_messages = n.max(1);
        self
    }

    /// Largest message [`ManagedSocket::send`] accepts (default 64 MiB). A larger message
    /// fails immediately with [`WsError::Socket`] carrying
    /// `tungstenite::Error::Capacity(MessageTooLong { .. })`, and the session continues.
    /// The effective limit is never above [`max_queued_bytes`](Self::max_queued_bytes).
    pub fn max_outbound_message(mut self, n: usize) -> Self {
        self.max_outbound_message = n;
        self
    }

    /// Byte budget of the outbound queue (default 64 MiB, at most `u32::MAX`): the summed
    /// payload sizes of messages accepted by `send` but not yet written to the socket.
    /// `send` waits (first come, first served across all senders of the session) while the
    /// budget is exhausted, and fails once the session has closed. Bytes are returned when
    /// a message is written or dropped because the session ended. A `send` cancelled while
    /// waiting reserves nothing. Together with [`queue_messages`](Self::queue_messages)
    /// this bounds a session's queued outbound memory. Application `Ping`/`Pong` payloads
    /// count against the budget. Close frames and the pump's own heartbeat pings (at most
    /// 125 bytes each) do not.
    pub fn max_queued_bytes(mut self, n: usize) -> Self {
        self.max_queued_bytes = n.min(MAX_BUDGET);
        self
    }

    /// Closes the session (`1001`) when nothing at all (data, ping, pong or close) has
    /// been received from the peer for this long (default 75 s). Time spent waiting for
    /// the handler to take an inbound message does not count. The socket keeps being read
    /// while an outbound write is blocked, so a peer that stops reading is still subject to
    /// this timeout.
    pub fn idle_timeout(mut self, d: std::time::Duration) -> Self {
        self.idle_timeout = Some(d);
        self
    }

    /// Disables the idle timeout.
    pub fn no_idle_timeout(mut self) -> Self {
        self.idle_timeout = None;
        self
    }

    /// Longest time one outbound message may take to be written to the socket, from when
    /// the pump hands it to the transport until it is flushed (default 60 s). A peer that
    /// stops reading eventually blocks writes (once the TCP or HTTP/2 flow-control windows
    /// are full). When this deadline passes the session ends without a close handshake (a
    /// close frame could not be delivered either), counted in
    /// [`WsStats::write_timeouts`]. Independently of this setting, a blocked write never
    /// delays heartbeat, idle, lifetime or shutdown handling: the pump keeps reading and
    /// keeps its timers running while a write is in progress.
    pub fn write_timeout(mut self, d: std::time::Duration) -> Self {
        self.write_timeout = Some(d);
        self
    }

    /// Disables the write timeout: a blocked write then ends only through the heartbeat,
    /// idle timeout, `max_lifetime`, shutdown or the peer disconnecting.
    pub fn no_write_timeout(mut self) -> Self {
        self.write_timeout = None;
        self
    }

    /// Longest time an inbound message may wait for the handler to take it (default 60 s).
    ///
    /// When the handler stops calling `recv` (or a split [`ManagedReceiver`] is kept but
    /// never read), the inbound queue fills and the pump stops reading the socket, which
    /// pauses the idle and pong timers so a slow handler is not blamed on the peer. This
    /// deadline is independent of those timers: once a message has waited this long, the
    /// session is closed with `1013 Try Again Later`, counted in
    /// [`WsStats::inbound_stalls`], and the handler gets `close_timeout` to return before it
    /// is cancelled. Its session slot, connection slot, queues and buffers are then released,
    /// so a stalled handler can never hold them indefinitely. Dropping the receiver instead
    /// (the handler only sends) never stalls: inbound data is then discarded.
    pub fn stall_timeout(mut self, d: std::time::Duration) -> Self {
        self.stall_timeout = Some(d);
        self
    }

    /// Disables the inbound stall deadline: a handler that stops reading then holds its
    /// session until `max_lifetime`, shutdown or a heartbeat write failing after the peer
    /// disconnected (the socket is not read while a message waits, so a disconnect is only
    /// noticed when writing). Prefer a long [`stall_timeout`](Self::stall_timeout) over
    /// disabling it.
    pub fn no_stall_timeout(mut self) -> Self {
        self.stall_timeout = None;
        self
    }

    /// How long to wait for the peer's close reply after sending a close frame (default
    /// 5 s).
    pub fn close_timeout(mut self, d: std::time::Duration) -> Self {
        self.close_timeout = d;
        self
    }

    /// See [`WebSocketUpgrade::max_lifetime`].
    pub fn max_lifetime(mut self, d: std::time::Duration) -> Self {
        self.inner.max_lifetime = Some(d);
        self
    }

    /// Production starting point for a managed session's deadlines and memory budget:
    ///
    /// | setting | default | `production()` |
    /// |---|---|---|
    /// | [`ping_interval`](Self::ping_interval) / [`pong_timeout`](Self::pong_timeout) | 30 s / 20 s | 30 s / 20 s |
    /// | [`idle_timeout`](Self::idle_timeout) | 75 s | 90 s |
    /// | [`write_timeout`](Self::write_timeout) | 60 s | 30 s |
    /// | [`stall_timeout`](Self::stall_timeout) | 60 s | 30 s |
    /// | [`close_timeout`](Self::close_timeout) | 5 s | 5 s |
    /// | [`queue_messages`](Self::queue_messages) | 16 | 32 |
    /// | [`max_outbound_message`](Self::max_outbound_message) | 64 MiB | 256 KiB |
    /// | [`max_queued_bytes`](Self::max_queued_bytes) | 64 MiB | 1 MiB |
    ///
    /// With the inbound limits of [`WebSocketUpgrade::production`] (64 KiB messages), the
    /// worst case is about 3.4 MiB per session (inbound 64 KiB × 33, outbound 1 MiB plus one
    /// 256 KiB message in flight). Call it before your own overrides. Inbound limits,
    /// origins, authentication and per-client caps are configured elsewhere (see
    /// [`WebSocketUpgrade::production`]).
    pub fn production(self) -> Self {
        use std::time::Duration;
        self.ping_interval(Duration::from_secs(30))
            .pong_timeout(Duration::from_secs(20))
            .idle_timeout(Duration::from_secs(90))
            .write_timeout(Duration::from_secs(30))
            .stall_timeout(Duration::from_secs(30))
            .close_timeout(DEFAULT_CLOSE_TIMEOUT)
            .queue_messages(32)
            .max_outbound_message(256 * 1024)
            .max_queued_bytes(1 << 20)
    }

    /// Like [`WebSocketUpgrade::production_warnings`], plus the managed deadlines and the
    /// outbound memory budget: disabled heartbeats together with no idle timeout, disabled
    /// write or stall deadlines, and outbound budgets above 8 MiB.
    pub fn production_warnings(&self) -> Vec<String> {
        let mut w = self.inner.production_warnings();
        if self.ping_interval.is_none() && self.idle_timeout.is_none() {
            w.push("no ping and no idle_timeout: dead peers are never detected".into());
        }
        if self.ping_interval.is_some() && self.pong_timeout.is_none() {
            w.push("no pong_timeout: unanswered heartbeats never end the session".into());
        }
        if self.write_timeout.is_none() {
            w.push("no write_timeout: a peer that stops reading holds its session".into());
        }
        if self.stall_timeout.is_none() {
            w.push("no stall_timeout: a handler that stops reading holds its session".into());
        }
        if self.max_queued_bytes > 8 << 20 {
            w.push(format!(
                "max_queued_bytes is {} bytes (outbound budget above 8 MiB per session)",
                self.max_queued_bytes
            ));
        }
        if self.max_outbound_message > 8 << 20 {
            w.push(format!(
                "max_outbound_message is {} bytes (above 8 MiB)",
                self.max_outbound_message
            ));
        }
        w
    }

    /// The selected subprotocol, if any.
    pub fn protocol(&self) -> Option<&str> {
        self.inner.protocol()
    }

    /// A handle that fires when the server begins shutting down.
    pub fn shutdown_signal(&self) -> WsShutdown {
        self.inner.shutdown_signal()
    }

    /// Switches to typed JSON messages on top of the managed session (pings, idle and
    /// lifetime handling, message limits and close handling as for [`ManagedSocket`]).
    pub fn typed<In, Out>(self) -> ManagedTypedUpgrade<In, Out> {
        ManagedTypedUpgrade {
            inner: self,
            _t: PhantomData,
        }
    }

    /// Completes the handshake and runs `f` with a [`ManagedSocket`]. The I/O pump and
    /// `f` run concurrently in the same supervised session task.
    ///
    /// Lifecycle: the session ends when both sides are done, and never waits on the
    /// handler indefinitely once the transport is gone.
    ///
    /// * The handler returns (or drops every sender): the pump closes with `1000` and the
    ///   session ends once the close handshake finished (bounded by `close_timeout`).
    /// * The transport ends first (peer close or disconnect, protocol error, idle or
    ///   heartbeat timeout, lifetime, shutdown): `recv` returns `None` and `send` fails, and
    ///   the handler gets `close_timeout` to return. After that it is cancelled (dropped at
    ///   its next await point). Its permits, queues and buffers are released either way.
    /// * The handler panics: the panic is caught, counted in
    ///   [`WsStats::sessions_panicked`], and the peer gets `1011`.
    pub fn on_upgrade<F, Fut>(mut self, f: F) -> Response
    where
        F: FnOnce(ManagedSocket) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let cfg = PumpConfig {
            ping: self.ping_interval.filter(|d| !d.is_zero()),
            pong: self.pong_timeout.filter(|d| !d.is_zero()),
            idle: self.idle_timeout.filter(|d| !d.is_zero()),
            write: self.write_timeout.filter(|d| !d.is_zero()),
            stall: self.stall_timeout.filter(|d| !d.is_zero()),
            close: self.close_timeout,
            lifetime: self.inner.max_lifetime.take(),
        };
        let stop = self.inner.shutdown_signal();
        let client_ip = self.inner.admission.as_ref().map(|a| a.client_ip);
        let gate = self.inner.message_gate(client_ip);
        let counters = self
            .inner
            .admission
            .as_ref()
            .map(|a| a.supervisor.counters.clone());
        let meter = SessionMeter::new(counters.clone());
        let queue = self.queue_messages.max(1);
        let budget = OutBudget {
            bytes: std::sync::Arc::new(tokio::sync::Semaphore::new(self.max_queued_bytes)),
            max_message: self.max_outbound_message.min(self.max_queued_bytes),
        };
        self.inner.on_upgrade(move |raw| async move {
            let (in_tx, in_rx) = tokio::sync::mpsc::channel(queue);
            let (out_tx, out_rx) = tokio::sync::mpsc::channel(queue);
            let (panic_tx, panic_rx) = tokio::sync::oneshot::channel::<()>();
            let sock = ManagedSocket {
                rx: in_rx,
                tx: OutboundTx {
                    tx: out_tx,
                    budget: budget.clone(),
                    counters: counters.clone(),
                },
                stop: stop.clone(),
            };
            let hard_cap = cfg.lifetime.map(|d| d + cfg.close);
            let io = Pump {
                out_rx,
                in_tx,
                cfg,
                stop,
                gate,
                meter,
                budget: budget.bytes,
                panicked: panic_rx,
            };
            let session = async move {
                let pump = pump(raw, io);
                tokio::pin!(pump);
                let mut handler = crate::app::tasks::CatchUnwind(Box::pin(f(sock)));
                tokio::select! {
                    biased;
                    () = &mut pump => {
                        // The transport is gone: the handler observes closed queues and
                        // gets `close_timeout` to return before it is cancelled.
                        match tokio::time::timeout(cfg.close, &mut handler).await {
                            Ok(Err(())) => note_panic(counters.as_deref()),
                            Ok(Ok(())) => {}
                            Err(_) => tracing::debug!(
                                "websocket handler still running after its session closed; cancelled"
                            ),
                        }
                    }
                    r = &mut handler => {
                        if r.is_err() {
                            note_panic(counters.as_deref());
                            let _ = panic_tx.send(());
                        } else {
                            drop(panic_tx);
                        }
                        // Closes with `1000` once every sender is gone (bounded close).
                        pump.await;
                    }
                }
            };
            match hard_cap {
                Some(d) => {
                    let _ = tokio::time::timeout(d, session).await;
                }
                None => session.await,
            }
        })
    }
}

fn note_panic(counters: Option<&WsCounters>) {
    if let Some(c) = counters {
        c.note(WsEvent::Panicked);
    }
    tracing::warn!("websocket session handler panicked");
}

/// Per-session outbound byte budget shared by every sender of the session.
#[derive(Clone, Debug)]
struct OutBudget {
    bytes: std::sync::Arc<tokio::sync::Semaphore>,
    max_message: usize,
}

/// Sending side of the outbound queue: a bounded channel plus the byte budget.
#[derive(Clone, Debug)]
struct OutboundTx {
    tx: tokio::sync::mpsc::Sender<Outbound>,
    budget: OutBudget,
    counters: Option<std::sync::Arc<WsCounters>>,
}

fn closed_error() -> WsError {
    WsError::Socket(tungstenite::Error::AlreadyClosed)
}

impl OutboundTx {
    async fn send(&self, msg: Message) -> Result<(), WsError> {
        let out = match msg {
            Message::Close(frame) => Outbound::Close(frame),
            m => {
                let len = m.len();
                if len > self.budget.max_message {
                    return Err(WsError::Socket(tungstenite::Error::Capacity(
                        tungstenite::error::CapacityError::MessageTooLong {
                            size: len,
                            max_size: self.budget.max_message,
                        },
                    )));
                }
                // First come, first served across senders. Fails once the pump has closed
                // the budget. A wait cancelled here reserves nothing.
                let n = u32::try_from(len).map_err(|_| closed_error())?;
                let reserved = match self.budget.bytes.clone().try_acquire_many_owned(n) {
                    Ok(r) => r,
                    Err(tokio::sync::TryAcquireError::Closed) => return Err(closed_error()),
                    Err(tokio::sync::TryAcquireError::NoPermits) => {
                        self.note_backpressure();
                        self.budget
                            .bytes
                            .clone()
                            .acquire_many_owned(n)
                            .await
                            .map_err(|_| closed_error())?
                    }
                };
                Outbound::Message(m, reserved)
            }
        };
        match self.tx.try_reserve() {
            Ok(slot) => {
                slot.send(out);
                Ok(())
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => Err(closed_error()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(())) => {
                self.note_backpressure();
                self.tx.send(out).await.map_err(|_| closed_error())
            }
        }
    }

    fn note_backpressure(&self) {
        if let Some(c) = &self.counters {
            c.note(WsEvent::OutboundBackpressure);
        }
    }

    async fn close(&self, frame: Option<tungstenite::protocol::CloseFrame>) {
        let _ = self.tx.send(Outbound::Close(frame)).await;
    }
}

/// A WebSocket whose I/O is driven by Poring (see [`WebSocketUpgrade::managed`]).
///
/// Guarantees, independent of how often the handler calls [`recv`](Self::recv):
///
/// * pings are sent every `ping_interval`, and a ping whose matching pong does not arrive
///   within `pong_timeout` closes the session with `1001`.
/// * a peer that sends nothing for `idle_timeout` is closed with `1001`.
/// * one outbound message that cannot be written within `write_timeout` ends the session.
///   Reading, heartbeats, timeouts and shutdown keep working while a write is blocked
///   (idle and heartbeat timeouts then drop the connection without a close frame, which
///   could not reach a peer that is not reading).
/// * `max_lifetime` and server shutdown close the session with `1001`.
/// * when the handler returns or drops the socket, the session closes with `1000`.
/// * every close waits at most `close_timeout` for the peer's reply.
/// * a peer close is answered with the peer's code (`1002` for codes that must not be sent).
/// * invalid UTF-8 fails the session with `1007`, an oversized message with `1009`, and any
///   other protocol violation with `1002`, without waiting for a reply.
///
/// Inbound and outbound messages pass through bounded queues (16 messages by default, see
/// [`ManagedUpgrade::queue_messages`]): a handler that stops reading eventually stops the
/// pump from reading data (pings are still sent and the idle and pong timers are paused
/// meanwhile), and `send` waits while the outbound queue is full or its byte budget
/// ([`ManagedUpgrade::max_queued_bytes`]) is exhausted.
/// Use [`WebSocketUpgrade::on_upgrade`] for full control of the raw socket instead. None of
/// these guarantees apply there.
#[derive(Debug)]
pub struct ManagedSocket {
    rx: tokio::sync::mpsc::Receiver<Message>,
    tx: OutboundTx,
    stop: WsShutdown,
}

#[derive(Debug)]
enum Outbound {
    /// A message and its reservation in the byte budget (returned when dropped).
    Message(Message, tokio::sync::OwnedSemaphorePermit),
    Close(Option<tungstenite::protocol::CloseFrame>),
}

impl ManagedSocket {
    /// The next text or binary message. `None` once the session is closing or closed.
    pub async fn recv(&mut self) -> Option<Message> {
        self.rx.recv().await
    }

    /// Queues a message for sending. Waits while the outbound queue is full or its byte
    /// budget is exhausted. Fails once the session is closed, and fails immediately for a
    /// message above [`ManagedUpgrade::max_outbound_message`]. Control frames are managed
    /// by Poring: `Ping`/`Pong` are sent as given, `Close` closes the session.
    pub async fn send(&mut self, msg: Message) -> Result<(), WsError> {
        self.tx.send(msg).await
    }

    /// Closes the session with `frame` (or `1000` when `None`). Codes that must not be sent
    /// (1004–1006, 1015, unassigned 1014–2999, below 1000, 5000 and above) are replaced by
    /// `1011`. Reasons longer than 123 bytes are truncated at a character boundary.
    pub async fn close(self, frame: Option<tungstenite::protocol::CloseFrame>) {
        self.tx.close(frame).await;
    }

    /// A handle that fires when the server begins shutting down.
    pub fn shutdown_signal(&self) -> WsShutdown {
        self.stop.clone()
    }

    /// Splits the socket into a receiver and a cloneable sender, so several tasks can send
    /// concurrently while one task receives. Messages from all senders go through the same
    /// bounded queue and byte budget, in the order the queue accepts them. The session closes
    /// with `1000` once the receiver's owner and every sender are gone (or on `close`).
    pub fn split(self) -> (ManagedReceiver, ManagedSender) {
        (
            ManagedReceiver { rx: self.rx },
            ManagedSender {
                tx: self.tx,
                stop: self.stop,
            },
        )
    }
}

/// Receiving half of a [`ManagedSocket`] (see [`ManagedSocket::split`]).
#[derive(Debug)]
pub struct ManagedReceiver {
    rx: tokio::sync::mpsc::Receiver<Message>,
}

impl ManagedReceiver {
    /// The next text or binary message. `None` once the session is closing or closed.
    pub async fn recv(&mut self) -> Option<Message> {
        self.rx.recv().await
    }
}

/// Cloneable sending half of a [`ManagedSocket`] (see [`ManagedSocket::split`]).
#[derive(Clone, Debug)]
pub struct ManagedSender {
    tx: OutboundTx,
    stop: WsShutdown,
}

impl ManagedSender {
    /// Queues a message (same semantics as [`ManagedSocket::send`]).
    pub async fn send(&self, msg: Message) -> Result<(), WsError> {
        self.tx.send(msg).await
    }

    /// Closes the session (same semantics as [`ManagedSocket::close`]).
    pub async fn close(&self, frame: Option<tungstenite::protocol::CloseFrame>) {
        self.tx.close(frame).await;
    }

    /// A handle that fires when the server begins shutting down.
    pub fn shutdown_signal(&self) -> WsShutdown {
        self.stop.clone()
    }
}

/// A managed upgrade with typed JSON messages (see [`ManagedUpgrade::typed`]).
pub struct ManagedTypedUpgrade<In, Out> {
    inner: ManagedUpgrade,
    _t: PhantomData<fn() -> (In, Out)>,
}

impl<In, Out> std::fmt::Debug for ManagedTypedUpgrade<In, Out> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedTypedUpgrade")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl<In, Out> ManagedTypedUpgrade<In, Out>
where
    In: DeserializeOwned + PoringSchema + Send + 'static,
    Out: Serialize + Send + 'static,
{
    /// Completes the handshake and runs `f` with a [`ManagedTypedSocket`].
    pub fn on_upgrade<F, Fut>(self, f: F) -> Response
    where
        F: FnOnce(ManagedTypedSocket<In, Out>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.inner.on_upgrade(move |sock| {
            f(ManagedTypedSocket {
                inner: sock,
                _t: PhantomData,
            })
        })
    }
}

/// A managed WebSocket carrying typed JSON messages: the guarantees of [`ManagedSocket`]
/// plus decoding and [`PoringSchema`] validation of inbound messages.
pub struct ManagedTypedSocket<In, Out> {
    inner: ManagedSocket,
    _t: PhantomData<fn() -> (In, Out)>,
}

impl<In, Out> std::fmt::Debug for ManagedTypedSocket<In, Out> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedTypedSocket").finish_non_exhaustive()
    }
}

impl<In, Out> ManagedTypedSocket<In, Out>
where
    In: DeserializeOwned + PoringSchema,
    Out: Serialize,
{
    /// The next decoded and validated message. `None` once the session is closing or
    /// closed. Decode and validation failures are returned and the session continues.
    pub async fn recv(&mut self) -> Option<Result<In, WsError>> {
        let msg = self.inner.recv().await?;
        let parsed = match &msg {
            Message::Text(t) => serde_json::from_slice::<In>(t.as_bytes()),
            Message::Binary(b) => serde_json::from_slice::<In>(b),
            // The pump only delivers data messages.
            _ => return Some(Err(WsError::Socket(tungstenite::Error::AlreadyClosed))),
        };
        Some(match parsed {
            Ok(v) => {
                let issues = crate::schema::validate(&v);
                if issues.is_empty() {
                    Ok(v)
                } else {
                    Err(WsError::Invalid(issues))
                }
            }
            Err(e) => Err(e.into()),
        })
    }

    /// Serialises and queues a message (same waiting and limits as [`ManagedSocket::send`]).
    pub async fn send(&mut self, msg: &Out) -> Result<(), WsError> {
        let s = serde_json::to_string(msg)?;
        self.inner.send(Message::text(s)).await
    }

    /// Closes the session with `frame` (or `1000`). See [`ManagedSocket::close`].
    pub async fn close(self, frame: Option<tungstenite::protocol::CloseFrame>) {
        self.inner.close(frame).await;
    }

    /// A handle that fires when the server begins shutting down.
    pub fn shutdown_signal(&self) -> WsShutdown {
        self.inner.shutdown_signal()
    }

    /// The underlying untyped managed socket.
    pub fn into_inner(self) -> ManagedSocket {
        self.inner
    }
}

#[derive(Clone, Copy)]
struct PumpConfig {
    ping: Option<std::time::Duration>,
    pong: Option<std::time::Duration>,
    idle: Option<std::time::Duration>,
    write: Option<std::time::Duration>,
    stall: Option<std::time::Duration>,
    close: std::time::Duration,
    lifetime: Option<std::time::Duration>,
}

/// Maximum close reason length: a close frame's payload (2-byte code + reason) is a control
/// frame payload, at most 125 bytes (RFC 6455 §5.5).
const MAX_CLOSE_REASON: usize = 123;

/// Makes an application-supplied close frame valid on the wire: codes that must not be sent
/// (RFC 6455 §7.4: 1004–1006, 1015, unassigned 1014–2999, < 1000, >= 5000) become `1011`
/// with no reason, and over-long reasons are cut at a character boundary.
fn sanitize_close(
    frame: Option<tungstenite::protocol::CloseFrame>,
) -> Option<tungstenite::protocol::CloseFrame> {
    use tungstenite::protocol::frame::coding::CloseCode;
    frame.map(|mut f| {
        if !f.code.is_allowed() {
            tracing::debug!(
                code = u16::from(f.code),
                "replacing a reserved close code with 1011"
            );
            return tungstenite::protocol::CloseFrame {
                code: CloseCode::Error,
                reason: "".into(),
            };
        }
        if f.reason.len() > MAX_CLOSE_REASON {
            let r = f.reason.as_str();
            let mut n = MAX_CLOSE_REASON;
            while !r.is_char_boundary(n) {
                n -= 1;
            }
            f.reason = r[..n].to_owned().into();
        }
        f
    })
}

/// The close code with which to fail the connection after a read error (RFC 6455 §7.1.7,
/// §7.4.1), or `None` when no close frame should be sent (I/O errors, already closed).
fn failure_code(e: &tungstenite::Error) -> Option<tungstenite::protocol::frame::coding::CloseCode> {
    use tungstenite::protocol::frame::coding::CloseCode;
    match e {
        tungstenite::Error::Utf8(_) => Some(CloseCode::Invalid),
        tungstenite::Error::Capacity(_) => Some(CloseCode::Size),
        // The peer vanished without a close frame: an abnormal disconnect (1006), not a
        // protocol violation, and there is nobody left to send a close frame to.
        tungstenite::Error::Protocol(
            tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
        ) => None,
        tungstenite::Error::Protocol(_) => Some(CloseCode::Protocol),
        _ => None,
    }
}

/// Fails the connection after a read error: sends the matching close frame (bounded) and
/// does not wait for a reply. Logs only the code, never payload bytes.
async fn fail_session(ws: &mut RawSocket, e: &tungstenite::Error, bound: std::time::Duration) {
    use tungstenite::protocol::frame::coding::CloseCode;
    let Some(code) = failure_code(e) else {
        tracing::debug!("websocket session ended by a transport error");
        return;
    };
    tracing::debug!(code = u16::from(code), "failing websocket session");
    let reason = match code {
        CloseCode::Invalid => "invalid utf-8",
        CloseCode::Size => "message too big",
        _ => "protocol error",
    };
    let _ = tokio::time::timeout(bound, ws.close(close_frame(code, reason))).await;
}

fn close_frame(
    code: tungstenite::protocol::frame::coding::CloseCode,
    reason: &'static str,
) -> Option<tungstenite::protocol::CloseFrame> {
    Some(tungstenite::protocol::CloseFrame {
        code,
        reason: reason.into(),
    })
}

/// Sends `frame` and waits (bounded) for the peer's close reply.
async fn close_session(
    ws: &mut RawSocket,
    frame: Option<tungstenite::protocol::CloseFrame>,
    bound: std::time::Duration,
) {
    let _ = tokio::time::timeout(bound, async {
        if ws.close(frame).await.is_ok() {
            while let Some(Ok(_)) = ws.next().await {}
        }
    })
    .await;
}

/// The pump's side of a managed session: queues, configuration and accounting.
struct Pump {
    out_rx: tokio::sync::mpsc::Receiver<Outbound>,
    in_tx: tokio::sync::mpsc::Sender<Message>,
    cfg: PumpConfig,
    stop: WsShutdown,
    gate: MessageGate,
    meter: SessionMeter,
    /// Closed when the pump ends, so senders waiting for budget fail instead of hanging.
    budget: std::sync::Arc<tokio::sync::Semaphore>,
    /// Fires when the handler panicked (dropped unfired when it returned normally).
    panicked: tokio::sync::oneshot::Receiver<()>,
}

/// An outstanding heartbeat challenge.
struct Challenge {
    payload: [u8; 8],
    deadline: tokio::time::Instant,
}

/// Drives a managed session's socket until it closes. Owns the socket. Talks to the
/// handler through two bounded queues. Wakes only on I/O, queue activity or its timers.
async fn pump(mut ws: RawSocket, io: Pump) {
    let budget = io.budget.clone();
    run_pump(&mut ws, io).await;
    // Wake senders waiting for budget: the session is over. Queued messages (and their
    // reservations) were dropped with the receiver.
    budget.close();
    // Dropping `in_tx` (in `io`) made `ManagedSocket::recv` return `None`.
}

/// An outbound write in progress: the frame was handed to the socket and is being flushed.
struct Writing {
    /// The written data message's byte-budget reservation (none for a heartbeat ping),
    /// returned when the flush completes or the session ends.
    _reserved: Option<tokio::sync::OwnedSemaphorePermit>,
    /// `write_timeout` deadline, if enabled.
    deadline: Option<tokio::time::Instant>,
}

/// One socket event (see [`socket_event`]).
enum SocketEvent {
    Read(Option<Result<Message, tungstenite::Error>>),
    Flushed(Result<(), tungstenite::Error>),
}

/// The next socket event: an inbound message (when `read`) or the completion of the
/// current flush (when `flush`). Both directions progress concurrently on the one socket:
/// tokio-tungstenite keeps separate read and write wakers, and tungstenite keeps reading
/// (and retries its own pong and close replies later) while a write would block. So a peer
/// that stops reading never stops the pump from reading, or from running its timers.
fn socket_event(
    ws: &mut RawSocket,
    read: bool,
    flush: bool,
) -> impl Future<Output = SocketEvent> + '_ {
    use futures_util::{Sink, Stream};
    use std::pin::Pin;
    use std::task::Poll;
    std::future::poll_fn(move |cx| {
        if flush && let Poll::Ready(r) = Pin::new(&mut *ws).poll_flush(cx) {
            return Poll::Ready(SocketEvent::Flushed(r));
        }
        if read && let Poll::Ready(m) = Pin::new(&mut *ws).poll_next(cx) {
            return Poll::Ready(SocketEvent::Read(m));
        }
        Poll::Pending
    })
}

/// Hands one frame to the socket without waiting for it to be written. The caller then
/// drives the flush through [`socket_event`]. A frame that cannot be written at once stays
/// in tungstenite's bounded write buffer (`max_write_buffer`).
fn start_write(ws: &mut RawSocket, m: Message) -> Result<(), tungstenite::Error> {
    futures_util::Sink::start_send(std::pin::Pin::new(ws), m)
}

async fn run_pump(ws: &mut RawSocket, io: Pump) {
    use tokio::time::{Instant, sleep_until};
    use tungstenite::protocol::frame::coding::CloseCode;

    let Pump {
        mut out_rx,
        in_tx,
        cfg,
        mut stop,
        mut gate,
        mut meter,
        budget: _,
        mut panicked,
    } = io;
    let start = Instant::now();
    let far = start + std::time::Duration::from_secs(60 * 60 * 24 * 365);
    let lifetime_at = cfg.lifetime.map_or(far, |d| start + d);
    let mut last_seen = start;
    let mut ping = cfg.ping.map(|d| {
        let mut i = tokio::time::interval_at(start + d, d);
        i.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        i
    });
    let mut challenge: Option<Challenge> = None;
    let mut ping_seq: u64 = 0;
    // An inbound message waiting for room in the handler's queue. The socket is not read
    // (and the idle and pong timers are paused) meanwhile.
    let mut pending: Option<Message> = None;
    let mut paused_at = start;
    let mut deliver = true;
    let mut handler_watch = true;
    // At most one outbound data message is in flight. The next is taken from the queue
    // once it is flushed. Reading and every timer keep running meanwhile.
    let mut writing: Option<Writing> = None;

    loop {
        let idle_at = cfg.idle.map_or(far, |d| last_seen + d);
        let pong_at = challenge.as_ref().map_or(far, |c| c.deadline);
        let write_at = writing.as_ref().and_then(|w| w.deadline);
        // Runs only while an inbound message waits for the handler, and is not paused by it.
        let stall_at = match (pending.is_some(), cfg.stall) {
            (true, Some(d)) => Some(paused_at + d),
            _ => None,
        };
        let (read, flush) = (pending.is_none(), writing.is_some());
        // Publishes counts of quiet sessions (also with `no_ping`) within `METER_INTERVAL`.
        let meter_at = meter.flush_deadline();
        tokio::select! {
            biased;
            _ = stop.wait() => {
                meter.note(WsEvent::ShutdownClose);
                close_session(ws, close_frame(CloseCode::Away, "server shutting down"), cfg.close).await;
                break;
            }
            r = &mut panicked, if handler_watch => {
                if r.is_ok() {
                    close_session(ws, close_frame(CloseCode::Error, "internal error"), cfg.close).await;
                    break;
                }
                handler_watch = false;
            }
            _ = sleep_until(lifetime_at), if cfg.lifetime.is_some() => {
                meter.note(WsEvent::LifetimeExpired);
                close_session(ws, close_frame(CloseCode::Away, "session lifetime exceeded"), cfg.close).await;
                break;
            }
            _ = sleep_until(idle_at), if cfg.idle.is_some() && pending.is_none() => {
                tracing::debug!("websocket session idle timeout");
                meter.note(WsEvent::IdleTimeout);
                // A peer that neither sends nor takes data cannot receive a close frame
                // queued behind the blocked write: drop the connection instead of waiting.
                if writing.is_none() {
                    close_session(ws, close_frame(CloseCode::Away, "idle timeout"), cfg.close).await;
                }
                break;
            }
            _ = sleep_until(stall_at.unwrap_or(far)), if stall_at.is_some() => {
                tracing::debug!("websocket handler did not take an inbound message in time");
                meter.note(WsEvent::InboundStall);
                // The peer is not at fault and may still be reading: tell it to retry later.
                // With a write blocked, the close frame could not be delivered.
                if writing.is_none() {
                    close_session(ws, close_frame(CloseCode::Again, "server busy"), cfg.close).await;
                }
                break;
            }
            _ = sleep_until(write_at.unwrap_or(far)), if write_at.is_some() => {
                // The peer is not taking data: a close frame would queue behind the blocked
                // bytes, so the connection is dropped without a handshake.
                tracing::debug!("websocket write did not complete in time");
                meter.note(WsEvent::WriteTimeout);
                break;
            }
            _ = sleep_until(meter_at.unwrap_or(far)), if meter_at.is_some() => {
                meter.flush();
            }
            _ = async { ping.as_mut().expect("guarded").tick().await }, if ping.is_some() => {
                // Quiet sessions publish their counts at least once per heartbeat.
                meter.flush();
                // One challenge at a time: an unanswered one keeps its own deadline.
                if challenge.is_some() {
                    continue;
                }
                ping_seq = ping_seq.wrapping_add(1);
                let payload = ping_seq.to_be_bytes();
                // Queued behind a write in progress, if any: the peer must read what was
                // sent before it to answer, so an unread backlog fails the heartbeat too.
                match start_write(ws, Message::Ping(bytes::Bytes::copy_from_slice(&payload))) {
                    Ok(()) => {}
                    // The write buffer is full of unread data: skip this tick (the write
                    // timeout and any outstanding deadline still apply).
                    Err(tungstenite::Error::WriteBufferFull(_)) => continue,
                    Err(_) => break,
                }
                let now = Instant::now();
                if writing.is_none() {
                    writing = Some(Writing {
                        _reserved: None,
                        deadline: cfg.write.map(|d| now + d),
                    });
                }
                if let Some(t) = cfg.pong {
                    challenge = Some(Challenge {
                        payload,
                        deadline: now + t,
                    });
                }
            }
            permit = in_tx.reserve(), if pending.is_some() => {
                match permit {
                    Ok(p) => p.send(pending.take().expect("guarded")),
                    // The handler dropped its receiver: keep the session, discard data.
                    Err(_) => {
                        pending = None;
                        deliver = false;
                    }
                }
                let now = Instant::now();
                // The socket was not read while the handler was busy: the pong deadline
                // does not run meanwhile.
                if let Some(c) = challenge.as_mut() {
                    c.deadline += now - paused_at;
                }
                last_seen = now;
            }
            ev = socket_event(ws, read, flush), if read || flush => {
                let msg = match ev {
                    // Written: the bytes are no longer queued.
                    SocketEvent::Flushed(Ok(())) => {
                        writing = None;
                        continue;
                    }
                    SocketEvent::Flushed(Err(_)) => {
                        tracing::debug!("websocket session ended by a write error");
                        break;
                    }
                    SocketEvent::Read(msg) => msg,
                };
                match msg {
                    Some(Ok(m)) => {
                        last_seen = Instant::now();
                        if matches!(m, Message::Text(_) | Message::Binary(_)) {
                            meter.received(&m);
                        }
                        match m {
                            Message::Text(_) | Message::Binary(_) if !gate.admit() => {
                                meter.note(WsEvent::RateLimited);
                                tracing::debug!("websocket session exceeded its message rate");
                                let _ = tokio::time::timeout(
                                    cfg.close,
                                    ws.close(close_frame(CloseCode::Policy, RATE_EXCEEDED)),
                                )
                                .await;
                                break;
                            }
                            Message::Text(_) | Message::Binary(_) if deliver => {
                                // Hand it over at once when the queue has room. Otherwise
                                // stop reading until the handler takes it (backpressure).
                                match in_tx.try_send(m) {
                                    Ok(()) => {}
                                    Err(tokio::sync::mpsc::error::TrySendError::Full(m)) => {
                                        meter.note(WsEvent::InboundBackpressure);
                                        pending = Some(m);
                                        paused_at = last_seen;
                                    }
                                    // The handler dropped its receiver: discard data.
                                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                        deliver = false;
                                    }
                                }
                            }
                            // Only the pong echoing the outstanding challenge answers it.
                            // Unsolicited and stale pongs are ignored (RFC 6455 §5.5.3).
                            Message::Pong(p)
                                if challenge.as_ref().is_some_and(|c| p.as_ref() == c.payload) =>
                            {
                                challenge = None;
                            }
                            Message::Close(_) => meter.note(WsEvent::PeerClose),
                            // Pings are answered by tungstenite on the next read/write. A
                            // peer close is answered likewise and ends the stream next.
                            _ => {}
                        }
                    }
                    Some(Err(e)) => {
                        meter.note(if failure_code(&e).is_some() {
                            WsEvent::ProtocolFailure
                        } else {
                            WsEvent::AbnormalDisconnect
                        });
                        fail_session(ws, &e, cfg.close).await;
                        break;
                    }
                    None => break,
                }
            }
            // After the socket branch, so a pong that is already readable wins the race.
            _ = sleep_until(pong_at), if challenge.is_some() && pending.is_none() => {
                tracing::debug!("websocket heartbeat not answered in time");
                meter.note(WsEvent::HeartbeatTimeout);
                // The peer stopped answering: its close reply is waited for (while its
                // input is drained, so the close frame is not lost to a TCP reset) no
                // longer than it was given for the pong.
                // With a write blocked, the close frame could not reach it at all.
                if writing.is_none() {
                    let bound = cfg.pong.map_or(cfg.close, |p| p.min(cfg.close));
                    close_session(ws, close_frame(CloseCode::Away, "heartbeat timeout"), bound).await;
                }
                break;
            }
            out = out_rx.recv(), if writing.is_none() => {
                match out {
                    Some(Outbound::Message(m, reserved)) => {
                        if matches!(m, Message::Text(_) | Message::Binary(_)) {
                            meter.sent(&m);
                        }
                        if start_write(ws, m).is_err() {
                            break;
                        }
                        writing = Some(Writing {
                            _reserved: Some(reserved),
                            deadline: cfg.write.map(|d| Instant::now() + d),
                        });
                    }
                    Some(Outbound::Close(frame)) => {
                        meter.note(WsEvent::ServerClose);
                        let frame = sanitize_close(frame).or_else(|| close_frame(CloseCode::Normal, ""));
                        close_session(ws, frame, cfg.close).await;
                        break;
                    }
                    // The handler finished (or dropped the socket).
                    None => {
                        meter.note(WsEvent::ServerClose);
                        close_session(ws, close_frame(CloseCode::Normal, ""), cfg.close).await;
                        break;
                    }
                }
            }
        }
    }
}

/// A typed upgrade in progress.
pub struct TypedUpgrade<In, Out> {
    inner: WebSocketUpgrade,
    _t: PhantomData<fn() -> (In, Out)>,
}

impl<In, Out> std::fmt::Debug for TypedUpgrade<In, Out> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypedUpgrade").finish_non_exhaustive()
    }
}

impl<In, Out> TypedUpgrade<In, Out> {
    /// The selected subprotocol, if any (see [`WebSocketUpgrade::protocols`]).
    pub fn protocol(&self) -> Option<&str> {
        self.inner.protocol()
    }
}

impl<In, Out> TypedUpgrade<In, Out>
where
    In: DeserializeOwned + PoringSchema + Send + 'static,
    Out: Serialize + Send + 'static,
{
    /// Completes the handshake and runs `f` with a typed socket.
    pub fn on_upgrade<F, Fut>(self, f: F) -> Response
    where
        F: FnOnce(TypedSocket<In, Out>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut inner = self.inner;
        let stop = inner.shutdown_signal();
        let client_ip = inner.admission.as_ref().map(|a| a.client_ip);
        let gate = inner.message_gate(client_ip);
        let meter = SessionMeter::new(
            inner
                .admission
                .as_ref()
                .map(|a| a.supervisor.counters.clone()),
        );
        inner.on_upgrade(move |raw| {
            f(TypedSocket {
                raw,
                stop,
                done: false,
                gate,
                meter,
                _t: PhantomData,
            })
        })
    }
}

/// Error receiving a typed message.
///
/// Non-exhaustive: match with a wildcard arm (for example `Err(_) => break`) so new
/// failure kinds do not break your code.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WsError {
    /// Transport/protocol error (including oversized messages).
    #[error("websocket error: {0}")]
    Socket(#[from] tungstenite::Error),
    /// The message was not valid JSON for the declared type.
    #[error("invalid message: {0}")]
    Decode(#[from] serde_json::Error),
    /// The message failed validation.
    #[error("message failed validation")]
    Invalid(Vec<ValidationIssue>),
    /// The peer exceeded the session's message rate or quota
    /// ([`WebSocketUpgrade::message_rate`], [`WebSocketUpgrade::message_quota`]). The
    /// session was closed with `1008 Policy Violation`.
    #[error("message rate exceeded")]
    RateLimited,
}

/// A WebSocket carrying typed JSON messages.
pub struct TypedSocket<In, Out> {
    raw: RawSocket,
    stop: WsShutdown,
    /// The session is closing or closed: `recv` returns `None`.
    done: bool,
    gate: MessageGate,
    meter: SessionMeter,
    _t: PhantomData<fn() -> (In, Out)>,
}

impl<In, Out> std::fmt::Debug for TypedSocket<In, Out> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypedSocket").finish_non_exhaustive()
    }
}

impl<In, Out> TypedSocket<In, Out>
where
    In: DeserializeOwned + PoringSchema,
    Out: Serialize,
{
    /// Receives the next data message. Ping/pong are handled internally. `None` means the
    /// connection is closing: the peer closed it (its close frame has been answered), or the
    /// server began shutting down, in which case a close frame with code 1001 (Going Away)
    /// has been sent. A transport or protocol error is returned exactly once and ends the
    /// stream: after invalid UTF-8, an oversized message or a protocol violation the session
    /// is failed with `1007`, `1009` or `1002`. After an I/O error, a reset or an abrupt
    /// disconnect nothing can be sent. Every later call returns `None`. Decode and
    /// validation errors are not terminal: the session continues.
    pub async fn recv(&mut self) -> Option<Result<In, WsError>> {
        loop {
            if self.done {
                return None;
            }
            // Counts received earlier are published within `METER_INTERVAL` even if no
            // further message arrives (`StreamExt::next` is cancel-safe).
            let flush_at = self.meter.flush_deadline();
            let next = tokio::select! {
                biased;
                _ = self.stop.wait() => {
                    self.done = true;
                    self.meter.note(WsEvent::ShutdownClose);
                    let frame = tungstenite::protocol::CloseFrame {
                        code: tungstenite::protocol::frame::coding::CloseCode::Away,
                        reason: "server shutting down".into(),
                    };
                    // Best effort: the peer may already be gone.
                    let _ = self.raw.close(Some(frame)).await;
                    return None;
                }
                m = self.raw.next() => m,
                _ = tokio::time::sleep_until(flush_at.unwrap_or_else(tokio::time::Instant::now)),
                    if flush_at.is_some() =>
                {
                    self.meter.flush();
                    continue;
                }
            };
            let Some(next) = next else {
                self.done = true;
                return None;
            };
            let msg = match next {
                Ok(m) => m,
                Err(e) => {
                    // Every read error is terminal for the stream: it is reported once and
                    // later calls return `None`. Without this, a handler that skips errors
                    // (`Err(_) => continue`) would poll a dead stream again and again,
                    // getting the same or an `AlreadyClosed` error in a busy loop and
                    // counting one abnormal disconnect per call.
                    self.done = true;
                    if failure_code(&e).is_some() {
                        // Fail the connection (1002/1007/1009).
                        self.meter.note(WsEvent::ProtocolFailure);
                        fail_session(&mut self.raw, &e, DEFAULT_CLOSE_TIMEOUT).await;
                    } else {
                        self.meter.note(WsEvent::AbnormalDisconnect);
                    }
                    return Some(Err(e.into()));
                }
            };
            if matches!(msg, Message::Text(_) | Message::Binary(_)) {
                self.meter.received(&msg);
            }
            if matches!(msg, Message::Text(_) | Message::Binary(_)) && !self.gate.admit() {
                self.done = true;
                self.meter.note(WsEvent::RateLimited);
                let frame = tungstenite::protocol::CloseFrame {
                    code: tungstenite::protocol::frame::coding::CloseCode::Policy,
                    reason: RATE_EXCEEDED.into(),
                };
                let _ =
                    tokio::time::timeout(DEFAULT_CLOSE_TIMEOUT, self.raw.close(Some(frame))).await;
                return Some(Err(WsError::RateLimited));
            }
            // Deserialize straight from the received frame's buffer (no payload copy).
            let parsed = match &msg {
                Message::Text(t) => serde_json::from_slice::<In>(t.as_bytes()),
                Message::Binary(b) => serde_json::from_slice::<In>(b),
                Message::Close(_) => {
                    // Tungstenite has queued the close reply. Reading again flushes it and
                    // completes the closing handshake.
                    self.done = true;
                    self.meter.note(WsEvent::PeerClose);
                    let _ = tokio::time::timeout(DEFAULT_CLOSE_TIMEOUT, async {
                        while let Some(Ok(_)) = self.raw.next().await {}
                    })
                    .await;
                    return None;
                }
                _ => continue,
            };
            let v: In = match parsed {
                Ok(v) => v,
                Err(e) => return Some(Err(e.into())),
            };
            let issues = crate::schema::validate(&v);
            if !issues.is_empty() {
                return Some(Err(WsError::Invalid(issues)));
            }
            return Some(Ok(v));
        }
    }

    /// Sends a message, waiting for the bounded write buffer to drain (backpressure).
    pub async fn send(&mut self, msg: &Out) -> Result<(), WsError> {
        let m = Message::text(serde_json::to_string(msg)?);
        self.meter.sent(&m);
        self.raw.send(m).await?;
        Ok(())
    }

    /// Closes the connection with a normal close frame.
    pub async fn close(mut self) -> Result<(), WsError> {
        self.raw.close(None).await?;
        Ok(())
    }

    /// A handle that fires when the server begins shutting down (see [`WsShutdown`]).
    pub fn shutdown_signal(&self) -> WsShutdown {
        self.stop.clone()
    }

    /// The underlying raw socket.
    pub fn into_raw(self) -> RawSocket {
        self.raw
    }
}

#[cfg(test)]
mod gate_tests {
    use super::Gcra;
    use proptest::prelude::*;
    use std::time::Duration;

    proptest! {
        /// Exactly `n` messages are admitted in a burst, the next one is refused, and after
        /// a full window `n` more are admitted again.
        #[test]
        fn gcra_burst_and_refill(n in 1u32..500, per_ms in 1u64..10_000) {
            let per = Duration::from_millis(per_ms);
            let mut g = Gcra::new(n, per);
            let t0 = g.start;
            for i in 0..n {
                prop_assert!(g.admit(t0), "message {} of {} refused", i + 1, n);
            }
            prop_assert!(!g.admit(t0), "message {} admitted", n + 1);
            let later = t0 + per;
            for i in 0..n {
                prop_assert!(g.admit(later), "after refill: message {} of {} refused", i + 1, n);
            }
            prop_assert!(!g.admit(later));
        }

        /// Sustained traffic never exceeds `n` per window by more than the burst.
        #[test]
        fn gcra_sustained_rate(n in 1u32..100, per_ms in 10u64..1_000, steps in 1usize..400) {
            let per = Duration::from_millis(per_ms);
            let mut g = Gcra::new(n, per);
            let t0 = g.start;
            let step = per / 50;
            let mut admitted = 0u64;
            for k in 0..steps {
                if g.admit(t0 + step * k as u32) {
                    admitted += 1;
                }
            }
            let elapsed = step.as_nanos() * steps as u128;
            let windows = elapsed / per.as_nanos() + 1;
            prop_assert!(u128::from(admitted) <= u128::from(n) * (windows + 1));
        }
    }

    #[test]
    fn degenerate_configurations_do_not_panic() {
        let mut g = Gcra::new(0, Duration::ZERO);
        let t = g.start;
        assert!(g.admit(t));
        let mut g = Gcra::new(u32::MAX, Duration::from_nanos(1));
        assert!(g.admit(g.start));
    }
}

#[cfg(test)]
mod outbound_tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    const SHORT: Duration = Duration::from_millis(50);

    fn queue(
        messages: usize,
        budget: usize,
        max_message: usize,
    ) -> (
        OutboundTx,
        tokio::sync::mpsc::Receiver<Outbound>,
        Arc<tokio::sync::Semaphore>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel(messages);
        let bytes = Arc::new(tokio::sync::Semaphore::new(budget));
        let out = OutboundTx {
            tx,
            budget: OutBudget {
                bytes: bytes.clone(),
                max_message: max_message.min(budget),
            },
            counters: None,
        };
        (out, rx, bytes)
    }

    fn bin(n: usize) -> Message {
        Message::binary(vec![0u8; n])
    }

    #[tokio::test]
    async fn small_messages_within_limits() {
        let (tx, mut rx, bytes) = queue(16, 100, 100);
        for _ in 0..3 {
            tx.send(bin(10)).await.unwrap();
        }
        assert_eq!(bytes.available_permits(), 70);
        for _ in 0..3 {
            drop(rx.recv().await.unwrap());
        }
        assert_eq!(
            bytes.available_permits(),
            100,
            "written messages return their bytes"
        );
    }

    #[tokio::test]
    async fn oversized_messages_fail_immediately_and_reserve_nothing() {
        let (tx, _rx, bytes) = queue(16, 1000, 100);
        let e = tx.send(bin(101)).await.unwrap_err();
        assert!(
            matches!(
                e,
                WsError::Socket(tungstenite::Error::Capacity(
                    tungstenite::error::CapacityError::MessageTooLong {
                        size: 101,
                        max_size: 100
                    }
                ))
            ),
            "{e:?}"
        );
        assert_eq!(bytes.available_permits(), 1000);
        // The per-message limit never exceeds the byte budget (it could never be queued).
        let (tx, _rx, _) = queue(16, 64, 1 << 20);
        assert!(tx.send(bin(65)).await.is_err());
        tx.send(bin(64)).await.unwrap();
    }

    #[tokio::test]
    async fn message_count_exhaustion_applies_backpressure() {
        let (tx, mut rx, _) = queue(2, 1 << 20, 1 << 20);
        tx.send(bin(1)).await.unwrap();
        tx.send(bin(1)).await.unwrap();
        assert!(
            tokio::time::timeout(SHORT, tx.send(bin(1))).await.is_err(),
            "a third message waits for room"
        );
        drop(rx.recv().await.unwrap());
        tokio::time::timeout(SHORT, tx.send(bin(1)))
            .await
            .expect("room again")
            .unwrap();
    }

    #[tokio::test]
    async fn queued_byte_exhaustion_applies_backpressure() {
        let (tx, mut rx, bytes) = queue(100, 100, 100);
        tx.send(bin(60)).await.unwrap();
        assert!(
            tokio::time::timeout(SHORT, tx.send(bin(60))).await.is_err(),
            "120 bytes do not fit a 100-byte budget"
        );
        // The cancelled wait reserved nothing.
        assert_eq!(bytes.available_permits(), 40);
        drop(rx.recv().await.unwrap());
        tokio::time::timeout(SHORT, tx.send(bin(60)))
            .await
            .expect("budget returned")
            .unwrap();
        assert_eq!(bytes.available_permits(), 40);
    }

    #[tokio::test]
    async fn waiting_senders_fail_once_the_session_ends() {
        let (tx, rx, bytes) = queue(16, 10, 10);
        tx.send(bin(10)).await.unwrap();
        let waiting = tokio::spawn({
            let tx = tx.clone();
            async move { tx.send(bin(5)).await }
        });
        tokio::task::yield_now().await;
        // What the pump does when it ends: drop the queue and close the budget.
        drop(rx);
        bytes.close();
        let r = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("does not hang")
            .unwrap();
        assert!(matches!(
            r,
            Err(WsError::Socket(tungstenite::Error::AlreadyClosed))
        ));
        assert!(tx.send(bin(1)).await.is_err());
    }

    #[tokio::test]
    async fn dropping_a_full_queue_returns_every_byte() {
        let (tx, rx, bytes) = queue(4, 1000, 1000);
        for _ in 0..4 {
            tx.send(bin(100)).await.unwrap();
        }
        assert_eq!(bytes.available_permits(), 600);
        drop(rx);
        assert_eq!(bytes.available_permits(), 1000, "no accounting leak");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_senders_share_the_budget_without_leaks() {
        let (tx, mut rx, bytes) = queue(8, 30, 30);
        let consumer = tokio::spawn(async move {
            let mut n = 0usize;
            while let Some(m) = rx.recv().await {
                if let Outbound::Message(m, reserved) = m {
                    n += m.len();
                    drop(reserved);
                }
            }
            n
        });
        let mut senders = Vec::new();
        for _ in 0..8 {
            let tx = tx.clone();
            senders.push(tokio::spawn(async move {
                for _ in 0..50 {
                    tx.send(bin(10)).await.unwrap();
                }
            }));
        }
        for s in senders {
            tokio::time::timeout(Duration::from_secs(10), s)
                .await
                .expect("no deadlock")
                .unwrap();
        }
        drop(tx);
        assert_eq!(consumer.await.unwrap(), 8 * 50 * 10);
        assert_eq!(bytes.available_permits(), 30);
    }
}

/// Property tests: handshake header validation never panics and accepts exactly what
/// RFC 6455 allows.
#[cfg(test)]
mod handshake_prop_tests {
    use super::{check_version, offered_protocols, valid_key};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn keys_are_canonical_base64_of_16_bytes(bytes in prop::collection::vec(any::<u8>(), 0..40)) {
            let ok = valid_key(&bytes);
            if ok {
                prop_assert_eq!(bytes.len(), 24);
                prop_assert_eq!(data_encoding::BASE64.decode(&bytes).unwrap().len(), 16);
            }
        }

        #[test]
        fn every_16_byte_nonce_is_a_valid_key(nonce in prop::array::uniform16(any::<u8>())) {
            let key = data_encoding::BASE64.encode(&nonce);
            prop_assert!(valid_key(key.as_bytes()));
        }

        #[test]
        fn version_and_protocol_headers_never_panic(
            versions in prop::collection::vec("[ 0-9a-z,]{0,6}", 0..3),
            protocols in prop::collection::vec("[ -~]{0,24}", 0..3),
        ) {
            let mut h = http::HeaderMap::new();
            for v in &versions {
                if let Ok(v) = http::HeaderValue::from_str(v) {
                    h.append(http::header::SEC_WEBSOCKET_VERSION, v);
                }
            }
            for p in &protocols {
                if let Ok(p) = http::HeaderValue::from_str(p) {
                    h.append(http::header::SEC_WEBSOCKET_PROTOCOL, p);
                }
            }
            let version_ok = check_version(&h).is_ok();
            let n = h.get_all(http::header::SEC_WEBSOCKET_VERSION).iter().count();
            if version_ok {
                prop_assert_eq!(n, 1);
            }
            if let Ok(list) = offered_protocols(&h) {
                // Unique, non-empty tokens only.
                let mut seen = std::collections::HashSet::new();
                for p in &list {
                    prop_assert!(!p.is_empty());
                    prop_assert!(!p.contains([' ', ',', '\t', '"', '/']));
                    prop_assert!(seen.insert(p.clone()));
                }
            }
        }
    }
}
