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
//! * `send` awaits the socket flush with a bounded write buffer, so a slow reader applies
//!   backpressure to the producer instead of growing memory.
//! * The upgrade request itself goes through the normal policy pipeline (auth, rate
//!   limits, CORS origin checks for cross-site upgrades) before `on_upgrade` runs.

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

/// The raw upgraded socket.
pub type RawSocket = WebSocketStream<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>>;

/// Extractor for a WebSocket upgrade request (validates the RFC 6455 handshake headers).
pub struct WebSocketUpgrade {
    key: HeaderValue,
    on_upgrade: Option<hyper::upgrade::OnUpgrade>,
    config: WebSocketConfig,
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

impl<S: Sync> FromRequest<S> for WebSocketUpgrade {
    type Rejection = ApiError;

    async fn from_request(cx: &mut Ctx<'_, S>) -> Result<Self, ApiError> {
        let h = &cx.parts.headers;
        if cx.parts.method != http::Method::GET
            || !header_has_token(h, header::CONNECTION, "upgrade")
            || !header_has_token(h, header::UPGRADE, "websocket")
        {
            return Err(rejection::bad_request("not_websocket", "expected a WebSocket upgrade request"));
        }
        if h.get(header::SEC_WEBSOCKET_VERSION).map(|v| v != "13").unwrap_or(true) {
            return Err(rejection::bad_request("websocket_version", "Sec-WebSocket-Version must be 13"));
        }
        let key = h
            .get(header::SEC_WEBSOCKET_KEY)
            .cloned()
            .ok_or_else(|| rejection::bad_request("websocket_key", "missing Sec-WebSocket-Key"))?;
        let on_upgrade = cx.parts.extensions.remove::<hyper::upgrade::OnUpgrade>();
        let mut config = WebSocketConfig::default();
        config.max_message_size = Some(64 * 1024);
        config.max_frame_size = Some(64 * 1024);
        config.write_buffer_size = 16 * 1024;
        config.max_write_buffer_size = 256 * 1024;
        Ok(WebSocketUpgrade { key, on_upgrade, config })
    }
}

impl WebSocketUpgrade {
    /// Maximum inbound message size in bytes (default 64 KiB).
    pub fn max_message_size(mut self, n: usize) -> Self {
        self.config.max_message_size = Some(n);
        self.config.max_frame_size = Some(n);
        self
    }

    /// Maximum buffered outbound bytes before `send` must wait (default 256 KiB).
    pub fn max_write_buffer(mut self, n: usize) -> Self {
        self.config.max_write_buffer_size = n.max(self.config.write_buffer_size + 1);
        self
    }

    /// Switches to typed JSON messages.
    pub fn typed<In, Out>(self) -> TypedUpgrade<In, Out> {
        TypedUpgrade { inner: self, _t: PhantomData }
    }

    /// Completes the handshake and runs `f` with the raw socket in a new task.
    pub fn on_upgrade<F, Fut>(self, f: F) -> Response
    where
        F: FnOnce(RawSocket) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let Some(on_upgrade) = self.on_upgrade else {
            // In-process test client / HTTP/2 without extended CONNECT: no upgrade possible.
            return rejection::bad_request("upgrade_unavailable", "connection cannot be upgraded").into_response();
        };
        let accept = tungstenite::handshake::derive_accept_key(self.key.as_bytes());
        let config = self.config;
        tokio::spawn(async move {
            match on_upgrade.await {
                Ok(upgraded) => {
                    let io = hyper_util::rt::TokioIo::new(upgraded);
                    let socket = WebSocketStream::from_raw_socket(io, Role::Server, Some(config)).await;
                    f(socket).await;
                }
                Err(e) => tracing::debug!(error = %e, "websocket upgrade failed"),
            }
        });
        let mut r = StatusCode::SWITCHING_PROTOCOLS.into_response();
        let h = r.headers_mut();
        h.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        h.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        if let Ok(v) = HeaderValue::from_str(&accept) {
            h.insert(header::SEC_WEBSOCKET_ACCEPT, v);
        }
        r
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
        self.inner.on_upgrade(move |raw| f(TypedSocket { raw, _t: PhantomData }))
    }
}

/// Error receiving a typed message.
#[derive(Debug, thiserror::Error)]
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
}

/// A WebSocket carrying typed JSON messages.
pub struct TypedSocket<In, Out> {
    raw: RawSocket,
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
    /// Receives the next data message. Ping/pong are handled internally; `None` means the
    /// peer closed the connection.
    pub async fn recv(&mut self) -> Option<Result<In, WsError>> {
        loop {
            let msg = match self.raw.next().await? {
                Ok(m) => m,
                Err(e) => return Some(Err(e.into())),
            };
            let bytes = match msg {
                Message::Text(t) => t.as_bytes().to_vec(),
                Message::Binary(b) => b.to_vec(),
                Message::Close(_) => return None,
                _ => continue,
            };
            let v: In = match serde_json::from_slice(&bytes) {
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
        let s = serde_json::to_string(msg)?;
        self.raw.send(Message::text(s)).await?;
        Ok(())
    }

    /// Closes the connection with a normal close frame.
    pub async fn close(mut self) -> Result<(), WsError> {
        self.raw.close(None).await?;
        Ok(())
    }

    /// The underlying raw socket.
    pub fn into_raw(self) -> RawSocket {
        self.raw
    }
}
