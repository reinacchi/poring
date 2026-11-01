//! The per-request context passed through hooks and extractors.

use std::borrow::Cow;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};

use crate::body::ReqBody;
use crate::flow::{FlowState, Stage};
use crate::policy::Identity;
use crate::router::RouteRuntime;

/// Maximum number of path parameters per route (checked at compile time by the macros).
pub const MAX_PARAMS: usize = 8;

/// Matched path parameters, stored as byte ranges into the request path (no allocation).
#[derive(Clone, Copy)]
pub(crate) struct Params<'a> {
    items: [(&'a str, u32, u32); MAX_PARAMS],
    len: usize,
}

impl<'a> Params<'a> {
    pub(crate) fn new() -> Self {
        Params { items: [("", 0, 0); MAX_PARAMS], len: 0 }
    }

    pub(crate) fn push(&mut self, name: &'a str, start: usize, end: usize) -> bool {
        if self.len >= MAX_PARAMS {
            return false;
        }
        self.items[self.len] = (name, start as u32, end as u32);
        self.len += 1;
        true
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&'a str, usize, usize)> + '_ {
        self.items[..self.len].iter().map(|(n, s, e)| (*n, *s as usize, *e as usize))
    }
}

/// Process-unique correlation ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestId {
    /// Validated client-supplied `x-request-id`.
    Client(HeaderValue),
    /// Generated: process-random prefix + counter.
    Generated(u32, u64),
}

static COUNTER: AtomicU64 = AtomicU64::new(1);

fn process_prefix() -> u32 {
    use std::sync::OnceLock;
    static P: OnceLock<u32> = OnceLock::new();
    *P.get_or_init(|| {
        let mut b = [0u8; 4];
        // Fall back to a time-derived prefix if the OS RNG is unavailable; uniqueness of
        // correlation IDs is a debugging aid, not a security property.
        if getrandom::fill(&mut b).is_err() {
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            return t;
        }
        u32::from_le_bytes(b)
    })
}

impl RequestId {
    /// Accepts a client-supplied ID only if it is 1..=64 chars of `[A-Za-z0-9._-]`;
    /// otherwise generates a fresh one. Prevents header/log injection via correlation IDs.
    pub(crate) fn from_headers(h: &HeaderMap) -> RequestId {
        if let Some(v) = h.get("x-request-id") {
            let b = v.as_bytes();
            if !b.is_empty()
                && b.len() <= 64
                && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
            {
                return RequestId::Client(v.clone());
            }
        }
        RequestId::Generated(process_prefix(), COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    /// As a header value.
    pub fn to_header(&self) -> HeaderValue {
        match self {
            RequestId::Client(v) => v.clone(),
            RequestId::Generated(p, n) => {
                // Hex-encode on the stack: `pppppppp-n...` (no intermediate String).
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let mut buf = [0u8; 8 + 1 + 16];
                for (i, b) in buf[..8].iter_mut().enumerate() {
                    *b = HEX[((p >> (28 - 4 * i)) & 0xf) as usize];
                }
                buf[8] = b'-';
                let digits = (16 - (n.leading_zeros() / 4) as usize).max(1);
                for i in 0..digits {
                    buf[9 + i] = HEX[((n >> (4 * (digits - 1 - i))) & 0xf) as usize];
                }
                HeaderValue::from_bytes(&buf[..9 + digits]).unwrap_or_else(|_| HeaderValue::from_static("invalid"))
            }
        }
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestId::Client(v) => f.write_str(v.to_str().unwrap_or("invalid")),
            RequestId::Generated(p, n) => write!(f, "{p:08x}-{n:x}"),
        }
    }
}

/// Per-request context.
///
/// A `Ctx` can only be created by the Poring runtime after routing and security
/// enforcement; there is no public constructor. This guarantees that macro-generated
/// handler entry points (which take a `Ctx`) cannot be invoked without passing through
/// the policy pipeline.
pub struct Ctx<'a, S> {
    pub(crate) parts: http::request::Parts,
    pub(crate) body: Option<ReqBody>,
    pub(crate) params: Params<'a>,
    pub(crate) state: &'a S,
    pub(crate) route: &'a RouteRuntime,
    pub(crate) identity: Option<Identity>,
    pub(crate) flow: Option<Box<FlowState>>,
    pub(crate) peer: Option<SocketAddr>,
    pub(crate) request_id: RequestId,
    pub(crate) response_headers: Option<HeaderMap>,
    pub(crate) limits: &'a crate::app::Limits,
}

impl<S> fmt::Debug for Ctx<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ctx")
            .field("method", &self.parts.method)
            .field("path", &self.parts.uri.path())
            .field("route", &self.route.id)
            .field("request_id", &self.request_id)
            .finish_non_exhaustive()
    }
}

impl<'a, S> Ctx<'a, S> {
    /// Request method.
    pub fn method(&self) -> &Method {
        &self.parts.method
    }

    /// Request URI.
    pub fn uri(&self) -> &Uri {
        &self.parts.uri
    }

    /// Request headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.parts.headers
    }

    /// Request extensions (hooks may insert typed values for `Extension<T>`).
    pub fn extensions(&self) -> &http::Extensions {
        &self.parts.extensions
    }

    /// Mutable request extensions.
    pub fn extensions_mut(&mut self) -> &mut http::Extensions {
        &mut self.parts.extensions
    }

    /// Raw (still percent-encoded) path parameter.
    pub fn raw_param(&self, name: &str) -> Option<&str> {
        let path = self.parts.uri.path();
        self.params.iter().find(|(n, _, _)| *n == name).and_then(|(_, s, e)| path.get(s..e))
    }

    /// Percent-decoded path parameter. Malformed encodings yield `None`.
    pub fn param(&self, name: &str) -> Option<Cow<'_, str>> {
        self.raw_param(name).and_then(|v| crate::extract::path::decode(v).ok())
    }

    /// Shared app state.
    pub fn state(&self) -> &'a S {
        self.state
    }

    /// The authenticated identity, if the route required authentication.
    pub fn identity(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }

    /// Peer address (if known).
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// Correlation ID.
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Stable route ID (matches graph node prefixes).
    pub fn route_id(&self) -> &str {
        &self.route.id
    }

    /// Effective body limit for this route.
    pub fn body_limit(&self) -> u64 {
        self.route.policy.body_limit
    }

    /// Sets a header on the eventual response (applied after all hooks).
    pub fn set_response_header(&mut self, name: HeaderName, value: HeaderValue) {
        self.response_headers.get_or_insert_with(HeaderMap::new).insert(name, value);
    }

    /// Takes the request body (at most once). Custom body extractors must use
    /// [`crate::body::collect_limited`] with [`Ctx::body_limit`].
    pub fn take_body(&mut self) -> Option<ReqBody> {
        self.body.take()
    }

    /// Content-Type header value, if valid UTF-8.
    pub fn content_type(&self) -> Option<&str> {
        self.parts.headers.get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok())
    }

    pub(crate) fn limits(&self) -> &crate::app::Limits {
        self.limits
    }

    #[inline]
    pub(crate) fn mark(&mut self, s: Stage) {
        if let Some(f) = self.flow.as_deref_mut() {
            f.mark(s);
        }
        if tracing::enabled!(target: "poring::flow", tracing::Level::TRACE) {
            tracing::trace!(
                target: "poring::flow",
                node = %crate::flow::NodeId { route: Some(&self.route.id), stage: s },
                request_id = %self.request_id,
            );
        }
    }

    #[doc(hidden)]
    #[inline]
    pub fn __mark_before(&mut self) {
        let i = self.flow.as_deref_mut().map(|f| {
            let i = f.before;
            f.before = f.before.saturating_add(1);
            i
        });
        if let Some(i) = i {
            self.mark(Stage::Before(i));
        }
    }

    #[doc(hidden)]
    #[inline]
    pub fn __mark_after(&mut self) {
        let i = self.flow.as_deref_mut().map(|f| {
            let i = f.after;
            f.after = f.after.saturating_add(1);
            i
        });
        if let Some(i) = i {
            self.mark(Stage::After(i));
        }
    }

    #[doc(hidden)]
    #[inline]
    pub fn __mark_extract(&mut self) {
        let i = self.flow.as_deref_mut().map(|f| {
            let i = f.extract;
            f.extract = f.extract.saturating_add(1);
            i
        });
        if let Some(i) = i {
            self.mark(Stage::Extract(i));
        }
    }

    /// Records the validation step of the extractor currently running.
    #[doc(hidden)]
    #[inline]
    pub fn __mark_validate(&mut self) {
        let i = self.flow.as_deref().map(|f| f.extract.saturating_sub(1));
        if let Some(i) = i {
            self.mark(Stage::Validate(i));
        }
    }

    #[doc(hidden)]
    #[inline]
    pub fn __mark_annotation(&mut self) {
        let i = self.flow.as_deref_mut().map(|f| {
            let i = f.annotation;
            f.annotation = f.annotation.saturating_add(1);
            i
        });
        if let Some(i) = i {
            self.mark(Stage::Annotation(i));
        }
    }

    #[doc(hidden)]
    #[inline]
    pub fn __mark(&mut self, s: crate::flow::Stage) {
        self.mark(s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_header_matches_display() {
        for (p, n) in [(0u32, 0u64), (0xdead_beef, 1), (1, u64::MAX), (0x0a0b0c0d, 0x1234)] {
            let id = RequestId::Generated(p, n);
            assert_eq!(id.to_header().to_str().unwrap(), id.to_string());
        }
    }
}
