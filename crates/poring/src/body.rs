//! Request and response body types.

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Frame, SizeHint};
use http_body_util::BodyExt;
use tokio::sync::mpsc;

/// Boxed error type used by bodies.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Request body: either hyper's streaming body or an in-memory buffer (tests, Wasm).
pub enum ReqBody {
    /// Streaming body from hyper.
    Incoming(hyper::body::Incoming),
    /// In-memory body.
    Full(Option<Bytes>),
}

impl ReqBody {
    /// An empty body.
    pub fn empty() -> Self {
        ReqBody::Full(None)
    }
}

impl From<Bytes> for ReqBody {
    fn from(b: Bytes) -> Self {
        ReqBody::Full(if b.is_empty() { None } else { Some(b) })
    }
}

impl fmt::Debug for ReqBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReqBody::Incoming(_) => f.write_str("ReqBody::Incoming"),
            ReqBody::Full(b) => write!(
                f,
                "ReqBody::Full({} bytes)",
                b.as_ref().map_or(0, Bytes::len)
            ),
        }
    }
}

impl http_body::Body for ReqBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match self.get_mut() {
            ReqBody::Incoming(b) => Pin::new(b).poll_frame(cx).map_err(Into::into),
            ReqBody::Full(b) => Poll::Ready(b.take().map(|d| Ok(Frame::data(d)))),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            ReqBody::Incoming(b) => b.is_end_stream(),
            ReqBody::Full(b) => b.is_none(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            ReqBody::Incoming(b) => b.size_hint(),
            ReqBody::Full(b) => SizeHint::with_exact(b.as_ref().map_or(0, |b| b.len() as u64)),
        }
    }
}

/// Error collecting a request body.
#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    /// The body exceeded the effective limit (413).
    #[error("request body exceeds {limit} bytes")]
    TooLarge {
        /// The limit.
        limit: u64,
    },
    /// I/O or protocol error while reading (400).
    #[error("failed to read request body")]
    Read(#[source] BoxError),
}

/// Collects a body into memory while enforcing `limit` *during* collection, so an
/// oversized or lying `Content-Length` never causes an unbounded allocation.
pub async fn collect_limited(body: ReqBody, limit: u64) -> Result<Bytes, CollectError> {
    let limit_usize = usize::try_from(limit).unwrap_or(usize::MAX);
    match body {
        ReqBody::Full(b) => {
            let b = b.unwrap_or_default();
            if b.len() as u64 > limit {
                Err(CollectError::TooLarge { limit })
            } else {
                Ok(b)
            }
        }
        ReqBody::Incoming(inc) => {
            let limited = http_body_util::Limited::new(inc, limit_usize);
            match limited.collect().await {
                Ok(c) => Ok(c.to_bytes()),
                Err(e) => {
                    if e.is::<http_body_util::LengthLimitError>() {
                        Err(CollectError::TooLarge { limit })
                    } else {
                        Err(CollectError::Read(e))
                    }
                }
            }
        }
    }
}

/// How a response body finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyEnd {
    /// All frames were handed to hyper.
    Complete,
    /// The body produced an error mid-stream.
    Error,
    /// The body was dropped before completion (client gone, or a HEAD request).
    Dropped,
}

type OnDone = Box<dyn FnOnce(BodyEnd) + Send>;
type DynBody = Pin<Box<dyn http_body::Body<Data = Bytes, Error = BoxError> + Send>>;

enum Inner {
    Full(Option<Bytes>),
    Channel(mpsc::Receiver<Bytes>),
    Boxed(DynBody),
}

/// Response body.
///
/// The common cases (empty, in-memory bytes) are allocation-free beyond the payload.
/// Streaming bodies are supported via [`Body::channel`] (bounded, so slow clients exert
/// backpressure on producers) or [`Body::wrap`].
pub struct Body {
    inner: Inner,
    on_done: Option<OnDone>,
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            Inner::Full(b) => write!(f, "Body::Full({} bytes)", b.as_ref().map_or(0, Bytes::len)),
            Inner::Channel(_) => f.write_str("Body::Channel"),
            Inner::Boxed(_) => f.write_str("Body::Boxed"),
        }
    }
}

impl Default for Body {
    fn default() -> Self {
        Body::empty()
    }
}

impl Body {
    /// Empty body.
    pub const fn empty() -> Self {
        Body {
            inner: Inner::Full(None),
            on_done: None,
        }
    }

    /// In-memory body.
    pub fn full(b: impl Into<Bytes>) -> Self {
        let b = b.into();
        Body {
            inner: Inner::Full(if b.is_empty() { None } else { Some(b) }),
            on_done: None,
        }
    }

    /// Wraps any `http_body::Body`.
    pub fn wrap<B>(b: B) -> Self
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        Body {
            inner: Inner::Boxed(Box::pin(b.map_err(Into::into))),
            on_done: None,
        }
    }

    /// A streaming body fed through a bounded channel of `capacity` chunks. Sending
    /// awaits when the client is slow, providing backpressure.
    pub fn channel(capacity: usize) -> (mpsc::Sender<Bytes>, Body) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (
            tx,
            Body {
                inner: Inner::Channel(rx),
                on_done: None,
            },
        )
    }

    /// Registers a callback run once when the body completes, errors or is dropped.
    /// Used by the runtime for after-response hooks and trace finalisation.
    pub(crate) fn on_done(&mut self, f: impl FnOnce(BodyEnd) + Send + 'static) {
        match self.on_done.take() {
            Some(prev) => {
                self.on_done = Some(Box::new(move |e| {
                    prev(e);
                    f(e);
                }))
            }
            None => self.on_done = Some(Box::new(f)),
        }
    }

    /// Exact length if known.
    pub fn exact_len(&self) -> Option<u64> {
        match &self.inner {
            Inner::Full(b) => Some(b.as_ref().map_or(0, |b| b.len() as u64)),
            Inner::Channel(_) => None,
            Inner::Boxed(b) => b.size_hint().exact(),
        }
    }

    /// Collects the body (for tests and the in-process client).
    pub async fn collect_bytes(mut self) -> Result<Bytes, BoxError> {
        let mut out = bytes::BytesMut::new();
        loop {
            let frame = std::future::poll_fn(|cx| Pin::new(&mut self).poll_frame_inner(cx)).await;
            match frame {
                None => break,
                Some(Ok(f)) => {
                    if let Ok(d) = f.into_data() {
                        out.extend_from_slice(&d);
                    }
                }
                Some(Err(e)) => return Err(e),
            }
        }
        Ok(out.freeze())
    }

    fn finish(&mut self, end: BodyEnd) {
        if let Some(f) = self.on_done.take() {
            f(end);
        }
    }

    fn poll_frame_inner(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let res = match &mut self.inner {
            Inner::Full(b) => Poll::Ready(b.take().map(|d| Ok(Frame::data(d)))),
            Inner::Channel(rx) => rx.poll_recv(cx).map(|o| o.map(|d| Ok(Frame::data(d)))),
            Inner::Boxed(b) => b.as_mut().poll_frame(cx),
        };
        match &res {
            Poll::Ready(None) => self.finish(BodyEnd::Complete),
            Poll::Ready(Some(Err(_))) => self.finish(BodyEnd::Error),
            Poll::Ready(Some(Ok(_))) if self.is_end_stream_inner() => {
                self.finish(BodyEnd::Complete)
            }
            _ => {}
        }
        res
    }

    fn is_end_stream_inner(&self) -> bool {
        match &self.inner {
            Inner::Full(b) => b.is_none(),
            Inner::Channel(_) => false,
            Inner::Boxed(b) => b.is_end_stream(),
        }
    }
}

impl Drop for Body {
    fn drop(&mut self) {
        let end = if self.is_end_stream_inner() {
            BodyEnd::Complete
        } else {
            BodyEnd::Dropped
        };
        self.finish(end);
    }
}

impl http_body::Body for Body {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.get_mut().poll_frame_inner(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.is_end_stream_inner()
    }

    fn size_hint(&self) -> SizeHint {
        match &self.inner {
            Inner::Full(b) => SizeHint::with_exact(b.as_ref().map_or(0, |b| b.len() as u64)),
            Inner::Channel(_) => SizeHint::default(),
            Inner::Boxed(b) => b.size_hint(),
        }
    }
}

impl From<Bytes> for Body {
    fn from(b: Bytes) -> Self {
        Body::full(b)
    }
}
impl From<String> for Body {
    fn from(s: String) -> Self {
        Body::full(s)
    }
}
impl From<&'static str> for Body {
    fn from(s: &'static str) -> Self {
        Body::full(Bytes::from_static(s.as_bytes()))
    }
}
impl From<Vec<u8>> for Body {
    fn from(v: Vec<u8>) -> Self {
        Body::full(v)
    }
}
impl From<&'static [u8]> for Body {
    fn from(v: &'static [u8]) -> Self {
        Body::full(Bytes::from_static(v))
    }
}
