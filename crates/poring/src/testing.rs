//! In-process test client: drives the full pipeline (routing, policy, hooks, extractors,
//! handlers, response finalisation) without opening a socket.

use std::net::SocketAddr;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};

use crate::app::{App, AppSpec};
use crate::body::ReqBody;

/// Test client for an [`App`].
#[derive(Debug)]
pub struct TestClient<A: AppSpec> {
    app: App<A>,
}

impl<A: AppSpec> App<A> {
    /// An in-process test client.
    pub fn client(&self) -> TestClient<A> {
        TestClient { app: self.clone() }
    }
}

macro_rules! verbs {
    ($($name:ident => $m:expr),*) => {$(
        #[doc = concat!("Starts a `", stringify!($m), "` request.")]
        pub fn $name(&self, uri: &str) -> TestRequest<A> {
            self.request($m, uri)
        }
    )*};
}

impl<A: AppSpec> TestClient<A> {
    /// Starts a request.
    pub fn request(&self, method: Method, uri: &str) -> TestRequest<A> {
        TestRequest {
            app: self.app.clone(),
            method,
            uri: uri.to_owned(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
            peer: Some(SocketAddr::from(([127, 0, 0, 1], 40000))),
        }
    }

    verbs!(get => Method::GET, post => Method::POST, put => Method::PUT, patch => Method::PATCH,
           delete => Method::DELETE, head => Method::HEAD, options => Method::OPTIONS);
}

/// A request being built.
#[derive(Debug)]
pub struct TestRequest<A: AppSpec> {
    app: App<A>,
    method: Method,
    uri: String,
    headers: HeaderMap,
    body: Bytes,
    peer: Option<SocketAddr>,
}

impl<A: AppSpec> TestRequest<A> {
    /// Adds a header. Panics on invalid header names/values (test helper).
    pub fn header(mut self, name: &str, value: &str) -> Self {
        let n = HeaderName::try_from(name).expect("test header name must be valid");
        let v = HeaderValue::try_from(value).expect("test header value must be valid");
        self.headers.append(n, v);
        self
    }

    /// Adds `Authorization: Bearer <token>`.
    pub fn bearer(self, token: &str) -> Self {
        self.header("authorization", &format!("Bearer {token}"))
    }

    /// Sets a JSON body and content type.
    pub fn json<T: serde::Serialize>(mut self, v: &T) -> Self {
        self.body = Bytes::from(serde_json::to_vec(v).expect("test JSON must serialise"));
        self.header("content-type", "application/json")
    }

    /// Sets a raw body (and `Content-Length`).
    pub fn body(mut self, b: impl Into<Bytes>) -> Self {
        self.body = b.into();
        self
    }

    /// Sets the peer address (rate limiting by IP).
    pub fn peer(mut self, addr: SocketAddr) -> Self {
        self.peer = Some(addr);
        self
    }

    /// Sends the request through the app pipeline.
    pub async fn send(self) -> TestResponse {
        let mut req = http::Request::builder()
            .method(self.method)
            .uri(self.uri.as_str())
            .body(ReqBody::from(self.body.clone()))
            .expect("test request must be valid");
        *req.headers_mut() = self.headers;
        if !self.body.is_empty() && !req.headers().contains_key(http::header::CONTENT_LENGTH) {
            req.headers_mut().insert(http::header::CONTENT_LENGTH, HeaderValue::from(self.body.len()));
        }
        let res = self.app.handle(req, self.peer).await;
        let (parts, body) = res.into_parts();
        let body = body.collect_bytes().await.unwrap_or_default();
        TestResponse { status: parts.status, headers: parts.headers, body }
    }
}

/// A collected response.
#[derive(Debug, Clone)]
pub struct TestResponse {
    /// Status.
    pub status: StatusCode,
    /// Headers.
    pub headers: HeaderMap,
    /// Body.
    pub body: Bytes,
}

impl TestResponse {
    /// Body as UTF-8 (lossy).
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// Body as JSON. Panics if it is not valid JSON for `T` (test helper).
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> T {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("response is not valid JSON ({e}): {}", self.text()))
    }

    /// A header value as str.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}
